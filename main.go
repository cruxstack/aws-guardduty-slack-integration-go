// main.go
//
// guardduty-to-slack — forward guardduty findings to slack
// env vars:
//   APP_DEBUG_ENABLED   (true|false)
//   APP_AWS_CONSOLE_URL (e.g. https://us-east-1.console.aws.amazon.com)
//   APP_SLACK_TOKEN     (bot token, xoxb-…)
//   APP_SLACK_CHANNEL   (channel id, C********)

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/joho/godotenv"
	"github.com/slack-go/slack"
)

// ------------------------------------------------------------------ config ---

type Config struct {
	DebugEnabled       bool
	AwsAccessPortalURL string
	AwsAccessRoleName  string
	AwsConsoleURL      string
	SlackToken         string
	SlackChannel       string
}

func BuildConfig() (Config, error) {
	cfg := Config{
		DebugEnabled:       os.Getenv("APP_DEBUG_ENABLED") == "true",
		AwsConsoleURL:      os.Getenv("APP_AWS_CONSOLE_URL"),
		AwsAccessPortalURL: os.Getenv("APP_AWS_ACCESS_PORTAL_URL"),
		AwsAccessRoleName:  os.Getenv("APP_AWS_ACCESS_ROLE_NAME"),
		SlackToken:         os.Getenv("APP_SLACK_TOKEN"),
		SlackChannel:       os.Getenv("APP_SLACK_CHANNEL"),
	}
	switch {
	case cfg.SlackToken == "":
		return Config{}, errors.New("missing env var APP_SLACK_TOKEN")
	case cfg.SlackChannel == "":
		return Config{}, errors.New("missing env var APP_SLACK_CHANNEL")
	case cfg.AwsAccessPortalURL == "":
		return Config{}, errors.New("missing env var APP_AWS_ACCESS_PORTAL_URL")
	case cfg.AwsAccessRoleName == "":
		return Config{}, errors.New("missing env var APP_AWS_ACCESS_ROLE_NAME")
	}
	if cfg.AwsConsoleURL == "" {
		cfg.AwsConsoleURL = "https://console.aws.amazon.com"
	}
	return cfg, nil
}

// --------------------------------------------------------------------- app ---

type App struct {
	cfg    Config
	client *slack.Client
}

func NewApp(cfg Config) *App {
	return &App{
		cfg:    cfg,
		client: slack.New(cfg.SlackToken),
	}
}

func (a *App) BuildConsoleURL(gdAccountId string, f *Finding) string {
	dst := fmt.Sprintf(
		"%s/guardduty/home?region=%s#/findings?&macros=current&fId=%s",
		a.cfg.AwsConsoleURL, f.Region, f.ID,
	)
	dstEncoded := url.QueryEscape(dst)
	return fmt.Sprintf(
		"%s/#/console?account_id=%s&role_name=%s&destination=%s",
		a.cfg.AwsAccessPortalURL, gdAccountId, a.cfg.AwsAccessRoleName, dstEncoded,
	)
}

func (a *App) ParseFindingData(gdAccountId string, raw json.RawMessage) (Finding, error) {
	var f Finding
	if err := json.Unmarshal(raw, &f); err != nil {
		return Finding{}, err
	}
	f.ConsoleURL = a.BuildConsoleURL(gdAccountId, &f)
	f.Raw = raw
	f.SeverityLabel = f.ToSeverityLevel()
	return f, nil
}

func (a *App) Process(gdAccountId string, raw json.RawMessage) error {
	f, err := a.ParseFindingData(gdAccountId, raw)
	if err != nil {
		return err
	}
	if a.cfg.DebugEnabled {
		log.Printf("finding id=%s severity=%.1f\n", f.ID, f.Severity)
	}
	return a.CreateThread(f)
}

func (a *App) CreateThread(f Finding) error {
	header := slack.NewHeaderBlock(slack.NewTextBlockObject("plain_text", f.Title, true, false))
	fields := []*slack.TextBlockObject{
		slack.NewTextBlockObject("mrkdwn", "*Severity:* "+string(f.SeverityLabel), false, false),
		slack.NewTextBlockObject("mrkdwn", "*Region:* "+f.Region, false, false),
		slack.NewTextBlockObject("mrkdwn", "*Account:* "+f.AccountID, false, false),
	}
	details := slack.NewSectionBlock(nil, fields, nil)
	desc := slack.NewSectionBlock(
		slack.NewTextBlockObject("plain_text", f.Description, false, false),
		nil, nil,
	)
	btn := slack.NewButtonBlockElement("view", "", slack.NewTextBlockObject("plain_text", "View in Console", false, false))
	btn.URL = f.ConsoleURL
	actions := slack.NewActionBlock("actions", btn)

	_, _, err := a.client.PostMessage(
		a.cfg.SlackChannel,
		slack.MsgOptionText(f.Title, false),
		slack.MsgOptionBlocks(
			header,
			details,
			desc,
			slack.NewDividerBlock(),
			actions,
		),
	)
	return err
}

// ----------------------------------------------------------------- finding ---

type SeverityLevel string

const (
	SeverityUnknown  SeverityLevel = "unknown"
	SeverityLow      SeverityLevel = "low"
	SeverityMedium   SeverityLevel = "medium"
	SeverityHigh     SeverityLevel = "high"
	SeverityCritical SeverityLevel = "critical"
)

type Finding struct {
	ID            string        `json:"id"`
	AccountID     string        `json:"accountId"`
	Region        string        `json:"region"`
	Title         string        `json:"title"`
	Description   string        `json:"description"`
	Severity      float64       `json:"severity"`
	SeverityLabel SeverityLevel `json:"-"`
	ConsoleURL    string        `json:"-"`
	Raw           json.RawMessage
}

func (f *Finding) ToSeverityLevel() SeverityLevel {
	switch {
	case f.Severity < 4:
		return SeverityLow
	case f.Severity < 7:
		return SeverityMedium
	case f.Severity < 9:
		return SeverityHigh
	case f.Severity <= 10:
		return SeverityCritical
	default:
		return SeverityUnknown
	}
}

// ------------------------------------------------------------- cmd: lambda ---

var (
	once    sync.Once
	initErr error
	app     *App
)

func LambdaHandler(_ context.Context, evt events.CloudWatchEvent) error {
	once.Do(func() {
		cfg, err := BuildConfig()
		if err != nil {
			initErr = err
			return
		}
		app = NewApp(cfg)
	})
	if initErr != nil {
		return initErr
	}

	evtJson, err := json.Marshal(evt)
	if err != nil {
		log.Printf("ERROR marshalling event: %v", err)
	}
	log.Print(string(evtJson))

	return app.Process(evt.AccountID, evt.Detail)
}

// ------------------------------------------------------------- cmd: sample ---

func TestWithSamples() {
	if _, err := os.Stat(".env"); err == nil {
		godotenv.Load(".env")
	}
	cfg, err := BuildConfig()
	if err != nil {
		log.Fatal(err)
	}
	app := NewApp(cfg)

	if err := ProcessSamples(app); err != nil {
		log.Fatal(err)
	}
}

func ProcessSamples(a *App) error {
	path := filepath.Join("fixtures", "samples.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read fixtures/samples.json: %w", err)
	}

	var events []events.CloudWatchEvent
	if err := json.Unmarshal(data, &events); err != nil {
		return fmt.Errorf("parse samples.json: %w", err)
	}

	for _, e := range events {
		if err := a.Process(e.AccountID, e.Detail); err != nil {
			return fmt.Errorf("process id=%s: %w", e.ID, err)
		}
	}
	return nil
}

// ------------------------------------------------------------------- main ----

func main() {
	if _, ok := os.LookupEnv("AWS_LAMBDA_FUNCTION_NAME"); ok {
		lambda.Start(LambdaHandler)
		return
	}

	// test with samples
	TestWithSamples()
}
