package main

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "log/slog"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "waf-automator/internal/config"
    "waf-automator/internal/monitor"
)

func main() {
    // Setup structured logging (JSON untuk production)
    logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
        Level: slog.LevelInfo,
    }))
    slog.SetDefault(logger)

    cfg, err := config.Load()
    if err != nil {
        slog.Error("Configuration error", "error", err)
        os.Exit(1)
    }

    // Setup Slack notifier (opsional)
    var notifier monitor.Notifier
    if cfg.SlackWebhookURL != "" {
        notifier = &SlackNotifier{webhookURL: cfg.SlackWebhookURL}
    }

    m := monitor.New(cfg, notifier)

    // Graceful shutdown dengan context
    ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
    defer cancel()

    m.Run(ctx)
    slog.Info("WAF Monitor exited cleanly")
}

// SlackNotifier implementasi sederhana untuk alert ke Slack
type SlackNotifier struct {
    webhookURL string
    client     http.Client
}

func (s *SlackNotifier) Notify(event string, details map[string]interface{}) error {
    emoji := "⚠️"
    if event == "MITIGATION_DEACTIVATED" {
        emoji = "✅"
    }

    text := fmt.Sprintf("%s *WAF Automation Alert: %s*\n", emoji, event)
    for k, v := range details {
        text += fmt.Sprintf("> *%s*: %v\n", k, v)
    }

    payload := map[string]string{"text": text}
    body, _ := json.Marshal(payload)

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    req, _ := http.NewRequestWithContext(ctx, http.MethodPost, s.webhookURL, bytes.NewReader(body))
    req.Header.Set("Content-Type", "application/json")

    resp, err := s.client.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()

    return nil
}