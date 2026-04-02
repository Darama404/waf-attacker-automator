package config

import (
    "fmt"
    "os"
    "strconv"
    "time"
)

type Config struct {
    // Cloudflare Credentials
    CFApiToken     string
    CFZoneID       string
    CFAccountID    string
    CFRulesetID    string // WAF Custom Ruleset ID
    CFRuleID       string // Specific Rule ID to toggle

    // Threshold Settings
    RPSThreshold      float64       // e.g. 1000
    TriggerDuration   time.Duration // e.g. 2 minutes (consecutive breach)
    CooldownDuration  time.Duration // e.g. 15 minutes stable below threshold

    // Polling
    PollInterval time.Duration // e.g. 1 minute

    // Notifications (opsional)
    SlackWebhookURL string
}

func Load() (*Config, error) {
    cfg := &Config{}

    required := map[string]*string{
        "CF_API_TOKEN":  &cfg.CFApiToken,
        "CF_ZONE_ID":    &cfg.CFZoneID,
        "CF_ACCOUNT_ID": &cfg.CFAccountID,
        "CF_RULESET_ID": &cfg.CFRulesetID,
        "CF_RULE_ID":    &cfg.CFRuleID,
    }

    for key, dest := range required {
        val := os.Getenv(key)
        if val == "" {
            return nil, fmt.Errorf("required env var %s is not set", key)
        }
        *dest = val
    }

    // Threshold dengan default values
    rps, _ := strconv.ParseFloat(getEnvOrDefault("RPS_THRESHOLD", "1000"), 64)
    cfg.RPSThreshold = rps

    triggerMin, _ := strconv.Atoi(getEnvOrDefault("TRIGGER_DURATION_MINUTES", "2"))
    cfg.TriggerDuration = time.Duration(triggerMin) * time.Minute

    cooldownMin, _ := strconv.Atoi(getEnvOrDefault("COOLDOWN_DURATION_MINUTES", "15"))
    cfg.CooldownDuration = time.Duration(cooldownMin) * time.Minute

    pollSec, _ := strconv.Atoi(getEnvOrDefault("POLL_INTERVAL_SECONDS", "60"))
    cfg.PollInterval = time.Duration(pollSec) * time.Second

    cfg.SlackWebhookURL = os.Getenv("SLACK_WEBHOOK_URL") // opsional

    return cfg, nil
}

func getEnvOrDefault(key, defaultVal string) string {
    if val := os.Getenv(key); val != "" {
        return val
    }
    return defaultVal
}