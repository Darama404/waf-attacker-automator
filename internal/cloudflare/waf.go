package cloudflare

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
)

const wafAPIBase = "https://api.cloudflare.com/client/v4/zones/%s/rulesets/%s/rules/%s"

type WAFClient struct {
    apiToken  string
    zoneID    string
    rulesetID string
    ruleID    string
    http      *http.Client
}

func NewWAFClient(apiToken, zoneID, rulesetID, ruleID string) *WAFClient {
    return &WAFClient{
        apiToken:  apiToken,
        zoneID:    zoneID,
        rulesetID: rulesetID,
        ruleID:    ruleID,
        http: &http.Client{
            Timeout: 30 * time.Second,
        },
    }
}

// RuleAction mendefinisikan action yang bisa diset pada WAF rule
type RuleAction string

const (
    ActionSkip               RuleAction = "skip"
    ActionManagedChallenge   RuleAction = "managed_challenge"
)

// WAFRuleUpdatePayload adalah body untuk PATCH/PUT ke Cloudflare Rules API
// Kita gunakan PATCH untuk hanya update field yang diperlukan
type WAFRuleUpdatePayload struct {
    Action     RuleAction         `json:"action"`
    Expression string             `json:"expression"`
    Description string            `json:"description"`
    ActionParameters *ActionParams `json:"action_parameters,omitempty"`
}

type ActionParams struct {
    // Untuk action "skip", kita perlu specify apa yang di-skip
    Ruleset string   `json:"ruleset,omitempty"`
    Rules   []string `json:"rules,omitempty"`
}

type UpdateRuleRequest struct {
    Action           RuleAction  `json:"action"`
    ActionParameters interface{} `json:"action_parameters,omitempty"`
}

// SetRuleAction mengubah action rule WAF antara "skip" dan "managed_challenge"
func (w *WAFClient) SetRuleAction(ctx context.Context, action RuleAction, expression string) error {
    url := fmt.Sprintf(wafAPIBase, w.zoneID, w.rulesetID, w.ruleID)

    var payload interface{}

    switch action {
    case ActionSkip:
        // Untuk "skip", action_parameters menentukan apa yang di-skip
        // Sesuaikan dengan konfigurasi rule asli Anda
        payload = map[string]interface{}{
            "action": action,
            "action_parameters": map[string]interface{}{
                "ruleset": "current", // Skip all remaining custom rules
            },
            "expression":  expression,
            "description": "Allow whitelisted countries and third-party IPs",
            "enabled":     true,
        }
    case ActionManagedChallenge:
        payload = map[string]interface{}{
            "action":      action,
            "expression":  expression,
            "description": "[AUTO-MITIGATED] Allow rule challenged due to high RPS",
            "enabled":     true,
        }
    default:
        return fmt.Errorf("unknown action: %s", action)
    }

    body, err := json.Marshal(payload)
    if err != nil {
        return fmt.Errorf("marshal payload: %w", err)
    }

    // Gunakan PATCH untuk update partial (lebih aman daripada PUT)
    req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(body))
    if err != nil {
        return fmt.Errorf("create request: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+w.apiToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := w.http.Do(req)
    if err != nil {
        return fmt.Errorf("execute request: %w", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode == http.StatusTooManyRequests {
        return fmt.Errorf("rate limited (429): retry after delay")
    }

    respBody, _ := io.ReadAll(resp.Body)

    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
        return fmt.Errorf("API error status %d: %s", resp.StatusCode, string(respBody))
    }

    return nil
}