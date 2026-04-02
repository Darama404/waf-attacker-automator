package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

const (
	// Endpoint untuk update rule spesifik dalam sebuah ruleset
	// PATCH lebih aman dari PUT karena hanya update field yang dikirim
	ruleEndpoint = "https://api.cloudflare.com/client/v4/zones/%s/rulesets/%s/rules/%s"

	// Endpoint untuk GET seluruh ruleset (dipakai untuk loadRuleExpression)
	rulesetEndpoint = "https://api.cloudflare.com/client/v4/zones/%s/rulesets/%s"
)

// RuleAction mendefinisikan nilai action yang valid untuk WAF rule.
type RuleAction string

const (
	// ActionSkip melewati semua custom rules berikutnya — untuk traffic yang sudah diizinkan.
	ActionSkip RuleAction = "skip"

	// ActionManagedChallenge memberikan Cloudflare Managed Challenge (JS + CAPTCHA adaptif).
	ActionManagedChallenge RuleAction = "managed_challenge"
)

// WAFClient menangani semua operasi ke Cloudflare WAF Rules API.
type WAFClient struct {
	apiToken  string
	zoneID    string
	rulesetID string
	ruleID    string
	http      *http.Client
}

// NewWAFClient membuat instance baru WAFClient.
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

// ---------------------------------------------------------------------------
// Request / Response Structs
// ---------------------------------------------------------------------------

// patchRuleRequest adalah payload untuk PATCH /rulesets/{id}/rules/{id}.
// Cloudflare mengharuskan expression disertakan meskipun tidak berubah.
type patchRuleRequest struct {
	Action           RuleAction        `json:"action"`
	ActionParameters *actionParameters `json:"action_parameters,omitempty"`
	Expression       string            `json:"expression"`
	Description      string            `json:"description"`
	Enabled          bool              `json:"enabled"`
}

// actionParameters digunakan khusus untuk action "skip".
// Menentukan apa yang di-skip: "current" = all remaining custom rules dalam ruleset ini.
type actionParameters struct {
	Ruleset string `json:"ruleset,omitempty"`
}

// cloudflareAPIResponse adalah struktur umum response Cloudflare REST API.
type cloudflareAPIResponse struct {
	Success  bool            `json:"success"`
	Errors   []apiError      `json:"errors"`
	Messages []apiMessage    `json:"messages"`
	Result   json.RawMessage `json:"result"`
}

type apiError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type apiMessage struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// getRulesetResponse digunakan untuk parsing response GET /rulesets/{id}.
type getRulesetResponse struct {
	Success bool `json:"success"`
	Result  struct {
		Rules []struct {
			ID         string `json:"id"`
			Expression string `json:"expression"`
		} `json:"rules"`
	} `json:"result"`
}

// ---------------------------------------------------------------------------
// Public Methods
// ---------------------------------------------------------------------------

// SetRuleAction mengubah action rule WAF antara "skip" dan "managed_challenge".
//
// Parameters:
//   - action: ActionSkip atau ActionManagedChallenge
//   - expression: Expression asli rule — wajib disertakan dalam PATCH request
//
// Catatan: Cloudflare API menggunakan PATCH untuk update partial rule.
// Kita tetap harus menyertakan expression agar tidak direset ke default.
func (w *WAFClient) SetRuleAction(ctx context.Context, action RuleAction, expression string) error {
	if expression == "" {
		return fmt.Errorf("expression cannot be empty: required by Cloudflare API for rule update")
	}

	payload := w.buildPatchPayload(action, expression)

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal patch payload: %w", err)
	}

	url := fmt.Sprintf(ruleEndpoint, w.zoneID, w.rulesetID, w.ruleID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create http request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+w.apiToken)
	req.Header.Set("Content-Type", "application/json")

	slog.Debug("Sending PATCH to Cloudflare WAF API",
		"url", url,
		"action", action,
	)

	resp, err := w.http.Do(req)
	if err != nil {
		return fmt.Errorf("execute http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	// Handle HTTP-level errors
	if err := w.checkHTTPStatus(resp.StatusCode, respBody); err != nil {
		return err
	}

	// Parse dan validasi response Cloudflare
	var cfResp cloudflareAPIResponse
	if err := json.Unmarshal(respBody, &cfResp); err != nil {
		return fmt.Errorf("decode api response: %w", err)
	}

	if !cfResp.Success {
		if len(cfResp.Errors) > 0 {
			return fmt.Errorf("cloudflare API error (code %d): %s",
				cfResp.Errors[0].Code,
				cfResp.Errors[0].Message,
			)
		}
		return fmt.Errorf("cloudflare API returned success=false with no error details")
	}

	slog.Info("WAF rule action updated successfully",
		"rule_id", w.ruleID,
		"action", action,
	)

	return nil
}

// GetRuleExpression mengambil expression rule berdasarkan ruleID dari Cloudflare API.
// Digunakan untuk menghindari hardcode expression di kode — dipanggil saat startup.
func (w *WAFClient) GetRuleExpression(ctx context.Context, ruleID string) (string, error) {
	url := fmt.Sprintf(rulesetEndpoint, w.zoneID, w.rulesetID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("create http request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+w.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := w.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("execute http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response body: %w", err)
	}

	if err := w.checkHTTPStatus(resp.StatusCode, respBody); err != nil {
		return "", err
	}

	var result getRulesetResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("decode ruleset response: %w", err)
	}

	if !result.Success {
		return "", fmt.Errorf("cloudflare API returned success=false for GET ruleset")
	}

	// Cari rule dengan ID yang sesuai
	for _, rule := range result.Result.Rules {
		if rule.ID == ruleID {
			return rule.Expression, nil
		}
	}

	return "", fmt.Errorf("rule ID %q not found in ruleset %q — check CF_RULE_ID", ruleID, w.rulesetID)
}

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

// buildPatchPayload membangun payload PATCH berdasarkan action yang diminta.
func (w *WAFClient) buildPatchPayload(action RuleAction, expression string) patchRuleRequest {
	payload := patchRuleRequest{
		Action:      action,
		Expression:  expression,
		Enabled:     true,
	}

	switch action {
	case ActionSkip:
		// Untuk "skip", action_parameters wajib ada — menentukan scope skip.
		// "current" = skip all remaining rules dalam ruleset yang sama.
		payload.ActionParameters = &actionParameters{
			Ruleset: "current",
		}
		payload.Description = "Allow whitelisted countries and trusted third-party IPs"

	case ActionManagedChallenge:
		// managed_challenge tidak memerlukan action_parameters.
		payload.ActionParameters = nil
		payload.Description = "[AUTO] Managed challenge active — high RPS detected"
	}

	return payload
}

// checkHTTPStatus memeriksa HTTP status code dan mengembalikan error yang deskriptif.
func (w *WAFClient) checkHTTPStatus(statusCode int, body []byte) error {
	switch {
	case statusCode >= 200 && statusCode < 300:
		return nil // Success
	case statusCode == http.StatusUnauthorized:
		return fmt.Errorf(
			"unauthorized (401): CF_API_TOKEN tidak valid atau expired — perlu permission Zone:WAF:Edit",
		)
	case statusCode == http.StatusForbidden:
		return fmt.Errorf(
			"forbidden (403): token tidak punya akses ke zone %s atau ruleset %s",
			w.zoneID, w.rulesetID,
		)
	case statusCode == http.StatusNotFound:
		return fmt.Errorf(
			"not found (404): rule ID %q atau ruleset ID %q tidak ditemukan — cek konfigurasi",
			w.ruleID, w.rulesetID,
		)
	case statusCode == http.StatusTooManyRequests:
		return fmt.Errorf("rate limited (429): Cloudflare API limit tercapai — akan retry dengan backoff")
	case statusCode >= 500:
		return fmt.Errorf(
			"cloudflare server error (%d): %s",
			statusCode,
			truncate(string(body), 200),
		)
	default:
		return fmt.Errorf(
			"unexpected HTTP status %d: %s",
			statusCode,
			truncate(string(body), 200),
		)
	}
}