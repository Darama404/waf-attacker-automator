package cloudflare

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const (
	listZonesEndpoint   = "https://api.cloudflare.com/client/v4/zones?per_page=50&page=%d"
	listRulesetsEndpoint = "https://api.cloudflare.com/client/v4/zones/%s/rulesets"
)

// ZoneClient menangani operasi yang berkaitan dengan zone dan rule discovery.
type ZoneClient struct {
	apiToken  string
	accountID string
	http      *http.Client
}

// NewZoneClient membuat instance baru ZoneClient.
func NewZoneClient(apiToken, accountID string) *ZoneClient {
	return &ZoneClient{
		apiToken:  apiToken,
		accountID: accountID,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

// Zone merepresentasikan satu domain di Cloudflare.
type Zone struct {
	ID     string `json:"id"`
	Name   string `json:"name"` // Domain name, e.g. "example.com"
	Status string `json:"status"`
}

// ZoneRule merepresentasikan rule yang ditemukan di dalam ruleset sebuah zone.
type ZoneRule struct {
	ZoneID      string
	ZoneName    string
	RulesetID   string
	RuleID      string
	Description string
	Expression  string
	Action      string
}

type listZonesResponse struct {
	Success    bool   `json:"success"`
	Result     []Zone `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		PerPage    int `json:"per_page"`
		TotalPages int `json:"total_pages"`
		Count      int `json:"count"`
		Total      int `json:"total_count"`
	} `json:"result_info"`
	Errors []apiError `json:"errors"`
}

type listRulesetsResponse struct {
	Success bool `json:"success"`
	Result  []struct {
		ID    string `json:"id"`
		Phase string `json:"phase"`
		Rules []struct {
			ID          string `json:"id"`
			Description string `json:"description"`
			Expression  string `json:"expression"`
			Action      string `json:"action"`
		} `json:"rules"`
	} `json:"result"`
	Errors []apiError `json:"errors"`
}

// ---------------------------------------------------------------------------
// Public Methods
// ---------------------------------------------------------------------------

// GetAllActiveZones mengambil semua zone aktif di bawah account ini.
// Melakukan pagination otomatis jika zone > 50.
func (z *ZoneClient) GetAllActiveZones(ctx context.Context) ([]Zone, error) {
	var allZones []Zone
	page := 1

	for {
		zones, totalPages, err := z.fetchZonesPage(ctx, page)
		if err != nil {
			return nil, fmt.Errorf("fetch zones page %d: %w", page, err)
		}

		// Filter hanya zone yang aktif
		for _, zone := range zones {
			if zone.Status == "active" {
				allZones = append(allZones, zone)
			}
		}

		slog.Debug("Fetched zones page",
			"page", page,
			"total_pages", totalPages,
			"zones_this_page", len(zones),
		)

		if page >= totalPages {
			break
		}
		page++
	}

	slog.Info("All active zones fetched", "total", len(allZones))
	return allZones, nil
}

// FindRuleByName mencari rule di sebuah zone berdasarkan nama/description rule.
// Mengembalikan ZoneRule lengkap termasuk RulesetID dan RuleID yang dibutuhkan untuk PATCH.
//
// ruleName harus sama persis dengan field "description" rule di Cloudflare dashboard.
// Contoh: "allow-countries-ip"
func (z *ZoneClient) FindRuleByName(ctx context.Context, zone Zone, ruleName string) (*ZoneRule, error) {
	url := fmt.Sprintf(listRulesetsEndpoint, zone.ID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+z.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := z.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d for zone %s: %s",
			resp.StatusCode, zone.Name, truncate(string(body), 200))
	}

	var result listRulesetsResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	if !result.Success {
		if len(result.Errors) > 0 {
			return nil, fmt.Errorf("API error: %s", result.Errors[0].Message)
		}
		return nil, fmt.Errorf("API returned success=false")
	}

	// Cari di semua ruleset — prioritaskan phase http_request_firewall_custom
	for _, ruleset := range result.Result {
		if ruleset.Phase != "http_request_firewall_custom" {
			continue
		}
		for _, rule := range ruleset.Rules {
			// Case-insensitive match pada description
			if strings.EqualFold(rule.Description, ruleName) {
				return &ZoneRule{
					ZoneID:      zone.ID,
					ZoneName:    zone.Name,
					RulesetID:   ruleset.ID,
					RuleID:      rule.ID,
					Description: rule.Description,
					Expression:  rule.Expression,
					Action:      rule.Action,
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("rule %q not found in zone %s — pastikan nama rule sesuai dengan description di dashboard",
		ruleName, zone.Name)
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

func (z *ZoneClient) fetchZonesPage(ctx context.Context, page int) ([]Zone, int, error) {
	url := fmt.Sprintf(listZonesEndpoint, page)

	// Filter berdasarkan account ID jika tersedia
	if z.accountID != "" {
		url += "&account.id=" + z.accountID
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+z.apiToken)

	resp, err := z.http.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("execute request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("read body: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		// lanjut
	case http.StatusUnauthorized:
		return nil, 0, fmt.Errorf("unauthorized (401): CF_API_TOKEN tidak valid")
	case http.StatusForbidden:
		return nil, 0, fmt.Errorf("forbidden (403): token tidak punya akses ke account %s", z.accountID)
	case http.StatusTooManyRequests:
		return nil, 0, fmt.Errorf("rate limited (429)")
	default:
		return nil, 0, fmt.Errorf("HTTP %d: %s", resp.StatusCode, truncate(string(body), 200))
	}

	var result listZonesResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, 0, fmt.Errorf("decode response: %w", err)
	}

	if !result.Success {
		if len(result.Errors) > 0 {
			return nil, 0, fmt.Errorf("API error: %s", result.Errors[0].Message)
		}
		return nil, 0, fmt.Errorf("success=false")
	}

	totalPages := result.ResultInfo.TotalPages
	if totalPages == 0 {
		totalPages = 1
	}

	return result.Result, totalPages, nil
}