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

const graphqlEndpoint = "https://api.cloudflare.com/client/v4/graphql"

// GraphQLClient menangani semua komunikasi ke Cloudflare GraphQL Analytics API.
type GraphQLClient struct {
	apiToken string
	zoneID   string
	http     *http.Client
}

// NewGraphQLClient membuat instance baru GraphQLClient.
func NewGraphQLClient(apiToken, zoneID string) *GraphQLClient {
	return &GraphQLClient{
		apiToken: apiToken,
		zoneID:   zoneID,
		http: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// ---------------------------------------------------------------------------
// Response Structs
// ---------------------------------------------------------------------------

// graphqlRequest adalah payload standar untuk Cloudflare GraphQL API.
type graphqlRequest struct {
	Query string `json:"query"`
}

// firewallEventsResponse memetakan response dari query firewallEventsAdaptiveGroups.
type firewallEventsResponse struct {
	Data struct {
		Viewer struct {
			Zones []struct {
				FirewallEventsAdaptiveGroups []struct {
					Count      int `json:"count"`
					Dimensions struct {
						RuleID string `json:"ruleId"`
					} `json:"dimensions"`
				} `json:"firewallEventsAdaptiveGroups"`
			} `json:"zones"`
		} `json:"viewer"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
		// Cloudflare kadang menyertakan path untuk debugging
		Path []string `json:"path,omitempty"`
	} `json:"errors"`
}

// ---------------------------------------------------------------------------
// Public Methods
// ---------------------------------------------------------------------------

// GetAllowRuleRPS mengambil rata-rata RPS dari traffic yang match dengan rule "allow"
// dalam window 2 menit terakhir.
//
// Cara kerja:
//   - Query mengambil total event count dalam window 2 menit
//   - Dibagi 120 detik untuk mendapat RPS rata-rata
//   - Difilter berdasarkan ruleId sehingga hanya traffic rule "allow" yang dihitung
//
// Return 0.0 jika tidak ada traffic yang match (bukan error).
func (c *GraphQLClient) GetAllowRuleRPS(ctx context.Context, allowRuleID string) (float64, error) {
	now := time.Now().UTC()

	// Gunakan window 2 menit untuk mendapat data yang cukup stabil.
	// Cloudflare GraphQL punya resolusi minimum ~1 menit untuk data analytics.
	since := now.Add(-2 * time.Minute).Format(time.RFC3339)
	until := now.Format(time.RFC3339)

	query := fmt.Sprintf(`{
		viewer {
			zones(filter: {zoneTag: "%s"}) {
				firewallEventsAdaptiveGroups(
					filter: {
						datetime_geq: "%s"
						datetime_leq: "%s"
						ruleId: "%s"
					}
					limit: 10
					orderBy: [count_DESC]
				) {
					count
					dimensions {
						ruleId
					}
				}
			}
		}
	}`, c.zoneID, since, until, allowRuleID)

	var result firewallEventsResponse
	if err := c.doQuery(ctx, query, &result); err != nil {
		return 0, err
	}

	// Validasi response structure
	if len(result.Data.Viewer.Zones) == 0 {
		slog.Debug("GraphQL returned no zones — zone ID mungkin salah atau tidak ada data")
		return 0, nil
	}

	groups := result.Data.Viewer.Zones[0].FirewallEventsAdaptiveGroups
	if len(groups) == 0 {
		// Tidak ada traffic yang match rule ini dalam window — bukan error.
		return 0, nil
	}

	// Jumlahkan semua count (bisa lebih dari 1 grup jika ada multiple dimensions)
	totalCount := 0
	for _, g := range groups {
		totalCount += g.Count
	}

	// Hitung RPS: total events / window dalam detik
	const windowSeconds = 120.0
	rps := float64(totalCount) / windowSeconds

	slog.Debug("GraphQL RPS calculated",
		"total_count", totalCount,
		"window_seconds", windowSeconds,
		"rps", fmt.Sprintf("%.2f", rps),
		"rule_id", allowRuleID,
	)

	return rps, nil
}

// ---------------------------------------------------------------------------
// Internal Methods
// ---------------------------------------------------------------------------

// doQuery mengirim GraphQL query ke Cloudflare dan meng-unmarshal hasilnya.
func (c *GraphQLClient) doQuery(ctx context.Context, query string, dest interface{}) error {
	payload := graphqlRequest{Query: query}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal graphql query: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, graphqlEndpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create http request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("execute http request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	// Handle HTTP-level errors
	switch resp.StatusCode {
	case http.StatusOK:
		// lanjut ke parse
	case http.StatusTooManyRequests:
		// Cloudflare rate limit — caller akan handle dengan backoff
		return fmt.Errorf("rate limited by Cloudflare API (429): reduce poll frequency")
	case http.StatusUnauthorized:
		return fmt.Errorf("unauthorized (401): check CF_API_TOKEN permission (needs Analytics:Read)")
	case http.StatusForbidden:
		return fmt.Errorf("forbidden (403): token tidak punya akses ke zone %s", c.zoneID)
	default:
		return fmt.Errorf("unexpected HTTP status %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}

	// Parse response
	if err := json.Unmarshal(respBody, dest); err != nil {
		return fmt.Errorf("decode graphql response: %w (body: %s)", err, truncate(string(respBody), 200))
	}

	// Check GraphQL-level errors (HTTP 200 tapi ada error di payload)
	type errChecker struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	var checker errChecker
	_ = json.Unmarshal(respBody, &checker)
	if len(checker.Errors) > 0 {
		return fmt.Errorf("graphql error: %s", checker.Errors[0].Message)
	}

	return nil
}

// truncate memotong string panjang untuk logging — mencegah log yang terlalu besar.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...[truncated]"
}