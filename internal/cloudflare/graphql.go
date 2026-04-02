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

const graphqlEndpoint = "https://api.cloudflare.com/client/v4/graphql"

type GraphQLClient struct {
    apiToken string
    zoneID   string
    http     *http.Client
}

func NewGraphQLClient(apiToken, zoneID string) *GraphQLClient {
    return &GraphQLClient{
        apiToken: apiToken,
        zoneID:   zoneID,
        http: &http.Client{
            Timeout: 30 * time.Second,
        },
    }
}

// QueryResult merepresentasikan hasil dari GraphQL query
type FirewallEventsMetric struct {
    Count    int     `json:"count"`
    RuleID   string  `json:"ruleId"`
}

type GraphQLResponse struct {
    Data struct {
        Viewer struct {
            Zones []struct {
                FirewallEventsAdaptiveGroups []struct {
                    Count       int `json:"count"`
                    Dimensions  struct {
                        RuleID string `json:"ruleId"`
                    } `json:"dimensions"`
                } `json:"firewallEventsAdaptiveGroups"`
            } `json:"zones"`
        } `json:"viewer"`
    } `json:"data"`
    Errors []struct {
        Message string `json:"message"`
    } `json:"errors"`
}

// GetAllowRuleRPS mengambil RPS untuk rule "allow" dalam 1 menit terakhir.
// Cloudflare GraphQL mengembalikan count per window; kita bagi dengan detik window.
func (c *GraphQLClient) GetAllowRuleRPS(ctx context.Context, allowRuleID string) (float64, error) {
    now := time.Now().UTC()
    // Ambil data 2 menit terakhir untuk dapat 1 menit penuh yang sudah complete
    since := now.Add(-2 * time.Minute).Format(time.RFC3339)
    until := now.Format(time.RFC3339)

    // GraphQL query - filter berdasarkan ruleId spesifik (rule "allow" kita)
    // Menggunakan firewallEventsAdaptiveGroups untuk efisiensi
    query := fmt.Sprintf(`{
        viewer {
            zones(filter: {zoneTag: "%s"}) {
                firewallEventsAdaptiveGroups(
                    filter: {
                        datetime_geq: "%s",
                        datetime_leq: "%s",
                        ruleId: "%s"
                    },
                    limit: 1,
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

    payload := map[string]string{"query": query}
    body, err := json.Marshal(payload)
    if err != nil {
        return 0, fmt.Errorf("marshal graphql query: %w", err)
    }

    req, err := http.NewRequestWithContext(ctx, http.MethodPost, graphqlEndpoint, bytes.NewReader(body))
    if err != nil {
        return 0, fmt.Errorf("create request: %w", err)
    }
    req.Header.Set("Authorization", "Bearer "+c.apiToken)
    req.Header.Set("Content-Type", "application/json")

    resp, err := c.http.Do(req)
    if err != nil {
        return 0, fmt.Errorf("execute graphql request: %w", err)
    }
    defer resp.Body.Close()

    // Handle rate limiting (HTTP 429)
    if resp.StatusCode == http.StatusTooManyRequests {
        return 0, fmt.Errorf("rate limited by Cloudflare API (429): back off before retry")
    }

    if resp.StatusCode != http.StatusOK {
        respBody, _ := io.ReadAll(resp.Body)
        return 0, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(respBody))
    }

    var result GraphQLResponse
    if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
        return 0, fmt.Errorf("decode graphql response: %w", err)
    }

    if len(result.Errors) > 0 {
        return 0, fmt.Errorf("graphql error: %s", result.Errors[0].Message)
    }

    zones := result.Data.Viewer.Zones
    if len(zones) == 0 || len(zones[0].FirewallEventsAdaptiveGroups) == 0 {
        return 0, nil // Tidak ada traffic = 0 RPS
    }

    totalCount := zones[0].FirewallEventsAdaptiveGroups[0].Count
    // Window 2 menit = 120 detik; hitung RPS rata-rata
    windowSeconds := 120.0
    rps := float64(totalCount) / windowSeconds

    return rps, nil
}