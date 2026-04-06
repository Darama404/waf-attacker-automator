package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"waf-attacker-automator/internal/cloudflare"
	"waf-attacker-automator/internal/config"
	"waf-attacker-automator/internal/notify"
)

// ---------------------------------------------------------------------------
// State Machine
// ---------------------------------------------------------------------------

type State int32

const (
	StateNormal      State = iota
	StateBreaching
	StateMitigating
	StateCoolingDown
)

func (s State) String() string {
	switch s {
	case StateNormal:
		return "NORMAL"
	case StateBreaching:
		return "BREACHING"
	case StateMitigating:
		return "MITIGATING"
	case StateCoolingDown:
		return "COOLING_DOWN"
	default:
		return "UNKNOWN"
	}
}

// ---------------------------------------------------------------------------
// ZoneMonitor — Monitor untuk satu zone
// ---------------------------------------------------------------------------

// ZoneMonitor menjalankan state machine untuk satu zone secara independen.
// Setiap zone punya goroutine sendiri sehingga serangan di satu domain
// tidak mempengaruhi polling atau state domain lain.
type ZoneMonitor struct {
	cfg      *config.Config
	rule     *cloudflare.ZoneRule // Rule yang ditemukan saat startup
	gql      *cloudflare.GraphQLClient
	waf      *cloudflare.WAFClient
	telegram *notify.TelegramNotifier

	// State machine
	currentState   State
	stateEnteredAt time.Time
	breachStartAt  time.Time
	stableStartAt  time.Time

	// Metrics
	pollCount int64
}

func newZoneMonitor(
	cfg *config.Config,
	rule *cloudflare.ZoneRule,
	telegram *notify.TelegramNotifier,
) *ZoneMonitor {
	return &ZoneMonitor{
		cfg:      cfg,
		rule:     rule,
		gql:      cloudflare.NewGraphQLClient(cfg.CFApiToken, rule.ZoneID),
		waf:      cloudflare.NewWAFClient(cfg.CFApiToken, rule.ZoneID, rule.RulesetID, rule.RuleID),
		telegram: telegram,

		currentState:   StateNormal,
		stateEnteredAt: time.Now(),
	}
}

// run adalah polling loop untuk satu zone. Dipanggil dalam goroutine terpisah.
func (zm *ZoneMonitor) run(ctx context.Context) {
	ticker := time.NewTicker(zm.cfg.PollInterval)
	defer ticker.Stop()

	slog.Info("Zone monitor started",
		"zone", zm.rule.ZoneName,
		"rule", zm.rule.Description,
		"rule_id", zm.rule.RuleID,
	)

	// Jalankan sekali langsung saat start
	zm.tick(ctx)

	for {
		select {
		case <-ctx.Done():
			slog.Info("Zone monitor stopping", "zone", zm.rule.ZoneName)
			return
		case <-ticker.C:
			zm.tick(ctx)
		}
	}
}

func (zm *ZoneMonitor) tick(ctx context.Context) {
	count := atomic.AddInt64(&zm.pollCount, 1)

	rps, err := zm.fetchRPSWithRetry(ctx, 3)
	if err != nil {
		slog.Error("Failed to fetch RPS",
			"zone", zm.rule.ZoneName,
			"error", err,
			"poll", count,
		)
		return
	}

	slog.Info("RPS polled",
		"zone", zm.rule.ZoneName,
		"rps", fmt.Sprintf("%.1f", rps),
		"threshold", zm.cfg.RPSThreshold,
		"state", zm.currentState.String(),
	)

	zm.evaluate(ctx, rps)

	// Update Telegram status (edit message strategy)
	zm.sendStatusUpdate(ctx, rps, count)
}

// ---------------------------------------------------------------------------
// State Machine
// ---------------------------------------------------------------------------

func (zm *ZoneMonitor) evaluate(ctx context.Context, rps float64) {
	isBreaching := rps > zm.cfg.RPSThreshold
	now := time.Now()

	switch zm.currentState {

	case StateNormal:
		if isBreaching {
			slog.Warn("RPS breach detected",
				"zone", zm.rule.ZoneName,
				"rps", rps,
			)
			zm.breachStartAt = now
			zm.transitionTo(StateBreaching)
		}

	case StateBreaching:
		if !isBreaching {
			slog.Info("RPS normalized before trigger",
				"zone", zm.rule.ZoneName,
				"breach_duration", now.Sub(zm.breachStartAt).Round(time.Second),
			)
			zm.transitionTo(StateNormal)
			return
		}

		elapsed := now.Sub(zm.breachStartAt)
		if elapsed >= zm.cfg.TriggerDuration {
			slog.Warn("Trigger duration exceeded — activating mitigation",
				"zone", zm.rule.ZoneName,
				"rps", rps,
				"breach_duration", elapsed.Round(time.Second),
			)
			if err := zm.activateMitigation(ctx, rps); err != nil {
				slog.Error("Failed to activate mitigation",
					"zone", zm.rule.ZoneName,
					"error", err,
				)
				return
			}
			zm.transitionTo(StateMitigating)
		}

	case StateMitigating:
		if !isBreaching {
			slog.Info("RPS dropped — starting cooldown",
				"zone", zm.rule.ZoneName,
			)
			zm.stableStartAt = now
			zm.transitionTo(StateCoolingDown)
		}

	case StateCoolingDown:
		if isBreaching {
			slog.Warn("RPS spiked during cooldown — resetting timer",
				"zone", zm.rule.ZoneName,
				"rps", rps,
			)
			zm.stableStartAt = now
			return
		}

		elapsed := now.Sub(zm.stableStartAt)
		if elapsed >= zm.cfg.CooldownDuration {
			slog.Info("Cooldown complete — restoring rule",
				"zone", zm.rule.ZoneName,
			)
			if err := zm.deactivateMitigation(ctx); err != nil {
				slog.Error("Failed to deactivate mitigation",
					"zone", zm.rule.ZoneName,
					"error", err,
				)
				return
			}
			zm.transitionTo(StateNormal)
		}
	}
}

func (zm *ZoneMonitor) transitionTo(s State) {
	old := zm.currentState
	zm.currentState = s
	zm.stateEnteredAt = time.Now()
	slog.Info("State transition",
		"zone", zm.rule.ZoneName,
		"from", old.String(),
		"to", s.String(),
	)
}

// ---------------------------------------------------------------------------
// WAF Actions
// ---------------------------------------------------------------------------

func (zm *ZoneMonitor) activateMitigation(ctx context.Context, rps float64) error {
	apiCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := zm.waf.SetRuleAction(apiCtx, cloudflare.ActionManagedChallenge, zm.rule.Expression); err != nil {
		return fmt.Errorf("cloudflare PATCH failed: %w", err)
	}

	slog.Warn("Mitigation ACTIVATED",
		"zone", zm.rule.ZoneName,
		"rps", rps,
	)

	if zm.telegram != nil {
		tgCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := zm.telegram.NotifyMitigationActivated(tgCtx, zm.rule.ZoneName, rps, zm.cfg.RPSThreshold); err != nil {
			slog.Warn("Telegram alert failed", "zone", zm.rule.ZoneName, "error", err)
		}
	}
	return nil
}

func (zm *ZoneMonitor) deactivateMitigation(ctx context.Context) error {
	apiCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := zm.waf.SetRuleAction(apiCtx, cloudflare.ActionSkip, zm.rule.Expression); err != nil {
		return fmt.Errorf("cloudflare PATCH failed: %w", err)
	}

	slog.Info("Mitigation DEACTIVATED", "zone", zm.rule.ZoneName)

	if zm.telegram != nil {
		tgCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := zm.telegram.NotifyMitigationDeactivated(tgCtx, zm.rule.ZoneName, zm.cfg.CooldownDuration.Minutes()); err != nil {
			slog.Warn("Telegram alert failed", "zone", zm.rule.ZoneName, "error", err)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Telegram Status
// ---------------------------------------------------------------------------

func (zm *ZoneMonitor) sendStatusUpdate(ctx context.Context, rps float64, pollCount int64) {
	if zm.telegram == nil {
		return
	}
	tgCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	report := &notify.StatusReport{
		Zone:          zm.rule.ZoneName,
		CurrentRPS:    rps,
		Threshold:     zm.cfg.RPSThreshold,
		State:         zm.currentState.String(),
		PollCount:     pollCount,
		LastPollTime:  time.Now(),
		StateDuration: time.Since(zm.stateEnteredAt),
	}

	if err := zm.telegram.UpdateStatusMessage(ctx, tgCtx, zm.rule.ZoneID, report); err != nil {
		slog.Warn("Telegram status update failed", "zone", zm.rule.ZoneName, "error", err)
	}
}

// ---------------------------------------------------------------------------
// RPS Fetch dengan Retry
// ---------------------------------------------------------------------------

func (zm *ZoneMonitor) fetchRPSWithRetry(ctx context.Context, maxRetries int) (float64, error) {
	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(5<<uint(attempt-1)) * time.Second
			if isRateLimitError(lastErr) {
				backoff *= 3
			}
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(backoff):
			}
		}

		fetchCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		rps, err := zm.gql.GetAllowRuleRPS(fetchCtx, zm.rule.RuleID)
		cancel()

		if err == nil {
			return rps, nil
		}
		lastErr = err
		slog.Warn("RPS fetch attempt failed",
			"zone", zm.rule.ZoneName,
			"attempt", attempt+1,
			"error", err,
		)
	}
	return 0, fmt.Errorf("all %d attempts failed: %w", maxRetries, lastErr)
}

func isRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return contains(s, "429") || contains(s, "rate limited")
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// MultiMonitor — Orchestrator semua ZoneMonitor
// ---------------------------------------------------------------------------

// MultiMonitor mengelola lifecycle semua ZoneMonitor.
// Bertanggung jawab untuk:
//   - Fetch daftar zone dari Cloudflare saat startup
//   - Spawn goroutine per zone
//   - Refresh daftar zone secara berkala (zone baru otomatis terdeteksi)
//   - Graceful shutdown semua goroutine sekaligus
type MultiMonitor struct {
	cfg      *config.Config
	zoneClient *cloudflare.ZoneClient
	telegram *notify.TelegramNotifier

	// mu melindungi akses ke activeMonitors
	mu             sync.RWMutex
	activeMonitors map[string]*ZoneMonitor // key: zone ID
}

// NewMultiMonitor membuat instance MultiMonitor baru.
func NewMultiMonitor(cfg *config.Config, telegram *notify.TelegramNotifier) *MultiMonitor {
	return &MultiMonitor{
		cfg:            cfg,
		zoneClient:     cloudflare.NewZoneClient(cfg.CFApiToken, cfg.CFAccountID),
		telegram:       telegram,
		activeMonitors: make(map[string]*ZoneMonitor),
	}
}

// Run memulai orchestration loop. Blocking sampai ctx dibatalkan.
func (m *MultiMonitor) Run(ctx context.Context) {
	slog.Info("MultiMonitor starting",
		"allow_rule_name", m.cfg.AllowRuleName,
		"excluded_zones", m.cfg.ExcludedZones,
		"zone_refresh_interval", m.cfg.ZoneRefreshInterval,
	)

	// Initial zone discovery dan spawn monitors
	if err := m.discoverAndSpawn(ctx); err != nil {
		slog.Error("Initial zone discovery failed", "error", err)
		// Jangan exit — coba lagi saat refresh berikutnya
	}

	// Ticker untuk periodic zone refresh
	// Berguna jika klien menambahkan domain baru ke account
	refreshTicker := time.NewTicker(m.cfg.ZoneRefreshInterval)
	defer refreshTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			slog.Info("MultiMonitor shutting down — waiting for all zone monitors...")
			return
		case <-refreshTicker.C:
			slog.Info("Refreshing zone list...")
			if err := m.discoverAndSpawn(ctx); err != nil {
				slog.Error("Zone refresh failed", "error", err)
			}
		}
	}
}

// discoverAndSpawn fetch semua zone, cari rule by name, lalu spawn monitor baru
// untuk zone yang belum punya monitor.
func (m *MultiMonitor) discoverAndSpawn(ctx context.Context) error {
	discoverCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	zones, err := m.zoneClient.GetAllActiveZones(discoverCtx)
	if err != nil {
		return fmt.Errorf("get zones: %w", err)
	}

	newCount := 0
	skippedCount := 0
	errorCount := 0

	for _, zone := range zones {
		// Skip zone yang dikecualikan
		if m.cfg.IsZoneExcluded(zone.Name) {
			slog.Debug("Zone excluded", "zone", zone.Name)
			skippedCount++
			continue
		}

		// Skip zone yang sudah punya monitor aktif
		m.mu.RLock()
		_, exists := m.activeMonitors[zone.ID]
		m.mu.RUnlock()
		if exists {
			continue
		}

		// Cari rule by name di zone ini
		findCtx, findCancel := context.WithTimeout(ctx, 15*time.Second)
		rule, err := m.zoneClient.FindRuleByName(findCtx, zone, m.cfg.AllowRuleName)
		findCancel()

		if err != nil {
			// Rule tidak ditemukan di zone ini — skip dengan warning
			// Ini normal jika ada zone yang struktur WAF-nya berbeda
			slog.Warn("Rule not found in zone — skipping",
				"zone", zone.Name,
				"rule_name", m.cfg.AllowRuleName,
				"error", err,
			)
			errorCount++
			continue
		}

		// Spawn goroutine monitor untuk zone ini
		zm := newZoneMonitor(m.cfg, rule, m.telegram)

		m.mu.Lock()
		m.activeMonitors[zone.ID] = zm
		m.mu.Unlock()

		// Jalankan di goroutine terpisah
		go zm.run(ctx)

		slog.Info("Zone monitor spawned",
			"zone", zone.Name,
			"zone_id", zone.ID,
			"rule_id", rule.RuleID,
			"ruleset_id", rule.RulesetID,
		)
		newCount++
	}

	slog.Info("Zone discovery complete",
		"new_monitors", newCount,
		"skipped_excluded", skippedCount,
		"rule_not_found", errorCount,
		"total_active", m.ActiveCount(),
	)

	return nil
}

// ActiveCount mengembalikan jumlah zone monitor yang aktif (thread-safe).
func (m *MultiMonitor) ActiveCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.activeMonitors)
}

// ActiveZones mengembalikan list domain yang sedang dimonitor (untuk logging/health).
func (m *MultiMonitor) ActiveZones() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	zones := make([]string, 0, len(m.activeMonitors))
	for _, zm := range m.activeMonitors {
		zones = append(zones, zm.rule.ZoneName)
	}
	return zones
}