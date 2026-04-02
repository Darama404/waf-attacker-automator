package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"waf-attacker-automator/internal/cloudflare"
	"waf-attacker-automator/internal/config"
	"waf-attacker-automator/internal/notify"
)

// ---------------------------------------------------------------------------
// State Machine
// ---------------------------------------------------------------------------

// State merepresentasikan kondisi monitor saat ini.
type State int32

const (
	StateNormal      State = iota // Traffic normal, WAF rule = skip
	StateBreaching                // RPS melewati threshold, sedang menghitung durasi
	StateMitigating               // Rule sudah diubah ke managed_challenge
	StateCoolingDown              // RPS turun, sedang menghitung cooldown
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
// Monitor
// ---------------------------------------------------------------------------

// Monitor adalah komponen utama yang menjalankan polling loop dan state machine.
type Monitor struct {
	cfg       *config.Config
	gql       *cloudflare.GraphQLClient
	waf       *cloudflare.WAFClient
	telegram  *notify.TelegramNotifier

	// Expression asli rule "allow" — wajib disertakan saat PATCH ke Cloudflare API.
	// Jangan sampai hilang, karena PATCH tanpa expression akan error.
	allowRuleExpr string

	// --- State machine fields ---
	currentState   State
	stateEnteredAt time.Time // Kapan masuk ke state saat ini (untuk hitung durasi)
	breachStartAt  time.Time // Kapan RPS pertama kali melewati threshold
	stableStartAt  time.Time // Kapan RPS mulai stabil di bawah threshold (cooldown)

	// --- Metrics ---
	pollCount int64 // Atomic counter — aman untuk concurrent access
}

// New membuat instance Monitor baru.
// telegram boleh nil jika notifikasi Telegram tidak dikonfigurasi.
func New(cfg *config.Config, telegram *notify.TelegramNotifier) *Monitor {
	return &Monitor{
		cfg:      cfg,
		gql:      cloudflare.NewGraphQLClient(cfg.CFApiToken, cfg.CFZoneID),
		waf:      cloudflare.NewWAFClient(cfg.CFApiToken, cfg.CFZoneID, cfg.CFRulesetID, cfg.CFRuleID),
		telegram: telegram,

		// PENTING: Nilai ini harus identik dengan expression yang ada di Cloudflare dashboard.
		// Cloudflare API mengharuskan expression disertakan saat update rule.
		// Idealnya diambil via GET /rulesets/{id} saat startup — lihat fungsi loadRuleExpression().
		allowRuleExpr: `(ip.src.country in {"KH" "ID" "MY" "LK" "HK"}) or (ip.src in $allow_ip_third_party)`,

		currentState:   StateNormal,
		stateEnteredAt: time.Now(),
	}
}

// ---------------------------------------------------------------------------
// Run — Entry Point
// ---------------------------------------------------------------------------

// Run memulai polling loop utama. Blocking sampai ctx dibatalkan.
// Gunakan signal.NotifyContext di main.go untuk graceful shutdown.
func (m *Monitor) Run(ctx context.Context) {
	slog.Info("WAF Monitor started",
		"zone_id", m.cfg.CFZoneID,
		"poll_interval", m.cfg.PollInterval,
		"rps_threshold", m.cfg.RPSThreshold,
		"trigger_duration", m.cfg.TriggerDuration,
		"cooldown_duration", m.cfg.CooldownDuration,
	)

	// Opsional: ambil expression rule dari API saat startup supaya tidak hardcode.
	// Uncomment baris di bawah jika ingin dynamic:
	// if err := m.loadRuleExpression(ctx); err != nil {
	//     slog.Warn("Could not load rule expression from API, using default", "error", err)
	// }

	ticker := time.NewTicker(m.cfg.PollInterval)
	defer ticker.Stop()

	// Jalankan satu kali langsung saat start — jangan tunggu tick pertama.
	m.tick(ctx)

	for {
		select {
		case <-ctx.Done():
			slog.Info("Monitor received shutdown signal, exiting cleanly")
			return
		case <-ticker.C:
			m.tick(ctx)
		}
	}
}

// ---------------------------------------------------------------------------
// Tick — Satu Siklus Poll
// ---------------------------------------------------------------------------

// tick adalah satu siklus: fetch RPS → evaluasi state → kirim notifikasi Telegram.
func (m *Monitor) tick(ctx context.Context) {
	count := atomic.AddInt64(&m.pollCount, 1)

	// Fetch RPS dengan retry dan exponential backoff.
	rps, err := m.fetchRPSWithRetry(ctx, 3)
	if err != nil {
		slog.Error("Failed to fetch RPS after all retries — skipping this tick",
			"error", err,
			"poll", count,
		)
		// Fail-safe: jangan ubah state jika data tidak tersedia.
		// Lebih baik false negative daripada false positive yang mengubah rule.
		return
	}

	slog.Info("RPS polled",
		"rps", fmt.Sprintf("%.1f", rps),
		"threshold", m.cfg.RPSThreshold,
		"state", m.currentState.String(),
		"poll", count,
	)

	// Jalankan state machine.
	m.evaluate(ctx, rps)

	// Kirim live status update ke Telegram (edit pesan yang sama — tidak spam).
	m.sendStatusUpdate(ctx, rps, count)
}

// ---------------------------------------------------------------------------
// State Machine — evaluate()
// ---------------------------------------------------------------------------

// evaluate adalah inti state machine. Dipanggil setiap tick.
func (m *Monitor) evaluate(ctx context.Context, rps float64) {
	isBreaching := rps > m.cfg.RPSThreshold
	now := time.Now()

	switch m.currentState {

	// -----------------------------------------------------------------------
	case StateNormal:
		if isBreaching {
			slog.Warn("RPS breach detected — starting trigger timer",
				"rps", rps,
				"threshold", m.cfg.RPSThreshold,
			)
			m.breachStartAt = now
			m.transitionTo(StateBreaching)
		}
		// Tidak ada aksi jika RPS masih normal.

	// -----------------------------------------------------------------------
	case StateBreaching:
		if !isBreaching {
			// RPS turun sendiri sebelum mencapai trigger duration.
			// Ini bisa false spike — kembali ke Normal tanpa aksi apapun.
			slog.Info("RPS normalized before trigger duration — returning to NORMAL",
				"breach_duration", now.Sub(m.breachStartAt).Round(time.Second),
			)
			m.transitionTo(StateNormal)
			return
		}

		elapsed := now.Sub(m.breachStartAt)
		remaining := m.cfg.TriggerDuration - elapsed

		slog.Warn("RPS still breaching",
			"rps", rps,
			"elapsed", elapsed.Round(time.Second),
			"remaining_until_trigger", remaining.Round(time.Second),
		)

		if elapsed >= m.cfg.TriggerDuration {
			// Threshold terlampaui selama durasi yang ditentukan → TRIGGER mitigasi.
			slog.Warn("Trigger duration exceeded — activating mitigation",
				"rps", rps,
				"breach_duration", elapsed.Round(time.Second),
			)
			if err := m.activateMitigation(ctx, rps); err != nil {
				slog.Error("Failed to activate mitigation — will retry next tick", "error", err)
				// Jangan transisi state jika API call gagal.
				// Akan dicoba lagi di tick berikutnya.
				return
			}
			m.transitionTo(StateMitigating)
		}

	// -----------------------------------------------------------------------
	case StateMitigating:
		if !isBreaching {
			// RPS mulai turun. Mulai hitung cooldown.
			slog.Info("RPS dropped below threshold during mitigation — starting cooldown",
				"rps", rps,
				"threshold", m.cfg.RPSThreshold,
			)
			m.stableStartAt = now
			m.transitionTo(StateCoolingDown)
		} else {
			slog.Warn("Attack still ongoing during mitigation",
				"rps", rps,
				"mitigating_for", now.Sub(m.stateEnteredAt).Round(time.Second),
			)
		}

	// -----------------------------------------------------------------------
	case StateCoolingDown:
		if isBreaching {
			// RPS naik lagi selama cooldown — reset timer cooldown.
			// Jangan deactivate mitigasi dulu.
			slog.Warn("RPS spiked again during cooldown — resetting cooldown timer",
				"rps", rps,
			)
			m.stableStartAt = now
			return
		}

		elapsed := now.Sub(m.stableStartAt)
		remaining := m.cfg.CooldownDuration - elapsed

		slog.Info("Cooldown in progress",
			"rps", rps,
			"stable_for", elapsed.Round(time.Second),
			"remaining", remaining.Round(time.Second),
		)

		if elapsed >= m.cfg.CooldownDuration {
			// Cooldown selesai → kembalikan rule ke skip.
			slog.Info("Cooldown complete — deactivating mitigation")
			if err := m.deactivateMitigation(ctx); err != nil {
				slog.Error("Failed to deactivate mitigation — will retry next tick", "error", err)
				// Jangan transisi state jika API call gagal.
				return
			}
			m.transitionTo(StateNormal)
		}
	}
}

// transitionTo mengubah state dan mencatat waktu masuk state baru.
func (m *Monitor) transitionTo(newState State) {
	oldState := m.currentState
	m.currentState = newState
	m.stateEnteredAt = time.Now()
	slog.Info("State transition",
		"from", oldState.String(),
		"to", newState.String(),
	)
}

// ---------------------------------------------------------------------------
// WAF Actions
// ---------------------------------------------------------------------------

// activateMitigation mengubah rule action dari "skip" menjadi "managed_challenge".
// Dipanggil saat RPS melewati threshold selama TriggerDuration.
func (m *Monitor) activateMitigation(ctx context.Context, rps float64) error {
	slog.Info("Calling Cloudflare API: skip → managed_challenge")

	// Beri timeout tersendiri untuk API call ini — jangan blok polling loop terlalu lama.
	apiCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := m.waf.SetRuleAction(apiCtx, cloudflare.ActionManagedChallenge, m.allowRuleExpr); err != nil {
		return fmt.Errorf("cloudflare API call failed: %w", err)
	}

	slog.Warn("🚨 Mitigation ACTIVATED — rule changed to managed_challenge",
		"rps", rps,
		"threshold", m.cfg.RPSThreshold,
	)

	// Kirim alert Telegram — pesan baru (bukan edit) karena ini event penting.
	if m.telegram != nil {
		tgCtx, tgCancel := context.WithTimeout(ctx, 10*time.Second)
		defer tgCancel()

		if err := m.telegram.NotifyMitigationActivated(tgCtx, m.cfg.CFZoneID, rps, m.cfg.RPSThreshold); err != nil {
			// Non-fatal — jangan gagalkan mitigasi hanya karena Telegram error.
			slog.Warn("Telegram alert failed (mitigation activated)", "error", err)
		}
	}

	return nil
}

// deactivateMitigation mengembalikan rule action dari "managed_challenge" ke "skip".
// Dipanggil setelah RPS stabil di bawah threshold selama CooldownDuration.
func (m *Monitor) deactivateMitigation(ctx context.Context) error {
	slog.Info("Calling Cloudflare API: managed_challenge → skip")

	apiCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := m.waf.SetRuleAction(apiCtx, cloudflare.ActionSkip, m.allowRuleExpr); err != nil {
		return fmt.Errorf("cloudflare API call failed: %w", err)
	}

	slog.Info("✅ Mitigation DEACTIVATED — rule restored to skip",
		"cooldown_duration", m.cfg.CooldownDuration,
	)

	// Kirim alert Telegram — pesan baru karena ini event penting.
	if m.telegram != nil {
		tgCtx, tgCancel := context.WithTimeout(ctx, 10*time.Second)
		defer tgCancel()

		if err := m.telegram.NotifyMitigationDeactivated(tgCtx, m.cfg.CFZoneID, m.cfg.CooldownDuration.Minutes()); err != nil {
			slog.Warn("Telegram alert failed (mitigation deactivated)", "error", err)
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Telegram Status Update
// ---------------------------------------------------------------------------

// sendStatusUpdate mengirim/mengedit pesan live status di Telegram setiap polling.
// Menggunakan strategi edit message supaya group tidak dibanjiri pesan.
func (m *Monitor) sendStatusUpdate(ctx context.Context, rps float64, pollCount int64) {
	if m.telegram == nil {
		return
	}

	tgCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	report := &notify.StatusReport{
		Zone:          m.cfg.CFZoneID,
		CurrentRPS:    rps,
		Threshold:     m.cfg.RPSThreshold,
		State:         m.currentState.String(),
		PollCount:     pollCount,
		LastPollTime:  time.Now(),
		StateDuration: time.Since(m.stateEnteredAt),
	}

	if err := m.telegram.UpdateStatusMessage(tgCtx, report); err != nil {
		// Non-fatal — status update bukan critical path.
		slog.Warn("Telegram status update failed", "error", err)
	}
}

// ---------------------------------------------------------------------------
// RPS Fetch dengan Retry
// ---------------------------------------------------------------------------

// fetchRPSWithRetry memanggil Cloudflare GraphQL API dengan retry dan exponential backoff.
//
// Backoff schedule (maxRetries=3):
//   - Attempt 1: langsung
//   - Attempt 2: tunggu 5 detik
//   - Attempt 3: tunggu 10 detik
//
// Jika rate limited (429), backoff lebih panjang diterapkan otomatis.
func (m *Monitor) fetchRPSWithRetry(ctx context.Context, maxRetries int) (float64, error) {
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			// Exponential backoff: 5s → 10s → 20s
			backoff := time.Duration(5<<uint(attempt-1)) * time.Second

			// Jika error sebelumnya adalah rate limit, tambah backoff ekstra.
			if isRateLimitError(lastErr) {
				backoff = backoff * 3
				slog.Warn("Rate limited by Cloudflare, applying extended backoff",
					"backoff", backoff,
					"attempt", attempt+1,
				)
			} else {
				slog.Info("Retrying RPS fetch",
					"attempt", attempt+1,
					"backoff", backoff,
					"last_error", lastErr,
				)
			}

			select {
			case <-ctx.Done():
				return 0, fmt.Errorf("context cancelled during retry backoff: %w", ctx.Err())
			case <-time.After(backoff):
			}
		}

		// Beri timeout per attempt — jangan tunggu indefinitely.
		fetchCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		rps, err := m.gql.GetAllowRuleRPS(fetchCtx, m.cfg.CFRuleID)
		cancel()

		if err == nil {
			if attempt > 0 {
				slog.Info("RPS fetch succeeded after retry", "attempt", attempt+1)
			}
			return rps, nil
		}

		lastErr = err
		slog.Warn("RPS fetch attempt failed",
			"attempt", attempt+1,
			"max_retries", maxRetries,
			"error", err,
		)
	}

	return 0, fmt.Errorf("all %d attempts failed, last error: %w", maxRetries, lastErr)
}

// isRateLimitError memeriksa apakah error adalah rate limit dari Cloudflare.
func isRateLimitError(err error) bool {
	if err == nil {
		return false
	}
	// GraphQL client kita meng-wrap error 429 dengan string ini.
	return contains(err.Error(), "rate limited") || contains(err.Error(), "429")
}

// contains adalah helper sederhana — menghindari import "strings" hanya untuk ini.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Optional: Load Rule Expression dari Cloudflare API
// ---------------------------------------------------------------------------

// loadRuleExpression mengambil expression rule "allow" langsung dari Cloudflare API
// saat startup, supaya tidak perlu hardcode di kode.
//
// Uncomment pemanggilan fungsi ini di Run() jika ingin dynamic expression loading.
func (m *Monitor) loadRuleExpression(ctx context.Context) error {
	expr, err := m.waf.GetRuleExpression(ctx, m.cfg.CFRuleID)
	if err != nil {
		return fmt.Errorf("get rule expression: %w", err)
	}

	if expr == "" {
		return fmt.Errorf("rule expression is empty — check CF_RULE_ID configuration")
	}

	m.allowRuleExpr = expr
	slog.Info("Rule expression loaded from Cloudflare API",
		"rule_id", m.cfg.CFRuleID,
		"expression", expr,
	)
	return nil
}

// ---------------------------------------------------------------------------
// Getters — untuk testing / health check endpoint
// ---------------------------------------------------------------------------

// CurrentState mengembalikan state saat ini (thread-safe read).
func (m *Monitor) CurrentState() State {
	return m.currentState
}

// PollCount mengembalikan jumlah total polling yang sudah dilakukan.
func (m *Monitor) PollCount() int64 {
	return atomic.LoadInt64(&m.pollCount)
}

// StateDuration mengembalikan berapa lama monitor berada di state saat ini.
func (m *Monitor) StateDuration() time.Duration {
	return time.Since(m.stateEnteredAt)
}