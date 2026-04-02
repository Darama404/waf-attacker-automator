package monitor

import (
    "context"
    "log/slog"
    "time"

    "waf-automator/internal/cloudflare"
    "waf-automator/internal/config"
	"waf-automator/internal/notify"
)

// State merepresentasikan status current dari state machine
type State int

const (
    StateNormal    State = iota // Traffic normal, rule = skip
    StateBreaching              // RPS di atas threshold, menghitung durasi
    StateMitigating             // Sedang challenge, menunggu cooldown
    StateCoolingDown            // RPS sudah turun, menghitung cooldown
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

// Monitor adalah state machine utama
type Monitor struct {
    cfg          *config.Config
    gqlClient    *cloudflare.GraphQLClient
    wafClient    *cloudflare.WAFClient
    allowRuleExpr string // Expression dari rule "allow" - jangan sampai hilang saat PATCH
	telegram     *notify.TelegramNotifier

    currentState     State
    breachStartTime  time.Time // Kapan RPS mulai breach
    stableStartTime  time.Time // Kapan RPS mulai stabil (untuk cooldown)
    pollCount    int64
    stateEnteredAt time.Time 

    notifier Notifier
}

// Notifier interface untuk alerting (Slack, dll)
type Notifier interface {
    Notify(event string, details map[string]interface{}) error
}

func New(cfg *config.Config, notifier Notifier) *Monitor {
    gqlClient := cloudflare.NewGraphQLClient(cfg.CFApiToken, cfg.CFZoneID)
    wafClient := cloudflare.NewWAFClient(
        cfg.CFApiToken,
        cfg.CFZoneID,
        cfg.CFRulesetID,
        cfg.CFRuleID,
    )

    return &Monitor{
        cfg:          cfg,
        gqlClient:    gqlClient,
        wafClient:    wafClient,
        currentState: StateNormal,
        // PENTING: Simpan expression asli rule allow agar tidak hilang saat PATCH
        allowRuleExpr: `(ip.src.country in {"KH" "ID" "MY" "LK" "HK"}) or (ip.src in $allow_ip_third_party)`,
        notifier:     notifier,
    }
}

// Run memulai polling loop utama
func (m *Monitor) Run(ctx context.Context) {
    ticker := time.NewTicker(m.cfg.PollInterval)
    defer ticker.Stop()

    slog.Info("WAF Monitor started",
        "poll_interval", m.cfg.PollInterval,
        "rps_threshold", m.cfg.RPSThreshold,
        "trigger_duration", m.cfg.TriggerDuration,
        "cooldown_duration", m.cfg.CooldownDuration,
    )

    // Jalankan sekali langsung saat start
    m.tick(ctx)

    for {
        select {
        case <-ctx.Done():
            slog.Info("Monitor shutting down")
            return
        case <-ticker.C:
            m.tick(ctx)
        }
    }
}

// tick adalah satu siklus evaluasi
func (m *Monitor) tick(ctx context.Context) {
    rps, err := m.fetchRPSWithRetry(ctx, 3)
    if err != nil {
        slog.Error("Failed to fetch RPS after retries", "error", err)
        // Jangan ubah state jika API gagal - fail safe
        return
    }

    slog.Info("Polled RPS",
        "rps", rps,
        "threshold", m.cfg.RPSThreshold,
        "state", m.currentState.String(),
    )

    m.evaluate(ctx, rps)
}

// evaluate menjalankan state machine logic
func (m *Monitor) evaluate(ctx context.Context, rps float64) {
    isBreaching := rps > m.cfg.RPSThreshold
    now := time.Now()

    switch m.currentState {

    case StateNormal:
        if isBreaching {
            slog.Warn("RPS breach detected, starting timer", "rps", rps)
            m.breachStartTime = now
            m.currentState = StateBreaching
        }

    case StateBreaching:
        if !isBreaching {
            // RPS turun sebelum trigger duration - kembali normal
            slog.Info("RPS normalized before trigger, back to NORMAL")
            m.currentState = StateNormal
            return
        }

        elapsed := now.Sub(m.breachStartTime)
        slog.Warn("Still breaching", "duration", elapsed, "required", m.cfg.TriggerDuration)

        if elapsed >= m.cfg.TriggerDuration {
            // TRIGGER! Ubah ke managed_challenge
            slog.Warn("Threshold exceeded duration limit, activating mitigation", "rps", rps)
            if err := m.activateMitigation(ctx, rps); err != nil {
                slog.Error("Failed to activate mitigation", "error", err)
                return
            }
            m.currentState = StateMitigating
        }

    case StateMitigating:
        if !isBreaching {
            // RPS mulai turun, masuk cooldown
            slog.Info("RPS dropped below threshold during mitigation, starting cooldown")
            m.stableStartTime = now
            m.currentState = StateCoolingDown
        } else {
            slog.Warn("Still under attack during mitigation", "rps", rps)
        }

    case StateCoolingDown:
        if isBreaching {
            // RPS naik lagi selama cooldown - reset cooldown timer
            slog.Warn("RPS spiked again during cooldown, resetting cooldown timer", "rps", rps)
            m.stableStartTime = now
            return
        }

        elapsed := now.Sub(m.stableStartTime)
        slog.Info("Cooling down", "stable_duration", elapsed, "required", m.cfg.CooldownDuration)

        if elapsed >= m.cfg.CooldownDuration {
            // Cooldown selesai - kembalikan ke skip
            slog.Info("Cooldown complete, restoring normal operation")
            if err := m.deactivateMitigation(ctx); err != nil {
                slog.Error("Failed to deactivate mitigation", "error", err)
                return
            }
            m.currentState = StateNormal
        }
    }
}

func (m *Monitor) activateMitigation(ctx context.Context, rps float64) error {
    slog.Info("Calling Cloudflare API: skip -> managed_challenge")

    err := m.wafClient.SetRuleAction(ctx, cloudflare.ActionManagedChallenge, m.allowRuleExpr)
    if err != nil {
        return err
    }

    if m.notifier != nil {
        _ = m.notifier.Notify("MITIGATION_ACTIVATED", map[string]interface{}{
            "rps":       rps,
            "threshold": m.cfg.RPSThreshold,
            "action":    "Rule changed to managed_challenge",
        })
    }

    slog.Warn("✅ Mitigation ACTIVATED - Rule set to managed_challenge")
    return nil
}

func (m *Monitor) deactivateMitigation(ctx context.Context) error {
    slog.Info("Calling Cloudflare API: managed_challenge -> skip")

    err := m.wafClient.SetRuleAction(ctx, cloudflare.ActionSkip, m.allowRuleExpr)
    if err != nil {
        return err
    }

    if m.notifier != nil {
        _ = m.notifier.Notify("MITIGATION_DEACTIVATED", map[string]interface{}{
            "cooldown_minutes": m.cfg.CooldownDuration.Minutes(),
            "action":           "Rule restored to skip",
        })
    }

    slog.Info("✅ Mitigation DEACTIVATED - Rule restored to skip")
    return nil
}

// fetchRPSWithRetry melakukan retry dengan exponential backoff
func (m *Monitor) fetchRPSWithRetry(ctx context.Context, maxRetries int) (float64, error) {
    var lastErr error

    for attempt := 0; attempt < maxRetries; attempt++ {
        if attempt > 0 {
            // Exponential backoff: 5s, 10s, 20s
            backoff := time.Duration(5<<uint(attempt-1)) * time.Second
            slog.Info("Retrying after backoff", "attempt", attempt+1, "backoff", backoff)
            select {
            case <-ctx.Done():
                return 0, ctx.Err()
            case <-time.After(backoff):
            }
        }

        rps, err := m.gqlClient.GetAllowRuleRPS(ctx, m.cfg.CFRuleID)
        if err == nil {
            return rps, nil
        }

        lastErr = err
        slog.Warn("RPS fetch attempt failed", "attempt", attempt+1, "error", err)
    }

    return 0, fmt.Errorf("all %d retry attempts failed, last error: %w", maxRetries, lastErr)
}