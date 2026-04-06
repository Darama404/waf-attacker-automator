package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"waf-attacker-automator/internal/cloudflare"
	"waf-attacker-automator/internal/config"
	"waf-attacker-automator/internal/monitor"
	"waf-attacker-automator/internal/notify"
)

var version = "dev"

func main() {
	// ---------------------------------------------------------------------------
	// Logger
	// ---------------------------------------------------------------------------
	logLevel := slog.LevelInfo
	if os.Getenv("LOG_LEVEL") == "debug" {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	})))

	slog.Info("WAF Automator starting", "version", version, "mode", "multi-zone")

	// ---------------------------------------------------------------------------
	// Config
	// ---------------------------------------------------------------------------
	cfg, err := config.Load()
	if err != nil {
		slog.Error("Configuration error", "error", err)
		printConfigHelp()
		os.Exit(1)
	}

	slog.Info("Configuration loaded",
		"account_id", cfg.CFAccountID,
		"allow_rule_name", cfg.AllowRuleName,
		"excluded_zones", cfg.ExcludedZones,
		"rps_threshold", cfg.RPSThreshold,
		"trigger_duration", cfg.TriggerDuration,
		"cooldown_duration", cfg.CooldownDuration,
		"poll_interval", cfg.PollInterval,
		"zone_refresh_interval", cfg.ZoneRefreshInterval,
		"telegram_enabled", cfg.TelegramEnabled(),
	)

	// ---------------------------------------------------------------------------
	// Startup Check — pastikan token valid sebelum mulai
	// ---------------------------------------------------------------------------
	if err := runStartupCheck(cfg); err != nil {
		slog.Error("Startup check failed", "error", err)
		os.Exit(1)
	}

	// ---------------------------------------------------------------------------
	// Telegram
	// ---------------------------------------------------------------------------
	var tgNotifier *notify.TelegramNotifier
	if cfg.TelegramEnabled() {
		tgNotifier = notify.NewTelegramNotifier(cfg.TelegramBotToken, cfg.TelegramChatID)

		startCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := tgNotifier.NotifyStartup(startCtx, "all zones", version); err != nil {
			slog.Warn("Telegram startup notification failed", "error", err)
		}
		cancel()

		slog.Info("Telegram notifier enabled", "chat_id", cfg.TelegramChatID)
	}

	// ---------------------------------------------------------------------------
	// Multi-zone Monitor
	// ---------------------------------------------------------------------------
	multi := monitor.NewMultiMonitor(cfg, tgNotifier)

	// ---------------------------------------------------------------------------
	// Graceful Shutdown
	// ---------------------------------------------------------------------------
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	done := make(chan struct{})
	go func() {
		defer close(done)
		multi.Run(ctx)
	}()

	<-ctx.Done()
	slog.Info("Shutdown signal received",
		"active_zones", multi.ActiveCount(),
		"zones", strings.Join(multi.ActiveZones(), ", "),
	)

	// Beri waktu 30 detik untuk semua goroutine selesai
	shutdownTimer := time.NewTimer(30 * time.Second)
	defer shutdownTimer.Stop()

	select {
	case <-done:
		slog.Info("All monitors stopped cleanly")
	case <-shutdownTimer.C:
		slog.Warn("Forced exit after 30s shutdown timeout")
	}

	// Kirim notifikasi shutdown
	if tgNotifier != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tgNotifier.NotifyShutdown(shutdownCtx, "all zones", int64(multi.ActiveCount()))
	}

	slog.Info("WAF Automator exited", "monitored_zones", multi.ActiveCount())
}

// ---------------------------------------------------------------------------
// Startup Check
// ---------------------------------------------------------------------------

func runStartupCheck(cfg *config.Config) error {
	slog.Info("Running startup check...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Validasi token dengan mencoba fetch zone list
	zoneClient := cloudflare.NewZoneClient(cfg.CFApiToken, cfg.CFAccountID)
	zones, err := zoneClient.GetAllActiveZones(ctx)
	if err != nil {
		return fmt.Errorf(
			"cannot fetch zones: %w\n"+
				"  → Pastikan CF_API_TOKEN valid dan punya permission: Zone:Zone:Read, Zone:WAF:Edit, Zone:Analytics:Read\n"+
				"  → Pastikan CF_ACCOUNT_ID benar",
			err,
		)
	}

	if len(zones) == 0 {
		slog.Warn("No active zones found in account — monitor will run but have nothing to watch")
	} else {
		slog.Info("Startup check passed",
			"active_zones_in_account", len(zones),
		)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Config Help
// ---------------------------------------------------------------------------

func printConfigHelp() {
	fmt.Fprintln(os.Stderr, `
Required environment variables:
  CF_API_TOKEN      Cloudflare API token
                    Permissions needed:
                      - Zone > Zone > Read       (list all zones)
                      - Zone > WAF > Edit        (toggle rule action)
                      - Zone > Analytics > Read  (fetch RPS)
  CF_ACCOUNT_ID     Cloudflare Account ID

Optional environment variables (with defaults):
  ALLOW_RULE_NAME              allow-countries-ip   Description of rule to toggle
  EXCLUDED_ZONES               (empty)              Comma-separated domains to skip
                                                    e.g. "staging.com,internal.com"
  RPS_THRESHOLD                1000                 RPS limit before mitigation
  TRIGGER_DURATION_MINUTES     2                    Minutes breach must persist
  COOLDOWN_DURATION_MINUTES    15                   Minutes stable before recovery
  POLL_INTERVAL_SECONDS        60                   Polling interval (min: 30)
  ZONE_REFRESH_HOURS           1                    How often to re-check zone list
  LOG_LEVEL                    info                 "debug" for verbose output

Telegram (both required if either is set):
  TELEGRAM_BOT_TOKEN    Bot token from @BotFather
  TELEGRAM_CHAT_ID      Group chat ID (negative number)
`)
}