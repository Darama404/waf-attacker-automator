package executor

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"waf-attacker-automator/internal/cloudflare"
	"waf-attacker-automator/internal/config"
	"waf-attacker-automator/internal/notify"
)

// Executor manages WAF mitigation states by keeping an in-memory cache
// of all active zones and their corresponding target rules to allow instant WAF updates via webhooks.
type Executor struct {
	cfg        *config.Config
	zoneClient *cloudflare.ZoneClient
	telegram   *notify.TelegramNotifier

	mu         sync.RWMutex
	rulesCache map[string]*cloudflare.ZoneRule  // key: domain (zone name)
	wafClients map[string]*cloudflare.WAFClient // key: domain (zone name)
}

func NewExecutor(cfg *config.Config, telegram *notify.TelegramNotifier) *Executor {
	return &Executor{
		cfg:        cfg,
		zoneClient: cloudflare.NewZoneClient(cfg.CFApiToken, cfg.CFAccountID),
		telegram:   telegram,
		rulesCache: make(map[string]*cloudflare.ZoneRule),
		wafClients: make(map[string]*cloudflare.WAFClient),
	}
}

// Discover pre-fetches zones and rule configurations and populates the cache.
// Call this during application startup.
func (e *Executor) Discover(ctx context.Context) error {
	slog.Info("Discovering zones and WAF rules...")

	zones, err := e.zoneClient.GetAllActiveZones(ctx)
	if err != nil {
		return fmt.Errorf("get zones: %w", err)
	}

	newCount := 0
	skippedCount := 0

	e.mu.Lock()
	defer e.mu.Unlock()

	for _, z := range zones {
		if e.cfg.IsZoneExcluded(z.Name) {
			slog.Debug("Zone excluded", "zone", z.Name)
			skippedCount++
			continue
		}

		findCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		rule, err := e.zoneClient.FindRuleByName(findCtx, z, e.cfg.AllowRuleName)
		cancel()

		if err != nil {
			slog.Warn("Rule not found in zone — skipping", "zone", z.Name, "rule_name", e.cfg.AllowRuleName)
			continue
		}

		e.rulesCache[z.Name] = rule
		e.wafClients[z.Name] = cloudflare.NewWAFClient(e.cfg.CFApiToken, rule.ZoneID, rule.RulesetID, rule.RuleID)
		newCount++

		slog.Debug("Cached rule", "zone", z.Name, "rule_id", rule.RuleID)
	}

	slog.Info("Discovery complete", "cached", newCount, "skipped", skippedCount)
	return nil
}

// TriggerMitigation updates the Cloudflare rule to Managed Challenge when an alert fires.
func (e *Executor) TriggerMitigation(ctx context.Context, domain string) error {
	e.mu.RLock()
	waf, wafExists := e.wafClients[domain]
	rule, ruleExists := e.rulesCache[domain]
	e.mu.RUnlock()

	if !wafExists || !ruleExists {
		return fmt.Errorf("domain %s not in cache or no such rule configured", domain)
	}

	apiCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := waf.SetRuleAction(apiCtx, cloudflare.ActionManagedChallenge, rule.Expression); err != nil {
		return fmt.Errorf("cloudflare PATCH failed: %w", err)
	}

	slog.Warn("Mitigation ACTIVATED via webhook", "zone", domain)

	if e.telegram != nil {
		tgCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := e.telegram.NotifyMitigationActivated(tgCtx, domain); err != nil {
			slog.Warn("Telegram alert failed", "zone", domain, "error", err)
		}
	}
	return nil
}

// ResolveMitigation updates the Cloudflare rule to Skip when the alert resolves.
func (e *Executor) ResolveMitigation(ctx context.Context, domain string) error {
	e.mu.RLock()
	waf, wafExists := e.wafClients[domain]
	rule, ruleExists := e.rulesCache[domain]
	e.mu.RUnlock()

	if !wafExists || !ruleExists {
		return fmt.Errorf("domain %s not in cache or no such rule configured", domain)
	}

	apiCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := waf.SetRuleAction(apiCtx, cloudflare.ActionSkip, rule.Expression); err != nil {
		return fmt.Errorf("cloudflare PATCH failed: %w", err)
	}

	slog.Info("Mitigation DEACTIVATED via webhook", "zone", domain)

	if e.telegram != nil {
		tgCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if err := e.telegram.NotifyMitigationDeactivated(tgCtx, domain); err != nil {
			slog.Warn("Telegram alert failed", "zone", domain, "error", err)
		}
	}
	return nil
}

func (e *Executor) GetCachedZoneCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rulesCache)
}
