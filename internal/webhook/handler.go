package webhook

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"waf-attacker-automator/internal/executor"
)

// Prometheus Alertmanager payload structures
type Alert struct {
	Status      string            `json:"status"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    time.Time         `json:"startsAt"`
	EndsAt      time.Time         `json:"endsAt"`
}

type WebhookMessage struct {
	Receiver string  `json:"receiver"`
	Status   string  `json:"status"` // "firing" or "resolved"
	Alerts   []Alert `json:"alerts"`
}

type Handler struct {
	exec *executor.Executor
}

func NewHandler(exec *executor.Executor) *Handler {
	return &Handler{exec: exec}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var msg WebhookMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		slog.Error("Failed to decode webhook JSON", "error", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// We only care about Alerts processing
	for _, alert := range msg.Alerts {
		// Attempt to extract the target domain from labels
		domain := alert.Labels["domain"]
		if domain == "" {
			domain = alert.Labels["host"] // fallback
		}

		if domain == "" {
			slog.Warn("Received webhook alert without 'domain' or 'host' label", "status", alert.Status)
			continue
		}

		// Fire off execution based on the alert status
		// Execute in a separate goroutine so we don't block the HTTP response
		go h.handleAlert(context.Background(), domain, alert.Status)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status": "ok"}`))
}

func (h *Handler) handleAlert(ctx context.Context, domain, status string) {
	var err error

	slog.Info("Processing alert for domain", "domain", domain, "status", status)

	if status == "firing" {
		err = h.exec.TriggerMitigation(ctx, domain)
	} else if status == "resolved" {
		err = h.exec.ResolveMitigation(ctx, domain)
	} else {
		slog.Warn("Unknown alert status", "domain", domain, "status", status)
		return
	}

	if err != nil {
		slog.Error("Failed to execute mitigation action", "domain", domain, "status", status, "error", err)
	}
}
