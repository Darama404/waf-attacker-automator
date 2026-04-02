package notify

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "log/slog"
    "net/http"
    "sync"
    "time"
)

const telegramAPIBase = "https://api.telegram.org/bot%s/%s"

type TelegramNotifier struct {
    botToken string
    chatID   string
    client   *http.Client

    // Untuk edit-message strategy (live RPS report)
    mu            sync.Mutex
    statusMsgID   int // Message ID dari pesan status yang akan di-edit
}

func NewTelegramNotifier(botToken, chatID string) *TelegramNotifier {
    return &TelegramNotifier{
        botToken: botToken,
        chatID:   chatID,
        client: &http.Client{
            Timeout: 10 * time.Second,
        },
    }
}

// --- Structs untuk Telegram API ---

type sendMessagePayload struct {
    ChatID    string `json:"chat_id"`
    Text      string `json:"text"`
    ParseMode string `json:"parse_mode"` // "HTML" atau "MarkdownV2"
}

type editMessagePayload struct {
    ChatID    string `json:"chat_id"`
    MessageID int    `json:"message_id"`
    Text      string `json:"text"`
    ParseMode string `json:"parse_mode"`
}

type telegramResponse struct {
    OK     bool `json:"ok"`
    Result struct {
        MessageID int `json:"message_id"`
    } `json:"result"`
    Description string `json:"description"` // Error message dari Telegram
}

// --- Core API Methods ---

func (t *TelegramNotifier) sendMessage(ctx context.Context, text string) (int, error) {
    payload := sendMessagePayload{
        ChatID:    t.chatID,
        Text:      text,
        ParseMode: "HTML",
    }
    return t.callAPI(ctx, "sendMessage", payload)
}

func (t *TelegramNotifier) editMessage(ctx context.Context, msgID int, text string) error {
    payload := editMessagePayload{
        ChatID:    t.chatID,
        MessageID: msgID,
        Text:      text,
        ParseMode: "HTML",
    }
    _, err := t.callAPI(ctx, "editMessageText", payload)
    return err
}

func (t *TelegramNotifier) callAPI(ctx context.Context, method string, payload interface{}) (int, error) {
    url := fmt.Sprintf(telegramAPIBase, t.botToken, method)

    body, err := json.Marshal(payload)
    if err != nil {
        return 0, fmt.Errorf("marshal payload: %w", err)
    }

    req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
    if err != nil {
        return 0, fmt.Errorf("create request: %w", err)
    }
    req.Header.Set("Content-Type", "application/json")

    resp, err := t.client.Do(req)
    if err != nil {
        return 0, fmt.Errorf("http request failed: %w", err)
    }
    defer resp.Body.Close()

    respBody, _ := io.ReadAll(resp.Body)

    var tgResp telegramResponse
    if err := json.Unmarshal(respBody, &tgResp); err != nil {
        return 0, fmt.Errorf("decode response: %w", err)
    }

    if !tgResp.OK {
        return 0, fmt.Errorf("telegram API error: %s", tgResp.Description)
    }

    return tgResp.Result.MessageID, nil
}

// --- Public Notification Methods ---

// NotifyMitigationActivated kirim alert baru (bukan edit) — event penting
func (t *TelegramNotifier) NotifyMitigationActivated(ctx context.Context, zone string, rps float64, threshold float64) error {
    text := fmt.Sprintf(
        "🚨 <b>WAF ALERT — MITIGATION ACTIVATED</b>\n\n"+
            "🌐 <b>Zone:</b> <code>%s</code>\n"+
            "📈 <b>RPS Detected:</b> <code>%.0f req/s</code>\n"+
            "⚠️ <b>Threshold:</b> <code>%.0f req/s</code>\n"+
            "🔄 <b>Action:</b> Rule changed <code>skip → managed_challenge</code>\n"+
            "🕐 <b>Time:</b> <code>%s</code>\n\n"+
            "Traffic dari whitelist countries sekarang mendapat challenge.",
        zone, rps, threshold,
        time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
    )

    _, err := t.sendMessage(ctx, text)
    return err
}

// NotifyMitigationDeactivated kirim alert baru — event penting
func (t *TelegramNotifier) NotifyMitigationDeactivated(ctx context.Context, zone string, cooldownMin float64) error {
    text := fmt.Sprintf(
        "✅ <b>WAF ALERT — MITIGATION DEACTIVATED</b>\n\n"+
            "🌐 <b>Zone:</b> <code>%s</code>\n"+
            "🕒 <b>Stable for:</b> <code>%.0f minutes</code>\n"+
            "🔄 <b>Action:</b> Rule restored <code>managed_challenge → skip</code>\n"+
            "🕐 <b>Time:</b> <code>%s</code>\n\n"+
            "Traffic kembali normal. Rule allow dipulihkan.",
        zone, cooldownMin,
        time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
    )

    _, err := t.sendMessage(ctx, text)
    return err
}

// UpdateStatusMessage update/edit pesan status live — dipanggil setiap polling
// Strategi: kirim 1x saat pertama, lalu edit pesan yang sama → group tidak spam
func (t *TelegramNotifier) UpdateStatusMessage(ctx context.Context, status *StatusReport) error {
    t.mu.Lock()
    defer t.mu.Unlock()

    text := formatStatusMessage(status)

    if t.statusMsgID == 0 {
        // Belum ada pesan status — kirim baru
        msgID, err := t.sendMessage(ctx, text)
        if err != nil {
            return fmt.Errorf("send initial status: %w", err)
        }
        t.statusMsgID = msgID
        slog.Info("Telegram: initial status message sent", "msg_id", msgID)
        return nil
    }

    // Edit pesan yang sudah ada
    err := t.editMessage(ctx, t.statusMsgID, text)
    if err != nil {
        // Jika edit gagal (misal pesan terlalu lama / dihapus), kirim baru
        slog.Warn("Telegram: edit failed, sending new status message", "error", err)
        msgID, err2 := t.sendMessage(ctx, text)
        if err2 != nil {
            return fmt.Errorf("fallback send failed: %w", err2)
        }
        t.statusMsgID = msgID
    }

    return nil
}

// --- Status Report Struct & Formatter ---

type StatusReport struct {
    Zone         string
    CurrentRPS   float64
    Threshold    float64
    State        string
    PollCount    int64
    LastPollTime time.Time
    // Durasi state saat ini
    StateDuration time.Duration
}

func formatStatusMessage(s *StatusReport) string {
    // State indicator
    stateIcon := map[string]string{
        "NORMAL":       "🟢",
        "BREACHING":    "🟡",
        "MITIGATING":   "🔴",
        "COOLING_DOWN": "🔵",
    }
    icon := stateIcon[s.State]
    if icon == "" {
        icon = "⚪"
    }

    // RPS bar visual (max 20 karakter, threshold = 100%)
    rpsBar := buildRPSBar(s.CurrentRPS, s.Threshold)

    return fmt.Sprintf(
        "📊 <b>WAF Monitor — Live Status</b>\n"+
            "━━━━━━━━━━━━━━━━━━━━\n"+
            "🌐 <b>Zone:</b> <code>%s</code>\n"+
            "%s <b>State:</b> <code>%s</code>\n"+
            "⏱ <b>In state for:</b> <code>%s</code>\n"+
            "━━━━━━━━━━━━━━━━━━━━\n"+
            "📈 <b>Current RPS:</b> <code>%.1f req/s</code>\n"+
            "🎯 <b>Threshold:</b>   <code>%.0f req/s</code>\n"+
            "%s\n"+
            "━━━━━━━━━━━━━━━━━━━━\n"+
            "🔄 Poll #%d | 🕐 <code>%s</code>",
        s.Zone,
        icon, s.State,
        formatDuration(s.StateDuration),
        s.CurrentRPS,
        s.Threshold,
        rpsBar,
        s.PollCount,
        s.LastPollTime.UTC().Format("15:04:05 UTC"),
    )
}

// buildRPSBar membuat visual bar RPS relatif terhadap threshold
func buildRPSBar(rps, threshold float64) string {
    const barLen = 10
    ratio := rps / threshold
    if ratio > 2 {
        ratio = 2 // Cap di 200%
    }
    filled := int(ratio * float64(barLen))
    if filled > barLen {
        filled = barLen
    }

    bar := ""
    for i := 0; i < barLen; i++ {
        if i < filled {
            if ratio >= 1.0 {
                bar += "🟥"
            } else if ratio >= 0.7 {
                bar += "🟧"
            } else {
                bar += "🟩"
            }
        } else {
            bar += "⬜"
        }
    }

    percentage := ratio * 100
    return fmt.Sprintf("%s <code>%.0f%%</code> of threshold", bar, percentage)
}

func formatDuration(d time.Duration) string {
    if d < time.Minute {
        return fmt.Sprintf("%ds", int(d.Seconds()))
    }
    if d < time.Hour {
        return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
    }
    return fmt.Sprintf("%dh %dm", int(d.Hours()), int(d.Minutes())%60)
}