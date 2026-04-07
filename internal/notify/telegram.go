package notify

import (
    "bytes"
    "context"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "time"
)

const telegramAPIBase = "https://api.telegram.org/bot%s/%s"

type TelegramNotifier struct {
    botToken string
    chatID   string
    client   *http.Client
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
func (t *TelegramNotifier) NotifyMitigationActivated(ctx context.Context, zone string) error {
    text := fmt.Sprintf(
        "🚨 <b>WAF ALERT — MITIGATION ACTIVATED</b>\n\n"+
            "🌐 <b>Zone:</b> <code>%s</code>\n"+
            "🔄 <b>Action:</b> Rule changed <code>skip → managed_challenge</code>\n"+
            "🕐 <b>Time:</b> <code>%s</code>\n\n"+
            "Traffic dari whitelist countries sekarang mendapat challenge.",
        zone,
        time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
    )

    _, err := t.sendMessage(ctx, text)
    return err
}

// NotifyMitigationDeactivated kirim alert baru — event penting
func (t *TelegramNotifier) NotifyMitigationDeactivated(ctx context.Context, zone string) error {
    text := fmt.Sprintf(
        "✅ <b>WAF ALERT — MITIGATION DEACTIVATED</b>\n\n"+
            "🌐 <b>Zone:</b> <code>%s</code>\n"+
            "🔄 <b>Action:</b> Rule restored <code>managed_challenge → skip</code>\n"+
            "🕐 <b>Time:</b> <code>%s</code>\n\n"+
            "Traffic kembali normal. Rule allow dipulihkan.",
        zone,
        time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
    )

    _, err := t.sendMessage(ctx, text)
    return err
}



// NotifyStartup kirim pesan saat service pertama kali jalan
func (t *TelegramNotifier) NotifyStartup(ctx context.Context, zone string, version string) error {
	text := fmt.Sprintf(
		"🟢 <b>WAF Automator Started</b>\n\n"+
			"🌐 <b>Mode:</b> <code>Multi-Zone</code>\n"+
			"🏷 <b>Version:</b> <code>%s</code>\n"+
			"🔍 <b>Monitoring:</b> <code>%s</code>\n"+
			"🕐 <b>Time:</b> <code>%s</code>\n\n"+
			"Service aktif dan mulai memantau semua zone.",
		version,
		zone,
		time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
	)
	_, err := t.sendMessage(ctx, text)
	return err
}

// NotifyShutdown kirim pesan saat service berhenti
func (t *TelegramNotifier) NotifyShutdown(ctx context.Context, zone string, activeZones int64) error {
	text := fmt.Sprintf(
		"🔴 <b>WAF Automator Stopped</b>\n\n"+
			"🌐 <b>Mode:</b> <code>Multi-Zone</code>\n"+
			"📊 <b>Was monitoring:</b> <code>%d zones</code>\n"+
			"🕐 <b>Time:</b> <code>%s</code>\n\n"+
			"Service telah berhenti.",
		activeZones,
		time.Now().UTC().Format("2006-01-02 15:04:05 UTC"),
	)
	_, err := t.sendMessage(ctx, text)
	return err
}