package trappsec

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

type EventHandler interface {
	Emit(event TriggerContext) error
}

type LogHandler struct {
	logger *log.Logger
}

func (h *LogHandler) Emit(event TriggerContext) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	h.logger.Println(string(data))
	return nil
}

type WebhookOptions struct {
	Secret            string
	Headers           map[string]string
	HeartbeatInterval int
	Template          func(TriggerContext) any
	Service           string
	Environment       string
	AlertsOnly        *bool
}

type SlackOptions struct {
	AlertsOnly *bool
}

type WebhookHandler struct {
	url         string
	secret      string
	headers     map[string]string
	template    func(TriggerContext) any
	service     string
	environment string
	alertsOnly  bool
	client      *http.Client
}

type SlackHandler struct {
	webhook *WebhookHandler
}

func NewWebhookHandler(url string, opts *WebhookOptions) (*WebhookHandler, error) {
	if url == "" {
		return nil, fmt.Errorf("webhook url is required")
	}
	if opts == nil {
		opts = &WebhookOptions{}
	}
	alertsOnly := true
	if opts.AlertsOnly != nil {
		alertsOnly = *opts.AlertsOnly
	}

	h := &WebhookHandler{
		url:         url,
		secret:      opts.Secret,
		headers:     map[string]string{"Content-Type": "application/json"},
		template:    opts.Template,
		service:     opts.Service,
		environment: opts.Environment,
		alertsOnly:  alertsOnly,
		client:      &http.Client{Timeout: 5 * time.Second},
	}
	for k, v := range opts.Headers {
		h.headers[k] = v
	}

	if opts.HeartbeatInterval > 0 {
		go h.heartbeatLoop(opts.HeartbeatInterval)
	}

	return h, nil
}

func (h *WebhookHandler) Emit(event TriggerContext) error {
	if h.alertsOnly && event.Type != "alert" {
		return nil
	}

	payload := any(event)
	if h.template != nil {
		payload = h.template(event)
	}
	return h.send(payload)
}

func (h *WebhookHandler) heartbeatLoop(interval int) {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		_ = h.send(map[string]any{
			"timestamp":   float64(time.Now().UnixNano()) / 1e9,
			"event":       "trappsec.heartbeat",
			"service":     h.service,
			"environment": h.environment,
		})
	}
}

func (h *WebhookHandler) send(payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, h.url, bytes.NewReader(data))
	if err != nil {
		return err
	}

	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	if h.secret != "" {
		mac := hmac.New(sha256.New, []byte(h.secret))
		mac.Write(data)
		req.Header.Set("x-trappsec-signature", hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func NewSlackHandler(url string, opts *SlackOptions) (*SlackHandler, error) {
	if opts == nil {
		opts = &SlackOptions{}
	}

	wh, err := NewWebhookHandler(url, &WebhookOptions{
		AlertsOnly: opts.AlertsOnly,
		Template:   buildSlackPayload,
	})
	if err != nil {
		return nil, err
	}

	return &SlackHandler{webhook: wh}, nil
}

func (h *SlackHandler) Emit(event TriggerContext) error {
	return h.webhook.Emit(event)
}

func buildSlackPayload(event TriggerContext) any {
	severity := "SIGNAL"
	emoji := ":large_blue_circle:"
	if strings.EqualFold(event.Type, "alert") {
		severity = "ALERT"
		emoji = ":rotating_light:"
	}

	eventName := event.Event
	if eventName == "" {
		eventName = "trappsec.event"
	}
	path := event.Path
	if path == "" {
		path = "-"
	}
	method := event.Method
	if method == "" {
		method = "-"
	}
	user := event.User
	if user == "" {
		user = "-"
	}
	role := event.Role
	if role == "" {
		role = "-"
	}
	ip := event.IP
	if ip == "" {
		ip = "-"
	}
	service := event.App.Service
	if service == "" {
		service = "unknown-service"
	}
	environment := event.App.Environment
	if environment == "" {
		environment = "unknown-env"
	}
	hostname := event.App.Hostname
	if hostname == "" {
		hostname = "unknown-host"
	}
	intent := event.Intent
	if intent == "" {
		intent = "-"
	}
	reason := event.Reason
	if reason == "" {
		reason = "-"
	}
	ua := event.UserAgent
	if ua == "" {
		ua = "-"
	}

	fields := []map[string]string{
		{"type": "mrkdwn", "text": "*Severity*\n" + severity},
		{"type": "mrkdwn", "text": "*Event*\n`" + eventName + "`"},
		{"type": "mrkdwn", "text": "*Service*\n`" + service + "`"},
		{"type": "mrkdwn", "text": "*Environment*\n`" + environment + "`"},
		{"type": "mrkdwn", "text": "*Method*\n`" + method + "`"},
		{"type": "mrkdwn", "text": "*Path*\n`" + path + "`"},
		{"type": "mrkdwn", "text": "*User*\n`" + user + "`"},
		{"type": "mrkdwn", "text": "*Role*\n`" + role + "`"},
		{"type": "mrkdwn", "text": "*IP*\n`" + ip + "`"},
		{"type": "mrkdwn", "text": "*Host*\n`" + hostname + "`"},
	}

	blocks := []any{
		map[string]any{"type": "header", "text": map[string]any{"type": "plain_text", "text": emoji + " Trappsec " + severity}},
		map[string]any{"type": "section", "fields": fields},
		map[string]any{"type": "context", "elements": []any{map[string]any{"type": "mrkdwn", "text": "*User-Agent:* `" + ua + "`"}}},
	}

	if strings.EqualFold(event.Event, "trappsec.watch_hit") && len(event.Found) > 0 {
		lines := make([]string, 0, len(event.Found))
		limit := len(event.Found)
		if limit > 8 {
			limit = 8
		}
		for i := 0; i < limit; i++ {
			f := event.Found[i]
			lines = append(lines, "- `"+fallback(f.Type)+"` `"+fallback(f.Field)+"` ("+fallback(f.Intent)+")")
		}
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": "*Triggered Fields*\n" + strings.Join(lines, "\n")},
		})
	}

	if intent != "-" || reason != "-" {
		blocks = append(blocks, map[string]any{
			"type": "section",
			"fields": []map[string]string{
				{"type": "mrkdwn", "text": "*Intent*\n" + intent},
				{"type": "mrkdwn", "text": "*Reason*\n" + reason},
			},
		})
	}

	return map[string]any{
		"text":   fmt.Sprintf("[%s] %s %s %s (%s/%s)", severity, eventName, method, path, service, environment),
		"blocks": blocks,
	}
}

func fallback(v string) string {
	if v == "" {
		return "-"
	}
	return v
}

type OTELHandler struct{}

func (h *OTELHandler) Emit(_ TriggerContext) error {
	// OTEL enrichment in Go requires request context propagation through trigger events.
	// This placeholder keeps API compatibility; integration can pass context-aware events in a follow-up.
	return nil
}
