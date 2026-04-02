package trappsec

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"log"
	"math"
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

var slackEventLabels = map[string]string{
	"trappsec.watch_hit": "Honey Field Accessed",
	"trappsec.trap_hit":  "Decoy Route Triggered",
	"trappsec.rule_hit":  "Security Rule Triggered",
}

func slackDateToken(ts float64) string {
	seconds := int64(ts)
	if seconds <= 0 {
		return "-"
	}
	fallback := time.Unix(seconds, 0).UTC().Format("2006-01-02 15:04:05 UTC")
	return fmt.Sprintf("<!date^%d^{date_short_pretty} at {time_secs}|%s>", seconds, fallback)
}

func kvLine(key, value string) string {
	if value == "" {
		return ""
	}
	return fmt.Sprintf("*%s:* %s", key, value)
}

func compactLines(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			out = append(out, line)
		}
	}
	return out
}

func slackNotificationText(eventName, severity, svc, user, method, path string, found []FoundField) string {
	actor := user
	if actor == "" {
		actor = "An unauthenticated request"
	}
	switch eventName {
	case "trappsec.watch_hit":
		names := make([]string, 0, 3)
		for i, f := range found {
			if i >= 3 {
				break
			}
			if f.Field != "" {
				names = append(names, f.Field)
			}
		}
		suffix := ""
		if len(names) > 0 {
			suffix = " (" + strings.Join(names, ", ") + ")"
		}
		return fmt.Sprintf("[%s] %s accessed a monitored field%s on %s", severity, actor, suffix, svc)
	case "trappsec.trap_hit":
		return fmt.Sprintf("[%s] Honeypot endpoint hit on %s - %s %s", severity, svc, method, path)
	case "trappsec.rule_hit":
		return fmt.Sprintf("[%s] Security rule triggered on %s - %s %s", severity, svc, method, path)
	}
	return fmt.Sprintf("[%s] %s on %s", severity, eventName, svc)
}

func buildSlackPayload(event TriggerContext) any {
	level := "signal"
	if strings.EqualFold(event.Type, "alert") {
		level = "alert"
	}
	color := "#0066CC"
	if level == "alert" {
		color = "#CC0000"
	}

	eventName := event.Event
	if eventName == "" {
		eventName = "trappsec.event"
	}
	path := fallback(event.Path)
	method := fallback(event.Method)
	service := event.App.Service
	if service == "" {
		service = "unknown-service"
	}
	environment := event.App.Environment
	if environment == "" {
		environment = "unknown-env"
	}
	when := slackDateToken(event.Timestamp)

	route := "-"
	if !(method == "-" && path == "-") {
		route = strings.TrimSpace(method + " " + path)
	}

	eventLines := compactLines([]string{
		kvLine("Event", func() string {
			if label, ok := slackEventLabels[eventName]; ok {
				return label
			}
			return eventName
		}()),
		kvLine("Timestamp", when),
		kvLine("Service", service),
		kvLine("Environment", environment),
		kvLine("Host", event.App.Hostname),
	})
	requestLines := compactLines([]string{
		kvLine("IP", event.IP),
		kvLine("Route", route),
		kvLine("User Agent", event.UserAgent),
		kvLine("User", event.User),
		kvLine("Role", event.Role),
	})

	blocks := []any{
		map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": strings.Join(eventLines, "\n")}},
	}
	if len(requestLines) > 0 {
		blocks = append(blocks,
			map[string]any{"type": "divider"},
			map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": strings.Join(requestLines, "\n")}},
		)
	}

	if strings.EqualFold(event.Event, "trappsec.watch_hit") && len(event.Found) > 0 {
		limit := len(event.Found)
		if limit > 8 {
			limit = 8
		}
		lines := make([]string, 0, limit)
		for i := 0; i < limit; i++ {
			f := event.Found[i]
			parts := []string{fallback(f.Field)}
			if f.Type != "" {
				parts = append(parts, "["+f.Type+"]")
			}
			if f.Intent != "" {
				parts = append(parts, "- "+f.Intent)
			}
			lines = append(lines, kvLine(fmt.Sprintf("Triggered Field %d", i+1), strings.Join(parts, " ")))
		}
		blocks = append(blocks,
			map[string]any{"type": "divider"},
			map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": strings.Join(lines, "\n")}},
		)
	}

	details := []string{}
	if event.Intent != "" {
		details = append(details, kvLine("Intent", event.Intent))
	}
	if event.Reason != "" {
		details = append(details, kvLine("Reason", event.Reason))
	}
	details = compactLines(details)
	if len(details) > 0 {
		blocks = append(blocks,
			map[string]any{"type": "divider"},
			map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": strings.Join(details, "\n")}},
		)
	}

	return map[string]any{
		"text":        "",
		"attachments": []map[string]any{{"color": color, "blocks": blocks}},
	}
}

func fallback(v string) string {
	if v == "" {
		return "-"
	}
	return v
}

type OTELHandler struct{}

func (h *OTELHandler) EmitWithContext(ctx context.Context, event TriggerContext) error {
	if ctx == nil {
		return nil
	}
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return nil
	}

	attrs := []attribute.KeyValue{
		attribute.Bool("trappsec.detected", true),
		attribute.String("trappsec.event", event.Event),
		attribute.String("trappsec.type", event.Type),
	}
	if event.User != "" {
		attrs = append(attrs, attribute.String("trappsec.user", event.User))
	}
	if event.Role != "" {
		attrs = append(attrs, attribute.String("trappsec.role", event.Role))
	}
	if event.IP != "" {
		attrs = append(attrs, attribute.String("trappsec.ip", event.IP))
	}
	if event.Intent != "" && (event.Event == "trappsec.trap_hit" || event.Event == "trappsec.rule_hit") {
		attrs = append(attrs, attribute.String("trappsec.intent", event.Intent))
	}
	if event.Reason != "" && event.Event == "trappsec.rule_hit" {
		attrs = append(attrs, attribute.String("trappsec.reason", event.Reason))
	}
	span.SetAttributes(attrs...)

	if event.Event == "trappsec.watch_hit" {
		for _, field := range event.Found {
			span.AddEvent("watch_hit", trace.WithAttributes(
				attribute.String("type", field.Type),
				attribute.String("field", field.Field),
				attribute.String("intent", field.Intent),
				toAttribute("value", field.Value),
			))
		}
	}

	if metadata, ok := event.Metadata.(map[string]any); ok {
		metadataAttrs := make([]attribute.KeyValue, 0, len(metadata))
		for k, v := range metadata {
			metadataAttrs = append(metadataAttrs, toAttribute("metadata."+k, v))
		}
		if len(metadataAttrs) > 0 {
			span.SetAttributes(metadataAttrs...)
		}
	}

	return nil
}

func (h *OTELHandler) Emit(event TriggerContext) error {
	// Backwards-compatible fallback when no request context is available.
	return h.EmitWithContext(context.Background(), event)
}

func toAttribute(key string, value any) attribute.KeyValue {
	switch v := value.(type) {
	case string:
		return attribute.String(key, v)
	case bool:
		return attribute.Bool(key, v)
	case int:
		return attribute.Int64(key, int64(v))
	case int8:
		return attribute.Int64(key, int64(v))
	case int16:
		return attribute.Int64(key, int64(v))
	case int32:
		return attribute.Int64(key, int64(v))
	case int64:
		return attribute.Int64(key, v)
	case uint:
		return attribute.Int64(key, int64(v))
	case uint8:
		return attribute.Int64(key, int64(v))
	case uint16:
		return attribute.Int64(key, int64(v))
	case uint32:
		return attribute.Int64(key, int64(v))
	case uint64:
		if v > uint64(math.MaxInt64) {
			return attribute.String(key, fmt.Sprintf("%v", v))
		}
		return attribute.Int64(key, int64(v))
	case float32:
		return attribute.Float64(key, float64(v))
	case float64:
		return attribute.Float64(key, v)
	case []string:
		return attribute.StringSlice(key, v)
	case []bool:
		return attribute.BoolSlice(key, v)
	case []int:
		out := make([]int64, len(v))
		for i := range v {
			out[i] = int64(v[i])
		}
		return attribute.Int64Slice(key, out)
	case []int64:
		return attribute.Int64Slice(key, v)
	case []float64:
		return attribute.Float64Slice(key, v)
	case []float32:
		out := make([]float64, len(v))
		for i := range v {
			out[i] = float64(v[i])
		}
		return attribute.Float64Slice(key, out)
	default:
		return attribute.String(key, fmt.Sprintf("%v", v))
	}
}
