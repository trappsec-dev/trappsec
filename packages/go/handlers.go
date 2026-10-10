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
	"io"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
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
	// Logger receives delivery failures and drop warnings (default: log.Default()).
	Logger *log.Logger
}

type SlackOptions struct {
	AlertsOnly *bool
	Logger     *log.Logger
}

const (
	webhookQueueSize  = 1000
	webhookMaxRetries = 2
	dropLogInterval   = 60 * time.Second
)

// WebhookHandler delivers events asynchronously: Emit only enqueues onto a
// bounded buffer (capacity 1000) drained by a single worker goroutine, so a
// slow or dead endpoint can never delay the host request. Delivery is retried
// at most twice in the worker. Call Close to flush and stop the goroutines.
type WebhookHandler struct {
	url         string
	secret      string
	headers     map[string]string
	template    func(TriggerContext) any
	service     string
	environment string
	alertsOnly  bool
	client      *http.Client
	logger      *log.Logger

	queue      chan []byte
	quit       chan struct{} // closed on Close: stops heartbeat
	workerDone chan struct{}
	hbDone     chan struct{}
	baseCtx    context.Context
	cancel     context.CancelFunc
	backoff    []time.Duration

	mu     sync.RWMutex // guards closed and sends on queue
	closed bool

	dropMu   sync.Mutex
	lastDrop time.Time
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
	logger := opts.Logger
	if logger == nil {
		logger = log.Default()
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
		logger:      logger,
		queue:       make(chan []byte, webhookQueueSize),
		quit:        make(chan struct{}),
		workerDone:  make(chan struct{}),
		backoff:     []time.Duration{200 * time.Millisecond, 600 * time.Millisecond},
	}
	h.baseCtx, h.cancel = context.WithCancel(context.Background())
	for k, v := range opts.Headers {
		h.headers[k] = v
	}

	go h.worker()
	if opts.HeartbeatInterval > 0 {
		h.hbDone = make(chan struct{})
		go h.heartbeatLoop(opts.HeartbeatInterval)
	}

	return h, nil
}

// Emit enqueues the event for asynchronous delivery. It never blocks and
// never performs I/O. A panicking Template drops the event for this handler
// (the raw event is never sent in its place).
func (h *WebhookHandler) Emit(event TriggerContext) error {
	if h.alertsOnly && event.Type != "alert" {
		return nil
	}

	payload := any(event)
	if h.template != nil {
		var ok bool
		payload, ok = h.runTemplate(event)
		if !ok {
			return nil
		}
	}
	data, err := marshalPayload(payload)
	if err != nil {
		h.logger.Printf("trappsec: webhook payload not serializable, dropping event: %v", err)
		return nil
	}
	h.enqueue(data)
	return nil
}

func (h *WebhookHandler) runTemplate(event TriggerContext) (out any, ok bool) {
	defer func() {
		if r := recover(); r != nil {
			h.logger.Printf("trappsec: webhook template panicked, dropping event: %v", r)
			out, ok = nil, false
		}
	}()
	return h.template(event), true
}

func marshalPayload(v any) (data []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			data, err = nil, fmt.Errorf("panic while marshaling: %v", r)
		}
	}()
	return json.Marshal(v)
}

func (h *WebhookHandler) enqueue(data []byte) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.closed {
		return
	}
	select {
	case h.queue <- data:
	default:
		h.dropMu.Lock()
		now := time.Now()
		warn := h.lastDrop.IsZero() || now.Sub(h.lastDrop) >= dropLogInterval
		if warn {
			h.lastDrop = now
		}
		h.dropMu.Unlock()
		if warn {
			h.logger.Printf("trappsec: webhook queue full (%d), dropping events", webhookQueueSize)
		}
	}
}

func (h *WebhookHandler) heartbeatLoop(interval int) {
	defer close(h.hbDone)
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-h.quit:
			return
		case <-ticker.C:
			data, err := marshalPayload(map[string]any{
				"timestamp":   float64(time.Now().UnixNano()) / 1e9,
				"event":       "trappsec.heartbeat",
				"service":     h.service,
				"environment": h.environment,
			})
			if err == nil {
				h.enqueue(data)
			}
		}
	}
}

// Close stops the heartbeat, flushes queued events (bounded by ctx) and stops
// the worker. After Close, Emit silently discards events. Safe to call more
// than once.
func (h *WebhookHandler) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		<-h.workerDone
		return nil
	}
	h.closed = true
	close(h.quit)
	close(h.queue) // no sender can be mid-send: enqueue holds RLock
	h.mu.Unlock()

	if h.hbDone != nil {
		select {
		case <-h.hbDone:
		case <-ctx.Done():
		}
	}
	select {
	case <-h.workerDone:
		h.cancel()
		return nil
	case <-ctx.Done():
		h.cancel() // abort in-flight delivery and discard the rest
		<-h.workerDone
		return fmt.Errorf("trappsec: webhook close timed out before flushing queue: %w", ctx.Err())
	}
}

func (h *WebhookHandler) worker() {
	defer close(h.workerDone)
	for data := range h.queue {
		if h.baseCtx.Err() != nil {
			continue // closing past deadline: discard
		}
		h.deliver(data)
	}
}

func (h *WebhookHandler) deliver(data []byte) {
	var lastErr error
	for attempt := 0; attempt <= webhookMaxRetries; attempt++ {
		if attempt > 0 {
			d := h.backoff[len(h.backoff)-1]
			if attempt-1 < len(h.backoff) {
				d = h.backoff[attempt-1]
			}
			select {
			case <-time.After(d):
			case <-h.baseCtx.Done():
				return
			}
		}
		retry, err := h.send(data)
		if err == nil {
			return
		}
		lastErr = err
		if !retry {
			break
		}
	}
	h.logger.Printf("trappsec: webhook delivery failed: %v", lastErr)
}

// send performs one POST. It reports whether a failure is worth retrying.
func (h *WebhookHandler) send(data []byte) (retry bool, err error) {
	req, err := http.NewRequestWithContext(h.baseCtx, http.MethodPost, h.url, bytes.NewReader(data))
	if err != nil {
		return false, err
	}
	for k, v := range h.headers {
		req.Header.Set(k, v)
	}
	if h.secret != "" {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		req.Header.Set("x-trappsec-timestamp", ts)
		req.Header.Set("x-trappsec-signature", signPayload(h.secret, ts, data))
	}

	resp, err := h.client.Do(req)
	if err != nil {
		return true, err
	}
	// Drain (bounded) and close so the connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode >= 500 || resp.StatusCode == http.StatusTooManyRequests,
			fmt.Errorf("webhook responded with status %d", resp.StatusCode)
	}
	return false, nil
}

// signPayload returns "sha256=<hex HMAC-SHA256(secret, "<timestamp>.<body>")>".
func signPayload(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func NewSlackHandler(url string, opts *SlackOptions) (*SlackHandler, error) {
	if opts == nil {
		opts = &SlackOptions{}
	}

	wh, err := NewWebhookHandler(url, &WebhookOptions{
		AlertsOnly: opts.AlertsOnly,
		Template:   buildSlackPayload,
		Logger:     opts.Logger,
	})
	if err != nil {
		return nil, err
	}

	return &SlackHandler{webhook: wh}, nil
}

func (h *SlackHandler) Emit(event TriggerContext) error {
	return h.webhook.Emit(event)
}

// Close flushes and stops the underlying delivery worker.
func (h *SlackHandler) Close(ctx context.Context) error {
	return h.webhook.Close(ctx)
}

// slackEscape escapes the characters Slack treats as control sequences in
// mrkdwn/text (&, <, >) so request-derived values cannot inject links or
// mentions such as <!channel>.
func slackEscape(s string) string {
	if !strings.ContainsAny(s, "&<>") {
		return s
	}
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
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

// kvLine renders "*key:* value"; value must already be Slack-safe.
func kvLine(key, value string) string {
	if value == "" {
		return ""
	}
	return fmt.Sprintf("*%s:* %s", key, value)
}

// kvEsc renders a line from an untrusted value, escaping it first.
func kvEsc(key, value string) string {
	return kvLine(key, slackEscape(value))
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
		kvEsc("Event", func() string {
			if label, ok := slackEventLabels[eventName]; ok {
				return label
			}
			return eventName
		}()),
		kvLine("Timestamp", when),
		kvEsc("Service", service),
		kvEsc("Environment", environment),
		kvEsc("Host", event.App.Hostname),
	})
	requestLines := compactLines([]string{
		kvEsc("IP", event.IP),
		kvEsc("Route", route),
		kvEsc("User Agent", event.UserAgent),
		kvEsc("User", event.User),
		kvEsc("Role", event.Role),
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
			lines = append(lines, kvEsc(fmt.Sprintf("Triggered Field %d", i+1), strings.Join(parts, " ")))
		}
		blocks = append(blocks,
			map[string]any{"type": "divider"},
			map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": strings.Join(lines, "\n")}},
		)
	}

	details := []string{}
	if event.Intent != "" {
		details = append(details, kvEsc("Intent", event.Intent))
	}
	if event.Reason != "" {
		details = append(details, kvEsc("Reason", event.Reason))
	}
	details = compactLines(details)
	if len(details) > 0 {
		blocks = append(blocks,
			map[string]any{"type": "divider"},
			map[string]any{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": strings.Join(details, "\n")}},
		)
	}

	return map[string]any{
		"text": slackNotificationText(eventName, level, slackEscape(service), slackEscape(event.User),
			slackEscape(event.Method), slackEscape(event.Path), escapeFound(event.Found)),
		"attachments": []map[string]any{{"color": color, "blocks": blocks}},
	}
}

func escapeFound(in []FoundField) []FoundField {
	out := make([]FoundField, len(in))
	for i, f := range in {
		out[i] = FoundField{Type: f.Type, Field: slackEscape(f.Field), Intent: f.Intent}
	}
	return out
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
			evAttrs := []attribute.KeyValue{
				attribute.String("type", field.Type),
				attribute.String("field", field.Field),
				attribute.String("intent", field.Intent),
			}
			if kv, ok := toAttribute("value", field.Value); ok {
				evAttrs = append(evAttrs, kv)
			}
			span.AddEvent("watch_hit", trace.WithAttributes(evAttrs...))
		}
	}

	if metadata, ok := event.Metadata.(map[string]any); ok {
		metadataAttrs := make([]attribute.KeyValue, 0, len(metadata))
		for k, v := range metadata {
			if kv, ok := toAttribute("metadata."+k, v); ok {
				metadataAttrs = append(metadataAttrs, kv)
			}
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

// toAttribute coerces a value to a valid OTel attribute: string, bool, int64,
// float64 or a homogeneous slice of those. nil is dropped (ok=false); anything
// else (maps, structs, mixed lists) is stringified (JSON when possible).
func toAttribute(key string, value any) (attribute.KeyValue, bool) {
	switch v := value.(type) {
	case nil:
		return attribute.KeyValue{}, false
	case string:
		return attribute.String(key, v), true
	case bool:
		return attribute.Bool(key, v), true
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return attribute.Int64(key, i), true
		}
		if f, err := v.Float64(); err == nil {
			return attribute.Float64(key, f), true
		}
		return attribute.String(key, string(v)), true
	case int:
		return attribute.Int64(key, int64(v)), true
	case int8:
		return attribute.Int64(key, int64(v)), true
	case int16:
		return attribute.Int64(key, int64(v)), true
	case int32:
		return attribute.Int64(key, int64(v)), true
	case int64:
		return attribute.Int64(key, v), true
	case uint:
		return uintAttr(key, uint64(v)), true
	case uint8:
		return attribute.Int64(key, int64(v)), true
	case uint16:
		return attribute.Int64(key, int64(v)), true
	case uint32:
		return attribute.Int64(key, int64(v)), true
	case uint64:
		return uintAttr(key, v), true
	case float32:
		return attribute.Float64(key, float64(v)), true
	case float64:
		return attribute.Float64(key, v), true
	case []string:
		return attribute.StringSlice(key, v), true
	case []bool:
		return attribute.BoolSlice(key, v), true
	case []int:
		out := make([]int64, len(v))
		for i := range v {
			out[i] = int64(v[i])
		}
		return attribute.Int64Slice(key, out), true
	case []int64:
		return attribute.Int64Slice(key, v), true
	case []float64:
		return attribute.Float64Slice(key, v), true
	case []float32:
		out := make([]float64, len(v))
		for i := range v {
			out[i] = float64(v[i])
		}
		return attribute.Float64Slice(key, out), true
	case []any:
		if kv, ok := homogeneousSlice(key, v); ok {
			return kv, true
		}
	}
	b, err := json.Marshal(value)
	if err != nil {
		return attribute.String(key, fmt.Sprintf("%v", value)), true
	}
	return attribute.String(key, string(b)), true
}

func uintAttr(key string, v uint64) attribute.KeyValue {
	if v > uint64(math.MaxInt64) {
		return attribute.String(key, strconv.FormatUint(v, 10))
	}
	return attribute.Int64(key, int64(v))
}

// homogeneousSlice converts a []any whose elements are all strings, all bools,
// all integers or all numbers into a typed OTel slice attribute.
func homogeneousSlice(key string, v []any) (attribute.KeyValue, bool) {
	if len(v) == 0 {
		return attribute.StringSlice(key, []string{}), true
	}
	kvs := make([]attribute.KeyValue, 0, len(v))
	for _, e := range v {
		kv, ok := toAttribute(key, e)
		if !ok {
			return attribute.KeyValue{}, false
		}
		kvs = append(kvs, kv)
	}
	typ := kvs[0].Value.Type()
	for _, kv := range kvs {
		if kv.Value.Type() != typ {
			return attribute.KeyValue{}, false
		}
	}
	switch typ {
	case attribute.STRING:
		out := make([]string, len(kvs))
		for i, kv := range kvs {
			out[i] = kv.Value.AsString()
		}
		return attribute.StringSlice(key, out), true
	case attribute.BOOL:
		out := make([]bool, len(kvs))
		for i, kv := range kvs {
			out[i] = kv.Value.AsBool()
		}
		return attribute.BoolSlice(key, out), true
	case attribute.INT64:
		out := make([]int64, len(kvs))
		for i, kv := range kvs {
			out[i] = kv.Value.AsInt64()
		}
		return attribute.Int64Slice(key, out), true
	case attribute.FLOAT64:
		out := make([]float64, len(kvs))
		for i, kv := range kvs {
			out[i] = kv.Value.AsFloat64()
		}
		return attribute.Float64Slice(key, out), true
	}
	return attribute.KeyValue{}, false
}
