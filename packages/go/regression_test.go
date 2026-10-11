package trappsec

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
)

func quietLogger() (*log.Logger, *syncBuf) {
	b := &syncBuf{}
	return log.New(b, "", 0), b
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}
func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func alertEvent() TriggerContext {
	return TriggerContext{Event: "trappsec.trap_hit", Type: "alert", Path: "/x", Method: "GET"}
}

func ctxT(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}

// ---- async delivery --------------------------------------------------------

func TestWebhookEmitDoesNotBlockOnSlowServer(t *testing.T) {
	release := make(chan struct{})
	var posts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		atomic.AddInt32(&posts, 1)
	}))
	defer srv.Close()

	s := NewSentry("svc", "test")
	s.AddWebhook(srv.URL, nil)
	s.Request.Path = func(any) string { return "/p" }
	s.IdentifyUser(func(any) *AuthContext { return &AuthContext{User: "u", Role: "r"} })

	start := time.Now()
	for i := 0; i < 20; i++ {
		s.TriggerWatchEvent(nil, []FoundField{{Type: "body", Field: "f"}})
		s.Trigger(nil, "r", "i", nil)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("emit blocked on slow webhook: %v", d)
	}
	close(release)
	ctx, cancel := ctxT(5 * time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := atomic.LoadInt32(&posts); got != 40 {
		t.Fatalf("expected 40 delivered posts after flush, got %d", got)
	}
}

func TestWebhookSignatureFormat(t *testing.T) {
	type got struct {
		ts, sig string
		body    []byte
	}
	ch := make(chan got, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		ch <- got{r.Header.Get("x-trappsec-timestamp"), r.Header.Get("x-trappsec-signature"), b}
	}))
	defer srv.Close()

	h, _ := NewWebhookHandler(srv.URL, &WebhookOptions{Secret: "s3cret"})
	_ = h.Emit(alertEvent())
	g := <-ch
	flush(t, h)

	if _, err := strconv.ParseInt(g.ts, 10, 64); err != nil {
		t.Fatalf("timestamp must be integer seconds, got %q", g.ts)
	}
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write([]byte(g.ts + "."))
	mac.Write(g.body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if g.sig != want {
		t.Fatalf("signature mismatch: got %q want %q", g.sig, want)
	}
}

func TestWebhookNoSecretNoSignatureHeaders(t *testing.T) {
	ch := make(chan http.Header, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { ch <- r.Header }))
	defer srv.Close()
	h, _ := NewWebhookHandler(srv.URL, nil)
	_ = h.Emit(alertEvent())
	hd := <-ch
	flush(t, h)
	if hd.Get("x-trappsec-signature") != "" || hd.Get("x-trappsec-timestamp") != "" {
		t.Fatalf("unexpected signing headers: %v", hd)
	}
}

func TestWebhookHeartbeatSignedAndStoppedByClose(t *testing.T) {
	var beats int32
	var unsigned int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if strings.Contains(string(b), "trappsec.heartbeat") {
			atomic.AddInt32(&beats, 1)
			if !strings.HasPrefix(r.Header.Get("x-trappsec-signature"), "sha256=") {
				atomic.AddInt32(&unsigned, 1)
			}
		}
	}))
	defer srv.Close()
	h, _ := NewWebhookHandler(srv.URL, &WebhookOptions{Secret: "k", HeartbeatInterval: 1})
	deadline := time.Now().Add(4 * time.Second)
	for atomic.LoadInt32(&beats) == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	flush(t, h)
	n := atomic.LoadInt32(&beats)
	if n == 0 {
		t.Fatal("no heartbeat received")
	}
	if atomic.LoadInt32(&unsigned) != 0 {
		t.Fatal("heartbeat not signed")
	}
	time.Sleep(1300 * time.Millisecond)
	if atomic.LoadInt32(&beats) != n {
		t.Fatal("heartbeat kept running after Close")
	}
	select {
	case <-h.hbDone:
	default:
		t.Fatal("heartbeat goroutine did not exit")
	}
}

func TestWebhookCloseIdempotentAndEmitAfterCloseSafe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	h, _ := NewWebhookHandler(srv.URL, nil)
	flush(t, h)
	flush(t, h)
	if err := h.Emit(alertEvent()); err != nil {
		t.Fatal(err)
	}
}

func TestWebhookCloseTimeoutAbortsInFlight(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	h, _ := NewWebhookHandler(srv.URL, nil)
	_ = h.Emit(alertEvent())
	ctx, cancel := ctxT(100 * time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := h.Close(ctx); err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("Close did not honor its deadline")
	}
}

func TestWebhookRetriesAtMostTwiceThenLogs(t *testing.T) {
	var posts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&posts, 1)
		w.WriteHeader(500)
	}))
	defer srv.Close()
	lg, buf := quietLogger()
	h, _ := NewWebhookHandler(srv.URL, &WebhookOptions{Logger: lg})
	h.backoff = []time.Duration{time.Millisecond, time.Millisecond}
	_ = h.Emit(alertEvent())
	flush(t, h)
	if got := atomic.LoadInt32(&posts); got != 3 {
		t.Fatalf("expected 1 attempt + 2 retries = 3, got %d", got)
	}
	if !strings.Contains(buf.String(), "status 500") {
		t.Fatalf("non-2xx not logged: %q", buf.String())
	}
}

func TestWebhookRetrySucceeds(t *testing.T) {
	var posts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&posts, 1) == 1 {
			w.WriteHeader(503)
		}
	}))
	defer srv.Close()
	h, _ := NewWebhookHandler(srv.URL, nil)
	h.backoff = []time.Duration{time.Millisecond}
	_ = h.Emit(alertEvent())
	flush(t, h)
	if got := atomic.LoadInt32(&posts); got != 2 {
		t.Fatalf("expected 2 posts, got %d", got)
	}
}

func TestWebhookClientErrorNotRetried(t *testing.T) {
	var posts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&posts, 1)
		w.WriteHeader(400)
	}))
	defer srv.Close()
	h, _ := NewWebhookHandler(srv.URL, nil)
	_ = h.Emit(alertEvent())
	flush(t, h)
	if atomic.LoadInt32(&posts) != 1 {
		t.Fatal("4xx must not be retried")
	}
}

func TestWebhookQueueFullDropsWithRateLimitedLog(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer srv.Close()
	lg, buf := quietLogger()
	h, _ := NewWebhookHandler(srv.URL, &WebhookOptions{Logger: lg})
	start := time.Now()
	for i := 0; i < 2500; i++ {
		_ = h.Emit(alertEvent())
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("Emit blocked when queue full")
	}
	if n := strings.Count(buf.String(), "queue full"); n != 1 {
		t.Fatalf("expected exactly one rate-limited warning, got %d", n)
	}
	close(release)
	flush(t, h)
}

func TestWebhookTemplatePanicDropsEventWithoutSendingRaw(t *testing.T) {
	var posts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { atomic.AddInt32(&posts, 1) }))
	defer srv.Close()
	lg, _ := quietLogger()
	h, _ := NewWebhookHandler(srv.URL, &WebhookOptions{
		Logger:   lg,
		Template: func(TriggerContext) any { panic("boom") },
	})
	if err := h.Emit(alertEvent()); err != nil {
		t.Fatal(err)
	}
	flush(t, h)
	if atomic.LoadInt32(&posts) != 0 {
		t.Fatal("raw event must not be sent when template panics")
	}
}

func TestWebhookResponseBodyDrainedConnectionReused(t *testing.T) {
	var newConns int32
	var posts int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&posts, 1)
		_, _ = w.Write([]byte(strings.Repeat("x", 4096)))
	}))
	srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			atomic.AddInt32(&newConns, 1)
		}
	}
	srv.Start()
	defer srv.Close()
	h, _ := NewWebhookHandler(srv.URL, nil)
	for i := 0; i < 5; i++ {
		_ = h.Emit(alertEvent())
		time.Sleep(30 * time.Millisecond)
	}
	flush(t, h)
	if atomic.LoadInt32(&posts) != 5 || atomic.LoadInt32(&newConns) != 1 {
		t.Fatalf("expected 5 posts over 1 connection, got %d posts / %d conns", posts, newConns)
	}
}

// ---- sentry-level panic safety --------------------------------------------

func TestPanicInIdentifyUserFallsBackToSignal(t *testing.T) {
	s := NewSentry("svc", "test")
	capture := &captureHandler{}
	s.handlers = []EventHandler{capture}
	s.IdentifyUser(func(any) *AuthContext { panic("auth exploded") })

	s.TriggerWatchEvent(nil, nil)
	if len(capture.events) != 1 || capture.events[0].Type != "signal" || capture.events[0].User != "" {
		t.Fatalf("unexpected events: %+v", capture.events)
	}
}

func TestPanicInOverrideSourceIPFallsBackToDefault(t *testing.T) {
	s := NewSentry("svc", "test")
	capture := &captureHandler{}
	s.handlers = []EventHandler{capture}
	s.Identity.IP = func(any) string { return "9.9.9.9" }
	s.OverrideSourceIP(func(any) string { panic("ip exploded") })
	s.TriggerWatchEvent(nil, nil)
	if capture.events[0].IP != "9.9.9.9" {
		t.Fatalf("expected default IP fallback, got %q", capture.events[0].IP)
	}
	s.OverrideSourceIP(func(any) string { return "7.7.7.7" })
	s.TriggerWatchEvent(nil, nil)
	if capture.events[1].IP != "7.7.7.7" {
		t.Fatalf("override must win, got %q", capture.events[1].IP)
	}
}

type panicHandler struct{}

func (panicHandler) Emit(TriggerContext) error { panic("handler exploded") }

func TestPanicInHandlerDoesNotPropagateOrStarveOthers(t *testing.T) {
	s := NewSentry("svc", "test")
	capture := &captureHandler{}
	s.handlers = []EventHandler{panicHandler{}, capture}
	s.TriggerWatchEvent(nil, nil)
	if len(capture.events) != 1 {
		t.Fatal("later handlers must still run")
	}
}

func TestPanicInRequestExtractorsAndDynamicBody(t *testing.T) {
	s := NewSentry("svc", "test")
	capture := &captureHandler{}
	s.handlers = []EventHandler{capture}
	s.Request.Path = func(any) string { panic("x") }
	s.Request.Context = func(any) context.Context { panic("x") }

	trap := TrapConfig{
		ResponseUnauthenticated: ResponseTemplate{StatusCode: 401, MIMEType: "application/json",
			Body: func(any) any { panic("body exploded") }},
	}
	body, cfg := s.TriggerTrapEvent(nil, trap)
	if string(body) != "{}" || cfg.StatusCode != 401 {
		t.Fatalf("expected {} fallback, got %q %d", body, cfg.StatusCode)
	}
	if len(capture.events) != 1 {
		t.Fatal("event should still be emitted")
	}
}

func TestPanicInDefaultCallbackTreatedAsNoDefaultAndStillStrips(t *testing.T) {
	s := NewSentry("svc", "test")
	data := map[string]any{"role": "user", "keep": 1}
	rules := map[string]WatchFieldRule{"role": {Default: func(any) any { panic("x") }, Intent: "i"}}
	out, found, touched := s.DetectHoneyFields(data, rules, nil)
	if !touched || len(found) != 1 {
		t.Fatalf("expected violation, got %+v touched=%v", found, touched)
	}
	if _, ok := out["role"]; ok {
		t.Fatal("must strip even when callable default panics")
	}
	if out["keep"] != 1 {
		t.Fatal("unrelated field lost")
	}
}

func TestTrapBodyStringSentRawRegardlessOfMime(t *testing.T) {
	if got := string(normalizePayload("application/json", "plain")); got != "plain" {
		t.Fatalf("got %q", got)
	}
	if got := string(normalizePayload("text/html", map[string]any{"a": 1})); got != `{"a":1}` {
		t.Fatalf("got %q", got)
	}
	if got := string(normalizePayload("application/json", make(chan int))); got != "{}" {
		t.Fatalf("unmarshalable body should degrade to {}, got %q", got)
	}
}

// ---- value matching --------------------------------------------------------

func TestValuesMatchTable(t *testing.T) {
	cases := []struct {
		a, b any
		want bool
	}{
		{float64(0), 0, true},
		{json.Number("0"), 0, true},
		{json.Number("5.0"), 5, true},
		{json.Number("1.5"), 1.5, true},
		{int64(3), uint8(3), true},
		{float64(3), float64(3.1), false},
		{"5", 5, true},
		{"5", float64(5), true},
		{"5.0", float64(5), false},
		{"1.5", 1.5, true},
		{"true", true, true},
		{"false", true, false},
		{"True", true, false},
		{true, true, true},
		{false, 0, false},
		{true, 1, false},
		{"1", true, false},
		{"abc", "abc", true},
		{"abc", "ABC", false},
		{nil, nil, true},
		{nil, 0, false},
		{"", 0, false},
		{[]any{1.0, "a"}, []any{1, "a"}, true},
		{map[string]any{"a": 1.0}, map[string]any{"a": 1}, true},
		{json.Number("12345678901234567890"), uint64(12345678901234567890), false},
	}
	for i, c := range cases {
		if got := valuesMatch(c.a, c.b); got != c.want {
			t.Errorf("case %d valuesMatch(%#v, %#v) = %v, want %v", i, c.a, c.b, got, c.want)
		}
	}
}

func detectH(rules map[string]WatchFieldRule, data map[string]any, src ...string) (map[string]any, []FoundField, bool) {
	return NewSentry("svc", "t").DetectHoneyFields(data, rules, nil, src...)
}

func TestDetectBenignJSONZeroNoLongerAlerts(t *testing.T) {
	// JSON decoding yields float64(0); the rule default is int 0.
	_, found, touched := detectH(map[string]WatchFieldRule{"credits": {Default: 0}}, map[string]any{"credits": float64(0)})
	if !touched || len(found) != 0 {
		t.Fatalf("benign 0 must not alert: %+v", found)
	}
	_, found, _ = detectH(map[string]WatchFieldRule{"credits": {Default: 0}}, map[string]any{"credits": json.Number("0")})
	if len(found) != 0 {
		t.Fatal("json.Number 0 must match")
	}
	_, found, _ = detectH(map[string]WatchFieldRule{"credits": {Default: 0}}, map[string]any{"credits": float64(100)})
	if len(found) != 1 {
		t.Fatal("100 must alert")
	}
}

func TestDetectFormStringsMatchBoolAndNumberDefaults(t *testing.T) {
	rules := map[string]WatchFieldRule{
		"is_admin": {Default: false}, "credits": {Default: 0}, "ratio": {Default: 1.5},
	}
	_, found, _ := detectH(rules, map[string]any{"is_admin": "false", "credits": "0", "ratio": "1.5"}, "query")
	if len(found) != 0 {
		t.Fatalf("string forms of defaults must match: %+v", found)
	}
	_, found, _ = detectH(rules, map[string]any{"is_admin": "true"}, "query")
	if len(found) != 1 || found[0].Type != "query" {
		t.Fatalf("expected query violation, got %+v", found)
	}
}

func TestDetectSourceTypeDefaultsToBody(t *testing.T) {
	_, found, _ := detectH(map[string]WatchFieldRule{"a": {Default: NoDefault}}, map[string]any{"a": "x"})
	if found[0].Type != "body" {
		t.Fatalf("got %q", found[0].Type)
	}
}

func TestDetectCaseInsensitiveJSONKeys(t *testing.T) {
	rules := map[string]WatchFieldRule{"is_admin": {Default: false, Intent: "priv"}}
	out, found, touched := detectH(rules, map[string]any{"IS_ADMIN": true, "Is_Admin": false, "is_admin": true, "ok": 1})
	if !touched {
		t.Fatal("touched expected")
	}
	if len(out) != 1 || out["ok"] != 1 {
		t.Fatalf("every case variant must be stripped, got %+v", out)
	}
	if len(found) != 2 {
		t.Fatalf("two violating variants expected, got %+v", found)
	}
	for _, f := range found {
		if f.Field != "is_admin" {
			t.Fatalf("field should be canonical rule name, got %q", f.Field)
		}
	}
}

func TestDetectQueryKeysStayCaseSensitive(t *testing.T) {
	rules := map[string]WatchFieldRule{"role": {Default: NoDefault}}
	out, _, touched := detectH(rules, map[string]any{"ROLE": "x"}, "query")
	if touched || out["ROLE"] != "x" {
		t.Fatal("query matching is exact")
	}
}

func TestDetectMultiValued(t *testing.T) {
	rules := map[string]WatchFieldRule{"role": {Default: "user"}}
	cases := []struct {
		name  string
		val   any
		viol  bool
		extra bool
	}{
		{"single element equals scalar", []any{"user"}, false, false},
		{"single element mismatch", []any{"admin"}, true, false},
		{"all match", []any{"user", "user"}, false, false},
		{"one bad", []any{"user", "admin"}, true, false},
		{"string slice bad", []string{"user", "admin"}, true, false},
		{"empty", []any{}, true, false},
	}
	for _, c := range cases {
		data := map[string]any{"role": c.val, "tags": []any{"a", "b"}}
		out, found, touched := detectH(rules, data, "query")
		if !touched || (len(found) == 1) != c.viol {
			t.Errorf("%s: violation=%v found=%+v", c.name, c.viol, found)
		}
		if _, ok := out["role"]; ok {
			t.Errorf("%s: not stripped", c.name)
		}
		if tags, _ := out["tags"].([]any); len(tags) != 2 {
			t.Errorf("%s: non-watched multi-valued field damaged: %+v", c.name, out["tags"])
		}
	}
}

func TestDetectDoesNotInventMatchesForUnwatchedKeys(t *testing.T) {
	_, found, touched := detectH(map[string]WatchFieldRule{"a": {Default: 1}}, map[string]any{"constructor": 1, "__proto__": 1})
	if touched || len(found) != 0 {
		t.Fatal("no match expected")
	}
}

func TestDetectRecordedValueIsSanitized(t *testing.T) {
	rules := map[string]WatchFieldRule{"v": {Default: NoDefault}}
	long := strings.Repeat("a", 5000)
	_, found, _ := detectH(rules, map[string]any{"v": long})
	if s := found[0].Value.(string); len(s) != 1027 || !strings.HasSuffix(s, "...") {
		t.Fatalf("string not truncated: %d", len(s))
	}
	big := make([]any, 50)
	for i := range big {
		big[i] = i
	}
	_, found, _ = detectH(rules, map[string]any{"v": big})
	if l := found[0].Value.([]any); len(l) != 20 {
		t.Fatalf("list not capped: %d", len(l))
	}
	_, found, _ = detectH(rules, map[string]any{"v": map[string]any{"a": 1}})
	if found[0].Value != `{"a":1}` {
		t.Fatalf("map should be JSON string: %#v", found[0].Value)
	}
	type upload struct{ Name string }
	if got := SafeValue(&upload{}); got != "<upload>" {
		t.Fatalf("got %#v", got)
	}
	if SafeValue(nil) != nil || SafeValue(true) != true || SafeValue(3) != 3 {
		t.Fatal("scalars must pass through")
	}
}

func TestDetectHoneyFieldsAnyShapes(t *testing.T) {
	s := NewSentry("svc", "t")
	rules := map[string]WatchFieldRule{"role": {Default: "user"}}
	arr := []any{map[string]any{"role": "admin", "n": 1}, "str", 3.0, nil, map[string]any{"role": "user"}}
	out, found, touched := s.DetectHoneyFieldsAny(arr, rules, nil)
	if !touched || len(found) != 1 {
		t.Fatalf("expected one violation in array: %+v", found)
	}
	for _, el := range out.([]any) {
		if m, ok := el.(map[string]any); ok {
			if _, ok := m["role"]; ok {
				t.Fatal("not stripped inside array element")
			}
		}
	}
	for _, v := range []any{"s", 1.0, nil, true, []any{}, map[string]any{}} {
		if _, _, touched := s.DetectHoneyFieldsAny(v, rules, nil); touched {
			t.Fatalf("shape %#v should be skipped", v)
		}
	}
}

// ---- events ---------------------------------------------------------------

func TestEventJSONHasNullForEmptyFields(t *testing.T) {
	b, err := json.Marshal(TriggerContext{Event: "trappsec.rule_hit", Type: "signal", Path: "/p", Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ip", "user_agent", "intent", "user", "role", "reason", "metadata"} {
		v, ok := m[k]
		if !ok || v != nil {
			t.Errorf("key %q must be present and null, got %v (present=%v)", k, v, ok)
		}
	}
	b, _ = json.Marshal(TriggerContext{Event: "trappsec.watch_hit"})
	m = nil
	_ = json.Unmarshal(b, &m)
	if f, ok := m["found_fields"].([]any); !ok || len(f) != 0 {
		t.Errorf("watch_hit found_fields must be an empty array, got %#v", m["found_fields"])
	}
}

func TestEventJSONNeverFailsAndTruncates(t *testing.T) {
	ev := TriggerContext{Path: strings.Repeat("p", 3000), UserAgent: strings.Repeat("u", 3000),
		Metadata: make(chan int)}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("marshal must not fail: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if m["path"] != strings.Repeat("p", 1024)+"..." || m["user_agent"] != strings.Repeat("u", 1024)+"..." {
		t.Fatal("path/user_agent not truncated to 1024 + \"...\"")
	}
}

func TestSentryTruncatesPathAndUserAgentInEvents(t *testing.T) {
	s := NewSentry("svc", "t")
	c := &captureHandler{}
	s.handlers = []EventHandler{c}
	s.Request.Path = func(any) string { return strings.Repeat("a", 5000) }
	s.Request.UserAgent = func(any) string { return strings.Repeat("b", 5000) }
	s.Trigger(nil, "r", "i", nil)
	if c.events[0].Path != strings.Repeat("a", 1024)+"..." || c.events[0].UserAgent != strings.Repeat("b", 1024)+"..." {
		t.Fatal("not truncated to 1024 + \"...\"")
	}
}

// ---- builders --------------------------------------------------------------

func TestTrapDefaultsResolvedAtBuildNotAtTrapCall(t *testing.T) {
	s := NewSentry("svc", "t")
	tb := s.Trap("/a")
	s.SetDefaultUnauthenticated(403, map[string]any{"e": "no"}, "")
	s.SetDefaultAuthenticated(202, map[string]any{"ok": 1}, "text/plain")
	cfg := s.Traps()[0]
	if cfg.ResponseUnauthenticated.StatusCode != 403 || cfg.ResponseAuthenticated.StatusCode != 202 {
		t.Fatalf("defaults set after Trap() ignored: %+v", cfg)
	}
	if cfg.ResponseUnauthenticated.MIMEType != "application/json" {
		t.Fatalf("empty mime must default to json: %q", cfg.ResponseUnauthenticated.MIMEType)
	}
	_ = tb
}

func TestRespondEmptyMimeKeepsDefaultAndHonorsFalsyBodies(t *testing.T) {
	s := NewSentry("svc", "t")
	cfg := s.Trap("/a").Respond(ResponseConfig{Status: 200, Body: ""}).
		IfUnauthenticated(ResponseConfig{Body: map[string]any{}}).Build()
	if cfg.ResponseAuthenticated.MIMEType != "application/json" || cfg.ResponseAuthenticated.Body != "" {
		t.Fatalf("got %+v", cfg.ResponseAuthenticated)
	}
	if m, ok := cfg.ResponseUnauthenticated.Body.(map[string]any); !ok || len(m) != 0 {
		t.Fatalf("empty body not honored: %+v", cfg.ResponseUnauthenticated)
	}
	cfg = s.Trap("/b").Respond(ResponseConfig{Body: 0}).Build()
	if cfg.ResponseAuthenticated.Body != 0 {
		t.Fatalf("zero body must be honored, got %#v", cfg.ResponseAuthenticated.Body)
	}
	cfg = s.Trap("/c").Respond(ResponseConfig{Body: false}).Build()
	if cfg.ResponseAuthenticated.Body != false {
		t.Fatal("false body must be honored")
	}
}

func TestMissingTemplatePanicsWithClearMessage(t *testing.T) {
	s := NewSentry("svc", "t")
	defer func() {
		r := recover()
		msg, _ := r.(string)
		if !strings.Contains(msg, `"nope"`) || !strings.Contains(msg, "Sentry.Template") {
			t.Fatalf("unclear panic: %v", r)
		}
	}()
	s.Trap("/a").Respond(ResponseConfig{Template: "nope"})
	t.Fatal("expected panic")
}

func TestTemplateAppliedThenOverridden(t *testing.T) {
	s := NewSentry("svc", "t")
	s.Template("gone", 410, map[string]any{"e": 1}, "")
	cfg := s.Trap("/a").Respond(ResponseConfig{Template: "gone"}).Respond(ResponseConfig{Status: 418}).Build()
	if cfg.ResponseAuthenticated.StatusCode != 418 || cfg.ResponseAuthenticated.MIMEType != "application/json" {
		t.Fatalf("%+v", cfg.ResponseAuthenticated)
	}
}

func TestBuiltConfigIsSnapshot(t *testing.T) {
	s := NewSentry("svc", "t")
	w := s.Watch("/w").Body("a", 1, "i")
	cfg := w.Build()
	w.Body("b", 2, "i")
	if _, ok := cfg.BodyFields["b"]; ok {
		t.Fatal("Build must return a snapshot")
	}
}

// ---- slack / otel ----------------------------------------------------------

func TestSlackEscapesRequestDerivedValuesAndSetsText(t *testing.T) {
	p := buildSlackPayload(TriggerContext{
		Event: "trappsec.trap_hit", Type: "alert", Timestamp: 1712011200,
		Path: "/a?x=<!channel>&y=1", Method: "GET", UserAgent: "<https://evil|click>",
		User: "<@U1>&co", Role: "r>",
		Intent: "<!here>", Reason: "a&b",
		App: AppInfo{Service: "s<", Environment: "e", Hostname: "h"},
	}).(map[string]any)
	b, _ := json.Marshal(p)
	raw := string(b)
	for _, bad := range []string{"<!channel>", "<!here>", "<@U1>", "<https://evil"} {
		// json.Marshal escapes < as <; look at decoded text instead.
		_ = bad
	}
	var dec map[string]any
	_ = json.Unmarshal([]byte(raw), &dec)
	flat := flattenStrings(dec)
	for _, bad := range []string{"<!channel>", "<!here>", "<@U1>", "<https://evil"} {
		if strings.Contains(strings.ReplaceAll(flat, "<!date^", ""), bad) {
			t.Errorf("unescaped %q in payload: %s", bad, flat)
		}
	}
	if !strings.Contains(flat, "&lt;!channel&gt;") || !strings.Contains(flat, "a&amp;b") {
		t.Errorf("expected escaped output, got %s", flat)
	}
	if txt, _ := dec["text"].(string); strings.TrimSpace(txt) == "" || strings.Contains(txt, "<") {
		t.Errorf("text fallback must be non-empty and escaped: %q", txt)
	}
}

func flattenStrings(v any) string {
	switch t := v.(type) {
	case string:
		return t + "\n"
	case []any:
		var sb strings.Builder
		for _, e := range t {
			sb.WriteString(flattenStrings(e))
		}
		return sb.String()
	case map[string]any:
		var sb strings.Builder
		for _, e := range t {
			sb.WriteString(flattenStrings(e))
		}
		return sb.String()
	}
	return ""
}

func TestSlackTextFallbackForAllEventTypes(t *testing.T) {
	for _, ev := range []string{"trappsec.watch_hit", "trappsec.trap_hit", "trappsec.rule_hit", ""} {
		p := buildSlackPayload(TriggerContext{Event: ev, Type: "signal"}).(map[string]any)
		if p["text"].(string) == "" {
			t.Errorf("empty text for %q", ev)
		}
	}
}

func TestToAttributeCoercion(t *testing.T) {
	if _, ok := toAttribute("k", nil); ok {
		t.Fatal("nil must be dropped")
	}
	cases := []struct {
		in   any
		want attribute.Type
	}{
		{"s", attribute.STRING}, {true, attribute.BOOL}, {3, attribute.INT64},
		{2.5, attribute.FLOAT64}, {json.Number("7"), attribute.INT64},
		{json.Number("7.5"), attribute.FLOAT64},
		{[]any{"a", "b"}, attribute.STRINGSLICE},
		{[]any{1, 2}, attribute.INT64SLICE},
		{[]any{true}, attribute.BOOLSLICE},
		{[]any{"a", 1}, attribute.STRING},
		{map[string]any{"a": 1}, attribute.STRING},
		{struct{ A int }{1}, attribute.STRING},
		{uint64(1 << 63), attribute.STRING},
	}
	for i, c := range cases {
		kv, ok := toAttribute("k", c.in)
		if !ok || kv.Value.Type() != c.want {
			t.Errorf("case %d (%#v): got %v ok=%v want %v", i, c.in, kv.Value.Type(), ok, c.want)
		}
	}
}

// ---- concurrency -----------------------------------------------------------

func TestConcurrentConfigAndEmitRace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	s := NewSentry("svc", "t")
	s.AddWebhook(srv.URL, &WebhookOptions{AlertsOnly: boolPtr(false)})
	lg, _ := quietLogger()
	s.logger = lg

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				switch (i + j) % 6 {
				case 0:
					s.Trap("/t").Respond(ResponseConfig{Status: 200})
				case 1:
					s.Watch("/w").Body("a", 1, "i")
				case 2:
					_ = s.Traps()
					_ = s.Watches()
				case 3:
					s.SetDefaultAuthenticated(200, map[string]any{}, "")
					s.IdentifyUser(func(any) *AuthContext { return &AuthContext{User: "u"} })
					s.OverrideSourceIP(func(any) string { return "1.1.1.1" })
				case 4:
					s.Trigger(nil, "r", "i", nil)
					s.TriggerWatchEvent(nil, nil)
				case 5:
					_ = s.DefaultResponses()
					s.Template("x", 200, nil, "")
				}
			}
		}(i)
	}
	wg.Wait()
	ctx, cancel := ctxT(5 * time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSentryCloseStopsAllWebhookAndSlackHandlers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	s := NewSentry("svc", "t")
	s.AddWebhook(srv.URL, &WebhookOptions{HeartbeatInterval: 1})
	s.AddSlack(srv.URL, nil)
	ctx, cancel := ctxT(5 * time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	for _, h := range s.handlers {
		switch v := h.(type) {
		case *WebhookHandler:
			<-v.workerDone
			<-v.hbDone
		case *SlackHandler:
			<-v.webhook.workerDone
		}
	}
	if err := s.Close(ctx); err != nil {
		t.Fatalf("second close: %v", err)
	}
}

func TestIsTrapMatchesMethodAndPathAndNeverPanics(t *testing.T) {
	s := NewSentry("svc", "t")
	s.Trap("/admin/backup").Methods("GET", "POST")
	s.Trap("/api/v1/users/:id").Methods("DELETE")
	s.Trap("/files/{name}").Methods("GET")
	type r struct{ m, p string }
	s.Request.Method = func(req any) string { return req.(r).m }
	s.Request.Path = func(req any) string { return req.(r).p }
	cases := []struct {
		req  r
		want bool
	}{
		{r{"POST", "/admin/backup"}, true},
		{r{"post", "/admin/backup/?x=1"}, true},
		{r{"PUT", "/admin/backup"}, false},
		{r{"DELETE", "/api/v1/users/7"}, true},
		{r{"DELETE", "/api/v1/users/7/x"}, false},
		{r{"DELETE", "/api/v1/users/"}, false},
		{r{"GET", "/files/a.txt"}, true},
		{r{"GET", "/other"}, false},
	}
	for _, c := range cases {
		if got := s.IsTrap(c.req); got != c.want {
			t.Errorf("IsTrap(%v) = %v, want %v", c.req, got, c.want)
		}
	}
	s.Request.Path = func(any) string { panic("boom") }
	if s.IsTrap(r{"GET", "/admin/backup"}) {
		t.Fatal("a panicking extractor must yield false")
	}
}
