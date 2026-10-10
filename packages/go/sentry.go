package trappsec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxStringLen  = 1024
	maxListItems  = 20
	defaultCloseT = 5 * time.Second
)

var NoDefault = struct{}{}

type AuthContext struct {
	User string
	Role string
}

// TriggerContext is the event emitted to handlers. All keys are always present
// in the JSON form; empty optional values serialize as null (see MarshalJSON).
type TriggerContext struct {
	Timestamp float64      `json:"timestamp"`
	Event     string       `json:"event"`
	Type      string       `json:"type"`
	Reason    string       `json:"reason"`
	Intent    string       `json:"intent"`
	Path      string       `json:"path"`
	Method    string       `json:"method"`
	IP        string       `json:"ip"`
	User      string       `json:"user"`
	Role      string       `json:"role"`
	UserAgent string       `json:"user_agent"`
	Found     []FoundField `json:"found_fields"`
	Metadata  any          `json:"metadata"`
	App       AppInfo      `json:"app"`
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// MarshalJSON emits every key; empty ip/user_agent/intent/reason/user/role,
// nil found_fields and nil metadata become null. It never fails: a metadata
// value that cannot be encoded is replaced by its fmt representation.
func (t TriggerContext) MarshalJSON() ([]byte, error) {
	var found any
	if t.Found != nil {
		found = t.Found
	}
	return json.Marshal(struct {
		Timestamp float64         `json:"timestamp"`
		Event     string          `json:"event"`
		Type      string          `json:"type"`
		Reason    any             `json:"reason"`
		Intent    any             `json:"intent"`
		Path      string          `json:"path"`
		Method    string          `json:"method"`
		IP        any             `json:"ip"`
		User      any             `json:"user"`
		Role      any             `json:"role"`
		UserAgent any             `json:"user_agent"`
		Found     any             `json:"found_fields"`
		Metadata  json.RawMessage `json:"metadata"`
		App       AppInfo         `json:"app"`
	}{
		Timestamp: t.Timestamp, Event: t.Event, Type: t.Type,
		Reason: nullable(t.Reason), Intent: nullable(t.Intent),
		Path: truncate(t.Path, maxStringLen), Method: t.Method,
		IP: nullable(t.IP), User: nullable(t.User), Role: nullable(t.Role),
		UserAgent: nullable(truncate(t.UserAgent, maxStringLen)),
		Found:     found, Metadata: safeMarshal(t.Metadata), App: t.App,
	})
}

// safeMarshal never fails or panics; unencodable values degrade to a string.
func safeMarshal(v any) (out json.RawMessage) {
	defer func() {
		if r := recover(); r != nil {
			out = json.RawMessage(`"<unserializable>"`)
		}
	}()
	if v == nil {
		return json.RawMessage("null")
	}
	b, err := json.Marshal(v)
	if err != nil {
		b, err = json.Marshal(fmt.Sprintf("%v", v))
		if err != nil {
			return json.RawMessage(`"<unserializable>"`)
		}
	}
	return b
}

// truncate shortens s to at most n characters (runes), without a suffix.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

type AppInfo struct {
	Service     string `json:"service"`
	Environment string `json:"environment"`
	Hostname    string `json:"hostname"`
}

type RequestContext struct {
	Path      func(any) string
	UserAgent func(any) string
	Method    func(any) string
	Context   func(any) context.Context
}

type IdentityContext struct {
	IP   func(any) string
	Auth func(any) *AuthContext
}

type Sentry struct {
	logger      *log.Logger
	hostname    string
	service     string
	environment string

	Identity IdentityContext
	Request  RequestContext

	ipOverride       func(any) string
	bodyResolver     func(body any, req any) any
	defaultResponses map[string]ResponseTemplate
	traps            []*TrapBuilder
	watches          []*WatchBuilder
	templates        map[string]ResponseTemplate
	handlers         []EventHandler

	mu sync.RWMutex
}

func NewSentry(service, environment string) *Sentry {
	hostname, _ := os.Hostname()
	s := &Sentry{
		logger:      log.New(os.Stdout, "", 0),
		hostname:    hostname,
		service:     service,
		environment: environment,
		Identity: IdentityContext{
			IP:   nil,
			Auth: nil,
		},
		Request: RequestContext{
			Path:      func(_ any) string { return "" },
			UserAgent: func(_ any) string { return "" },
			Method:    func(_ any) string { return "" },
			Context:   func(_ any) context.Context { return context.Background() },
		},
		defaultResponses: map[string]ResponseTemplate{
			"authenticated": {
				StatusCode: 200,
				Body:       map[string]any{},
				MIMEType:   "application/json",
			},
			"unauthenticated": {
				StatusCode: 401,
				Body:       map[string]any{},
				MIMEType:   "application/json",
			},
		},
		traps:     []*TrapBuilder{},
		watches:   []*WatchBuilder{},
		templates: map[string]ResponseTemplate{},
		handlers:  []EventHandler{},
	}

	s.handlers = append(s.handlers, &LogHandler{logger: s.logger})
	return s
}

// SetBodyResolver registers a framework-specific body resolver. Integration
// packages call this during setup to handle framework-typed body callbacks
// (e.g. func(*gin.Context) any) before core's generic resolver runs.
func (s *Sentry) SetBodyResolver(fn func(body any, req any) any) {
	s.mu.Lock()
	s.bodyResolver = fn
	s.mu.Unlock()
}

func (s *Sentry) Service() string { return s.service }

func (s *Sentry) Environment() string { return s.environment }

func (s *Sentry) Logger() *log.Logger { return s.logger }

func (s *Sentry) DefaultResponses() map[string]ResponseTemplate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return map[string]ResponseTemplate{
		"authenticated":   cloneTemplate(s.defaultResponses["authenticated"]),
		"unauthenticated": cloneTemplate(s.defaultResponses["unauthenticated"]),
	}
}

func (s *Sentry) SetDefaultUnauthenticated(statusCode int, body any, mimeType string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if mimeType == "" {
		mimeType = "application/json"
	}
	s.defaultResponses["unauthenticated"] = ResponseTemplate{StatusCode: statusCode, Body: body, MIMEType: mimeType}
}

func (s *Sentry) SetDefaultAuthenticated(statusCode int, body any, mimeType string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if mimeType == "" {
		mimeType = "application/json"
	}
	s.defaultResponses["authenticated"] = ResponseTemplate{StatusCode: statusCode, Body: body, MIMEType: mimeType}
}

func (s *Sentry) Template(name string, statusCode int, body any, mimeType string) *Sentry {
	s.mu.Lock()
	defer s.mu.Unlock()
	if mimeType == "" {
		mimeType = "application/json"
	}
	s.templates[name] = ResponseTemplate{StatusCode: statusCode, Body: body, MIMEType: mimeType}
	return s
}

func (s *Sentry) Trap(path string) *TrapBuilder {
	builder := newTrapBuilder(s, path)
	s.mu.Lock()
	s.traps = append(s.traps, builder)
	s.mu.Unlock()
	return builder
}

func (s *Sentry) Watch(path string) *WatchBuilder {
	builder := newWatchBuilder(s, path)
	s.mu.Lock()
	s.watches = append(s.watches, builder)
	s.mu.Unlock()
	return builder
}

func (s *Sentry) AddWebhook(url string, opts *WebhookOptions) *Sentry {
	localOpts := &WebhookOptions{}
	if opts != nil {
		*localOpts = *opts
	}
	if localOpts.Service == "" {
		localOpts.Service = s.service
	}
	if localOpts.Environment == "" {
		localOpts.Environment = s.environment
	}
	if localOpts.Logger == nil {
		localOpts.Logger = s.logger
	}

	h, err := NewWebhookHandler(url, localOpts)
	if err != nil {
		s.logger.Printf("failed to initialize webhook handler: %v", err)
		return s
	}
	s.mu.Lock()
	s.handlers = append(s.handlers, h)
	s.mu.Unlock()
	return s
}

func (s *Sentry) AddOTEL() *Sentry {
	s.mu.Lock()
	s.handlers = append(s.handlers, &OTELHandler{})
	s.mu.Unlock()
	return s
}

func (s *Sentry) AddSlack(url string, opts *SlackOptions) *Sentry {
	localOpts := &SlackOptions{}
	if opts != nil {
		*localOpts = *opts
	}
	if localOpts.Logger == nil {
		localOpts.Logger = s.logger
	}
	h, err := NewSlackHandler(url, localOpts)
	if err != nil {
		s.logger.Printf("failed to initialize slack handler: %v", err)
		return s
	}
	s.mu.Lock()
	s.handlers = append(s.handlers, h)
	s.mu.Unlock()
	return s
}

// IdentifyUser registers the identity callback. A panic inside fn is
// recovered and treated as "no user".
func (s *Sentry) IdentifyUser(fn func(any) *AuthContext) *Sentry {
	s.mu.Lock()
	s.Identity.Auth = fn
	s.mu.Unlock()
	return s
}

// OverrideSourceIP registers a source-IP callback that takes precedence over
// the framework's default extractor. A panic inside fn falls back to the
// default extractor's result.
func (s *Sentry) OverrideSourceIP(fn func(any) string) *Sentry {
	s.mu.Lock()
	s.ipOverride = fn
	s.mu.Unlock()
	return s
}

// Close flushes and stops every handler that supports it (webhook, Slack:
// stops heartbeat and worker goroutines, drains the queue). The context
// bounds the flush; if it has no deadline a 5s default is applied.
func (s *Sentry) Close(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultCloseT)
		defer cancel()
	}
	s.mu.RLock()
	handlers := append([]EventHandler(nil), s.handlers...)
	s.mu.RUnlock()

	var errs []error
	for _, h := range handlers {
		switch c := h.(type) {
		case interface{ Close(context.Context) error }:
			if err := c.Close(ctx); err != nil {
				errs = append(errs, err)
			}
		case io.Closer:
			if err := c.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

func (s *Sentry) Traps() []TrapConfig {
	s.mu.RLock()
	builders := append([]*TrapBuilder(nil), s.traps...)
	s.mu.RUnlock()
	out := make([]TrapConfig, 0, len(builders))
	for _, t := range builders {
		out = append(out, t.Build())
	}
	return out
}

func (s *Sentry) Watches() []WatchConfig {
	s.mu.RLock()
	builders := append([]*WatchBuilder(nil), s.watches...)
	s.mu.RUnlock()
	out := make([]WatchConfig, 0, len(builders))
	for _, w := range builders {
		out = append(out, w.Build())
	}
	return out
}

// guard runs fn and recovers from any panic, logging it.
func (s *Sentry) guard(what string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Printf("trappsec: panic in %s: %v", what, r)
		}
	}()
	fn()
}

func (s *Sentry) newEvent(req any, name string) (TriggerContext, extractedIdentity) {
	identity := s.getIdentity(req)
	request := s.getRequest(req)
	ctx := TriggerContext{
		Timestamp: float64(time.Now().UnixNano()) / 1e9,
		Event:     name,
		Type:      "signal",
		Path:      truncate(request.Path, maxStringLen),
		Method:    request.Method,
		UserAgent: truncate(request.UserAgent, maxStringLen),
		IP:        identity.IP,
	}
	if identity.User != "" {
		ctx.Type = "alert"
		ctx.User = identity.User
		ctx.Role = identity.Role
	}
	return ctx, identity
}

func (s *Sentry) Trigger(req any, reason, intent string, metadata any) {
	s.guard("Trigger", func() {
		ctx, _ := s.newEvent(req, "trappsec.rule_hit")
		ctx.Reason = reason
		ctx.Intent = intent
		ctx.Metadata = metadata
		s.emit(ctx, s.getContext(req))
	})
}

// TriggerTrapEvent emits a trap_hit event and returns the response body and config.
// Called by framework integration packages. It never panics: failures in
// callbacks degrade to an empty `{}` body.
func (s *Sentry) TriggerTrapEvent(req any, trap TrapConfig) (payload []byte, cfg ResponseTemplate) {
	cfg = trap.ResponseUnauthenticated
	payload = []byte("{}")
	defer func() {
		if r := recover(); r != nil {
			s.logger.Printf("trappsec: panic in TriggerTrapEvent: %v", r)
			payload = []byte("{}")
		}
	}()

	ctx, identity := s.newEvent(req, "trappsec.trap_hit")
	ctx.Intent = trap.Intent
	if identity.User != "" {
		cfg = trap.ResponseAuthenticated
	}
	s.emit(ctx, s.getContext(req))

	bodyVal := s.resolveDynamicBody(cfg.Body, req)
	payload = normalizePayload(cfg.MIMEType, bodyVal)
	return payload, cfg
}

// TriggerWatchEvent emits a watch_hit event. Called by framework integration packages.
func (s *Sentry) TriggerWatchEvent(req any, found []FoundField) {
	s.guard("TriggerWatchEvent", func() {
		ctx, _ := s.newEvent(req, "trappsec.watch_hit")
		ctx.Found = found
		s.emit(ctx, s.getContext(req))
	})
}

// DetectHoneyFields scans data for fields matching the watch rules and returns
// the sanitized map, any triggered fields, and whether any watched key was present.
// Called by framework integration packages.
//
// The optional source ("query" or "body", default "body") is recorded as the
// found field's type. Every occurrence of a watched key is stripped, including
// case variants when source is "body" (encoding/json and gin bind JSON keys
// case-insensitively). Multi-valued fields are passed as []any / []string: a
// single element is compared as a scalar; more than one is a violation unless
// every element matches. Watched keys are always stripped, even if a callable
// default panics (then the field is treated as having no default).
//
// Value comparison follows values_match: numbers compare numerically
// regardless of Go type (float64, json.Number, ints), and a string matches a
// bool/number whose canonical text equals it ("5", "true").
func (s *Sentry) DetectHoneyFields(data map[string]any, rules map[string]WatchFieldRule, requestObj any, source ...string) (map[string]any, []FoundField, bool) {
	if len(data) == 0 || len(rules) == 0 {
		return data, nil, false
	}
	src := "body"
	if len(source) > 0 && source[0] == "query" {
		src = "query"
	}
	caseInsensitive := src == "body"

	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Rule names sorted for deterministic case-insensitive resolution.
	var ruleNames []string
	if caseInsensitive {
		ruleNames = make([]string, 0, len(rules))
		for n := range rules {
			ruleNames = append(ruleNames, n)
		}
		sort.Strings(ruleNames)
	}

	found := make([]FoundField, 0)
	touched := false
	for _, key := range keys {
		ruleName := key
		rule, ok := rules[key]
		if !ok && caseInsensitive {
			for _, n := range ruleNames {
				if strings.EqualFold(n, key) {
					ruleName, rule, ok = n, rules[n], true
					break
				}
			}
		}
		if !ok {
			continue
		}
		touched = true
		value := data[key]
		// Always strip, regardless of what happens below.
		delete(data, key)

		violation := s.isViolation(value, rule, requestObj)
		if violation {
			found = append(found, FoundField{
				Type:   src,
				Field:  ruleName,
				Value:  SafeValue(value),
				Intent: rule.Intent,
			})
		}
	}
	return data, found, touched
}

// DetectHoneyFieldsAny is DetectHoneyFields for a decoded top-level JSON
// value: an object is inspected, an array has each object element inspected
// (watched keys stripped inside them), anything else is returned untouched.
// It never panics for any input shape.
func (s *Sentry) DetectHoneyFieldsAny(data any, rules map[string]WatchFieldRule, requestObj any, source ...string) (any, []FoundField, bool) {
	switch v := data.(type) {
	case map[string]any:
		m, f, t := s.DetectHoneyFields(v, rules, requestObj, source...)
		return m, f, t
	case []any:
		var all []FoundField
		touched := false
		for _, el := range v {
			if m, ok := el.(map[string]any); ok {
				_, f, t := s.DetectHoneyFields(m, rules, requestObj, source...)
				all = append(all, f...)
				touched = touched || t
			}
		}
		return v, all, touched
	default:
		return data, nil, false
	}
}

func (s *Sentry) isViolation(value any, rule WatchFieldRule, requestObj any) (violation bool) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Printf("trappsec: panic evaluating honey field: %v", r)
			violation = true
		}
	}()
	expected := rule.Default
	if fn, ok := expected.(func(any) any); ok {
		expected = s.callDefault(fn, requestObj)
	}
	if isNoDefault(expected) {
		return true
	}
	if valuesMatch(value, expected) {
		return false
	}
	var elems []any
	switch l := value.(type) {
	case []any:
		elems = l
	case []string:
		elems = make([]any, len(l))
		for i, e := range l {
			elems[i] = e
		}
	default:
		return true
	}
	if len(elems) == 0 {
		return true
	}
	for _, e := range elems {
		if !valuesMatch(e, expected) {
			return true
		}
	}
	return false
}

func (s *Sentry) callDefault(fn func(any) any, req any) (out any) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Printf("trappsec: panic in default callback: %v", r)
			out = NoDefault
		}
	}()
	return fn(req)
}

func isNoDefault(v any) bool {
	_, ok := v.(struct{})
	return ok
}

// numeric kinds -------------------------------------------------------------

type num struct {
	isInt bool
	i     int64
	u     uint64 // only used when big unsigned
	big   bool
	f     float64
}

func toNum(v any) (num, bool) {
	switch t := v.(type) {
	case int:
		return num{isInt: true, i: int64(t), f: float64(t)}, true
	case int8:
		return num{isInt: true, i: int64(t), f: float64(t)}, true
	case int16:
		return num{isInt: true, i: int64(t), f: float64(t)}, true
	case int32:
		return num{isInt: true, i: int64(t), f: float64(t)}, true
	case int64:
		return num{isInt: true, i: t, f: float64(t)}, true
	case uint:
		return uintNum(uint64(t)), true
	case uint8:
		return uintNum(uint64(t)), true
	case uint16:
		return uintNum(uint64(t)), true
	case uint32:
		return uintNum(uint64(t)), true
	case uint64:
		return uintNum(t), true
	case float32:
		return num{f: float64(t)}, true
	case float64:
		return num{f: t}, true
	case json.Number:
		if i, err := strconv.ParseInt(string(t), 10, 64); err == nil {
			return num{isInt: true, i: i, f: float64(i)}, true
		}
		if f, err := strconv.ParseFloat(string(t), 64); err == nil {
			return num{f: f}, true
		}
	}
	return num{}, false
}

func uintNum(u uint64) num {
	if u > math.MaxInt64 {
		return num{u: u, big: true, f: float64(u)}
	}
	return num{isInt: true, i: int64(u), f: float64(u)}
}

func numEqual(a, b num) bool {
	if a.big || b.big {
		return a.big && b.big && a.u == b.u
	}
	if a.isInt && b.isInt {
		return a.i == b.i
	}
	return a.f == b.f
}

// canonical returns the canonical text of a bool/number, for matching
// against string values (form and query values are always strings).
func canonical(v any) (string, bool) {
	if b, ok := v.(bool); ok {
		if b {
			return "true", true
		}
		return "false", true
	}
	n, ok := toNum(v)
	if !ok {
		return "", false
	}
	switch {
	case n.big:
		return strconv.FormatUint(n.u, 10), true
	case n.isInt:
		return strconv.FormatInt(n.i, 10), true
	case math.IsNaN(n.f) || math.IsInf(n.f, 0):
		return strconv.FormatFloat(n.f, 'g', -1, 64), true
	case n.f == math.Trunc(n.f) && math.Abs(n.f) < 1e15:
		return strconv.FormatInt(int64(n.f), 10), true
	}
	return strconv.FormatFloat(n.f, 'f', -1, 64), true
}

// valuesMatch implements C3 values_match(actual, expected).
func valuesMatch(actual, expected any) bool {
	if actual == nil || expected == nil {
		return actual == nil && expected == nil
	}
	_, ab := actual.(bool)
	_, eb := expected.(bool)
	if !ab && !eb {
		if an, ok := toNum(actual); ok {
			if en, ok := toNum(expected); ok {
				return numEqual(an, en)
			}
		}
	}
	if as, ok := actual.(string); ok {
		if es, ok := expected.(string); ok {
			return as == es
		}
		if c, ok := canonical(expected); ok {
			return as == c
		}
	}
	if es, ok := expected.(string); ok {
		if c, ok := canonical(actual); ok {
			return es == c
		}
	}
	switch av := actual.(type) {
	case []any:
		if ev, ok := expected.([]any); ok {
			if len(av) != len(ev) {
				return false
			}
			for i := range av {
				if !valuesMatch(av[i], ev[i]) {
					return false
				}
			}
			return true
		}
	case map[string]any:
		if ev, ok := expected.(map[string]any); ok {
			if len(av) != len(ev) {
				return false
			}
			for k, v := range av {
				e, ok := ev[k]
				if !ok || !valuesMatch(v, e) {
					return false
				}
			}
			return true
		}
	}
	defer func() { _ = recover() }()
	return reflect.DeepEqual(actual, expected)
}

// SafeValue sanitizes a value for inclusion in an event (C3 safe_value):
// nil/bool/numbers pass through; strings are truncated to 1024 chars (plus
// "..."); lists keep their first 20 elements, each sanitized; maps become a
// JSON string truncated to 1024; anything else becomes "<TypeName>".
func SafeValue(v any) any {
	if v == nil {
		return nil
	}
	switch t := v.(type) {
	case bool, json.Number:
		return t
	case string:
		return truncEllipsis(t)
	case []byte:
		return "<bytes>"
	}
	if _, ok := toNum(v); ok {
		return v
	}
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		n := rv.Len()
		if n > maxListItems {
			n = maxListItems
		}
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, SafeValue(rv.Index(i).Interface()))
		}
		return out
	case reflect.Map:
		b, err := json.Marshal(v)
		if err != nil {
			return truncEllipsis(fmt.Sprintf("%v", v))
		}
		return truncEllipsis(string(b))
	}
	t := rv.Type()
	for t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return "<" + t.Name() + ">"
}

func truncEllipsis(s string) string {
	if len(s) <= maxStringLen {
		return s
	}
	r := []rune(s)
	if len(r) <= maxStringLen {
		return s
	}
	return string(r[:maxStringLen]) + "..."
}

type extractedIdentity struct {
	User string
	Role string
	IP   string
}

type extractedRequest struct {
	Path      string
	Method    string
	UserAgent string
}

func (s *Sentry) getIdentity(req any) extractedIdentity {
	s.mu.RLock()
	authFn, ipFn, ipOverride := s.Identity.Auth, s.Identity.IP, s.ipOverride
	s.mu.RUnlock()

	id := extractedIdentity{}
	if authFn != nil {
		s.guard("IdentifyUser", func() {
			if auth := authFn(req); auth != nil {
				id.User = auth.User
				id.Role = auth.Role
			}
		})
	}
	gotIP := false
	if ipOverride != nil {
		s.guard("OverrideSourceIP", func() {
			id.IP = ipOverride(req)
			gotIP = true
		})
	}
	if !gotIP && ipFn != nil {
		s.guard("default IP extractor", func() { id.IP = ipFn(req) })
	}
	return id
}

func (s *Sentry) getRequest(req any) extractedRequest {
	s.mu.RLock()
	r := s.Request
	s.mu.RUnlock()
	out := extractedRequest{}
	call := func(name string, fn func(any) string, dst *string) {
		if fn == nil {
			return
		}
		s.guard(name, func() { *dst = fn(req) })
	}
	call("request path extractor", r.Path, &out.Path)
	call("request method extractor", r.Method, &out.Method)
	call("request user-agent extractor", r.UserAgent, &out.UserAgent)
	return out
}

func (s *Sentry) getContext(req any) (ctx context.Context) {
	ctx = context.Background()
	s.mu.RLock()
	fn := s.Request.Context
	s.mu.RUnlock()
	if fn == nil {
		return ctx
	}
	s.guard("request context extractor", func() {
		if c := fn(req); c != nil {
			ctx = c
		}
	})
	return ctx
}

type contextEventHandler interface {
	EmitWithContext(context.Context, TriggerContext) error
}

// emit dispatches the event to all handlers. Handlers are expected not to
// block (webhook/Slack enqueue to a worker); panics and errors are logged and
// never propagate to the caller.
func (s *Sentry) emit(ctx TriggerContext, reqCtx context.Context) {
	ctx.App = AppInfo{Service: s.service, Environment: s.environment, Hostname: s.hostname}

	s.mu.RLock()
	handlers := append([]EventHandler(nil), s.handlers...)
	s.mu.RUnlock()

	for _, h := range handlers {
		h := h
		s.guard("event handler", func() {
			if ch, ok := h.(contextEventHandler); ok {
				if err := ch.EmitWithContext(reqCtx, ctx); err != nil {
					s.logger.Printf("error invoking handler: %v", err)
				}
				return
			}
			if err := h.Emit(ctx); err != nil {
				s.logger.Printf("error invoking handler: %v", err)
			}
		})
	}
}

func cloneTemplate(t ResponseTemplate) ResponseTemplate {
	out := t
	out.Body = deepCopyValue(t.Body)
	return out
}

func deepCopyValue(v any) any {
	if v == nil {
		return nil
	}

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Map:
		if rv.IsNil() {
			return v
		}
		cp := reflect.MakeMapWithSize(rv.Type(), rv.Len())
		iter := rv.MapRange()
		for iter.Next() {
			val := deepCopyValue(iter.Value().Interface())
			if val == nil {
				cp.SetMapIndex(iter.Key(), reflect.Zero(rv.Type().Elem()))
				continue
			}
			cp.SetMapIndex(iter.Key(), reflect.ValueOf(val))
		}
		return cp.Interface()
	case reflect.Slice:
		if rv.IsNil() {
			return v
		}
		cp := reflect.MakeSlice(rv.Type(), rv.Len(), rv.Len())
		for i := 0; i < rv.Len(); i++ {
			val := deepCopyValue(rv.Index(i).Interface())
			if val == nil {
				cp.Index(i).Set(reflect.Zero(rv.Type().Elem()))
				continue
			}
			cp.Index(i).Set(reflect.ValueOf(val))
		}
		return cp.Interface()
	default:
		return v
	}
}

// normalizePayload encodes a trap response body: []byte and string bodies are
// sent raw regardless of MIME type; everything else is JSON-encoded.
func normalizePayload(_ string, body any) []byte {
	if body == nil {
		body = map[string]any{}
	}
	switch v := body.(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	}
	b, err := json.Marshal(body)
	if err != nil {
		return []byte("{}")
	}
	return b
}

// resolveDynamicBody evaluates callable bodies. A panicking callback is
// logged and replaced by an empty object.
func (s *Sentry) resolveDynamicBody(body any, req any) (out any) {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Printf("trappsec: panic in dynamic response body: %v", r)
			out = map[string]any{}
		}
	}()
	// Framework-specific resolver runs first (e.g. func(*gin.Context) any).
	// If the resolver does not recognise the body type it returns body unchanged,
	// and the generic func(any) any case below handles it.
	// NOTE: never compare the returned value to body — function types are
	// uncomparable in Go and will panic at runtime.
	s.mu.RLock()
	resolver := s.bodyResolver
	s.mu.RUnlock()
	if resolver != nil {
		body = resolver(body, req)
	}
	if fn, ok := body.(func(any) any); ok {
		return fn(req)
	}
	return body
}
