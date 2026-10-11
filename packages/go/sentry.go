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

// maxDepth is how many nested containers values_match compares and SafeValue
// keeps (a top-level list or object is depth 1), so a hostile request body
// cannot exhaust the stack.
const maxDepth = 32

type noDefault struct{}

// NoDefault, as a field's Default, means "any presence is a violation". It is
// a sentinel: only this value counts, no other struct{}.
var NoDefault any = noDefault{}

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

// MarshalJSON emits exactly the documented keys for the event: the common
// keys plus intent (trap_hit), found_fields (watch_hit) or reason, intent and
// metadata (rule_hit); other event names get all of them. Empty optional
// values are null and found_fields is never null on a watch_hit. It never
// fails: a metadata value that cannot be encoded is replaced by its fmt
// representation.
func (t TriggerContext) MarshalJSON() ([]byte, error) {
	m := map[string]any{
		"timestamp":  t.Timestamp,
		"event":      t.Event,
		"type":       t.Type,
		"path":       truncEllipsis(t.Path),
		"method":     t.Method,
		"ip":         nullable(t.IP),
		"user":       nullable(t.User),
		"role":       nullable(t.Role),
		"user_agent": nullable(truncEllipsis(t.UserAgent)),
		"app":        t.App,
	}
	var found any = t.Found // a nil slice encodes as null
	switch t.Event {
	case "trappsec.trap_hit":
		m["intent"] = nullable(t.Intent)
	case "trappsec.watch_hit":
		if t.Found == nil {
			found = []FoundField{}
		}
		m["found_fields"] = found
	case "trappsec.rule_hit":
		m["reason"] = nullable(t.Reason)
		m["intent"] = nullable(t.Intent)
		m["metadata"] = safeMarshal(t.Metadata)
	default:
		m["intent"] = nullable(t.Intent)
		m["reason"] = nullable(t.Reason)
		m["found_fields"] = found
		m["metadata"] = safeMarshal(t.Metadata)
	}
	return json.Marshal(m)
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

	// Identity and Request are assigned by adapters and by the application
	// during setup. Assign the fields directly only before the Sentry serves
	// requests; they are read under mu, and IdentifyUser, which writes under
	// it, is the one setter that is safe to call while serving.
	Identity IdentityContext
	Request  RequestContext

	ipOverride       func(any) string
	bodyResolver     func(body any, req any) any
	defaultResponses map[string]ResponseTemplate
	traps            []*TrapBuilder
	watches          []*WatchBuilder
	templates        map[string]ResponseTemplate
	handlers         []EventHandler

	// trapGen changes whenever a trap's path or methods may have changed;
	// trapIdx is the IsTrap index built for generation trapIdxGen.
	trapGen    uint64
	trapIdx    *trapIndex
	trapIdxGen uint64

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

// setBodyResolver registers a framework-specific body resolver. Integration
// packages call this during setup to handle framework-typed body callbacks
// (e.g. func(*gin.Context) any) before core's generic resolver runs.
func (s *Sentry) setBodyResolver(fn func(body any, req any) any) {
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

// DefaultResponse sets the response for authenticated requests to traps that
// do not call Respond. It takes the same ResponseConfig as Respond: only the
// fields you set change the default, and Template replaces it. Defaults are
// resolved when traps are built, so the order of calls does not matter.
func (s *Sentry) DefaultResponse(cfg ResponseConfig) *Sentry {
	s.setDefault("authenticated", cfg)
	return s
}

// DefaultUnauthenticatedResponse sets the response for unauthenticated
// requests to traps that do not call IfUnauthenticated.
func (s *Sentry) DefaultUnauthenticatedResponse(cfg ResponseConfig) *Sentry {
	s.setDefault("unauthenticated", cfg)
	return s
}

func (s *Sentry) setDefault(key string, cfg ResponseConfig) {
	op := s.responseOp(cfg)
	s.mu.Lock()
	defer s.mu.Unlock()
	t := cloneTemplate(s.defaultResponses[key])
	op(&t)
	if t.MIMEType == "" {
		t.MIMEType = "application/json"
	}
	s.defaultResponses[key] = t
}

// Deprecated: use DefaultUnauthenticatedResponse(ResponseConfig{...}).
func (s *Sentry) SetDefaultUnauthenticated(statusCode int, body any, mimeType string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if mimeType == "" {
		mimeType = "application/json"
	}
	s.defaultResponses["unauthenticated"] = ResponseTemplate{StatusCode: statusCode, Body: body, MIMEType: mimeType}
}

// Deprecated: use DefaultResponse(ResponseConfig{...}).
func (s *Sentry) SetDefaultAuthenticated(statusCode int, body any, mimeType string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if mimeType == "" {
		mimeType = "application/json"
	}
	s.defaultResponses["authenticated"] = ResponseTemplate{StatusCode: statusCode, Body: body, MIMEType: mimeType}
}

// Template registers a named response for Respond / IfUnauthenticated /
// DefaultResponse. The MIME type is optional (default "application/json").
func (s *Sentry) Template(name string, statusCode int, body any, mimeType ...string) *Sentry {
	s.mu.Lock()
	defer s.mu.Unlock()
	mt := ""
	if len(mimeType) > 0 {
		mt = mimeType[0]
	}
	if mt == "" {
		mt = "application/json"
	}
	s.templates[name] = ResponseTemplate{StatusCode: statusCode, Body: body, MIMEType: mt}
	return s
}

func (s *Sentry) Trap(path string) *TrapBuilder {
	builder := newTrapBuilder(s, path)
	s.mu.Lock()
	s.traps = append(s.traps, builder)
	s.trapGen++
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

// IsTrap reports whether req targets a trap (method and path, read with the
// Request extractors the adapter installed). Use it to skip middleware that
// would otherwise reject a trap before it can answer, such as CSRF protection
// (R22): a trap that answers 403 is both disabled and easy to fingerprint.
// Path segments written as :id, {id}, <id>, <int:id> or *rest match one
// segment; a last segment written *rest, {rest...}, {rest:path} or <path:rest>
// matches one or more remaining segments. It never panics.
func (s *Sentry) IsTrap(req any) (is bool) {
	defer func() {
		if recover() != nil {
			is = false
		}
	}()
	r := s.requestFuncs()
	method := strings.ToUpper(r.Method(req))
	path := cleanTrapPath(r.Path(req))
	if method == "" || path == "" {
		return false
	}
	idx := s.trapIndex()
	if idx.exact[path][method] {
		return true
	}
	for _, p := range idx.patterns {
		if p.methods[method] && p.matches(path) {
			return true
		}
	}
	return false
}

// trapIndex is what IsTrap looks up: literal trap paths in a map, and only the
// traps with parameter segments in a list to match.
type trapIndex struct {
	exact    map[string]map[string]bool // path -> method set
	patterns []trapPattern
}

type trapPattern struct {
	methods map[string]bool
	segs    []trapSeg
}

// trapSeg is one cleaned pattern segment (the leading "/" is dropped).
type trapSeg struct {
	lit      string
	param    bool // matches one non-empty segment
	catchAll bool // last segment only: matches one or more segments
}

// trapIndex returns the index for the current traps, rebuilding it only when
// a trap was added or its methods changed since the last call.
func (s *Sentry) trapIndex() *trapIndex {
	s.mu.RLock()
	idx, gen := s.trapIdx, s.trapGen
	fresh := idx != nil && s.trapIdxGen == gen
	if fresh {
		s.mu.RUnlock()
		return idx
	}
	idx = &trapIndex{exact: map[string]map[string]bool{}}
	for _, b := range s.traps {
		path := cleanTrapPath(patternPathOnly(b.path))
		methods := make(map[string]bool, len(b.methods))
		for _, m := range b.methods {
			methods[strings.ToUpper(m)] = true
		}
		if segs, ok := parseTrapSegs(path); ok {
			idx.patterns = append(idx.patterns, trapPattern{methods: methods, segs: segs})
			continue
		}
		if idx.exact[path] == nil {
			idx.exact[path] = map[string]bool{}
		}
		for m := range methods {
			idx.exact[path][m] = true
		}
	}
	s.mu.RUnlock()
	s.mu.Lock()
	if s.trapGen == gen {
		s.trapIdx, s.trapIdxGen = idx, gen
	}
	s.mu.Unlock()
	return idx
}

// parseTrapSegs splits a cleaned pattern path into segments. ok is false when
// no segment is a parameter, i.e. the path is a literal.
func parseTrapSegs(path string) (segs []trapSeg, ok bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	segs = make([]trapSeg, len(parts))
	for i, seg := range parts {
		switch {
		case strings.HasPrefix(seg, ":"), strings.HasPrefix(seg, "*"),
			strings.HasPrefix(seg, "{") && strings.HasSuffix(seg, "}"),
			strings.HasPrefix(seg, "<") && strings.HasSuffix(seg, ">"):
			segs[i].param = true
			segs[i].catchAll = i == len(parts)-1 &&
				(strings.HasPrefix(seg, "*") || strings.HasSuffix(seg, "...}") ||
					strings.HasSuffix(seg, ":path}") || strings.HasPrefix(seg, "<path:"))
			ok = true
		default:
			segs[i].lit = seg
		}
	}
	return segs, ok
}

// matches reports whether the cleaned request path fits the pattern. It walks
// the path in place, without splitting it.
func (p trapPattern) matches(path string) bool {
	rest, more := strings.TrimPrefix(path, "/"), true
	for _, seg := range p.segs {
		if !more {
			return false
		}
		if seg.catchAll {
			return rest != "" && rest[0] != '/' && !strings.Contains(rest, "//")
		}
		part := rest
		if i := strings.IndexByte(rest, '/'); i >= 0 {
			part, rest = rest[:i], rest[i+1:]
		} else {
			more = false
		}
		if seg.param {
			if part == "" {
				return false
			}
		} else if part != seg.lit {
			return false
		}
	}
	return !more
}

func cleanTrapPath(p string) string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if p == "" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if t := strings.TrimRight(p, "/"); t != "" {
		return t
	}
	return "/"
}

// patternPathOnly drops a net/http "METHOD [HOST]" prefix from a pattern.
func patternPathOnly(p string) string {
	if i := strings.IndexByte(p, '/'); i > 0 {
		return p[i:]
	}
	return p
}

// Watches returns the watch configurations, one per path: builders for the
// same path are merged (union of fields, a later rule for the same field wins).
func (s *Sentry) Watches() []WatchConfig {
	s.mu.RLock()
	builders := append([]*WatchBuilder(nil), s.watches...)
	s.mu.RUnlock()
	out := make([]WatchConfig, 0, len(builders))
	at := map[string]int{}
	for _, w := range builders {
		cfg := w.Build()
		i, seen := at[cfg.Path]
		if !seen {
			at[cfg.Path] = len(out)
			out = append(out, cfg)
			continue
		}
		for k, v := range cfg.QueryFields {
			out[i].QueryFields[k] = v
		}
		for k, v := range cfg.BodyFields {
			out[i].BodyFields[k] = v
		}
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
		Path:      truncEllipsis(request.Path),
		Method:    request.Method,
		UserAgent: truncEllipsis(request.UserAgent),
		IP:        identity.IP,
	}
	if identity.User != "" {
		ctx.Type = "alert"
		ctx.User = identity.User
		ctx.Role = identity.Role
	}
	return ctx, identity
}

// Trigger emits a trappsec.rule_hit event from your own logic. Intent and
// Metadata are optional:
//
//	ts.Trigger(c, "Velocity limit exceeded", trappsec.Intent("fraud"), trappsec.Metadata(m))
//
// The positional form Trigger(req, reason, intent, metadata) is still
// accepted. It never panics.
func (s *Sentry) Trigger(req any, reason string, opts ...any) {
	s.guard("Trigger", func() {
		var intent string
		var metadata any
		positional, err := splitOptions(opts, func(o Option) bool {
			switch o.kind {
			case optIntent:
				intent, _ = o.value.(string)
			case optMetadata:
				metadata = o.value
			default:
				return false
			}
			return true
		})
		if err != nil {
			s.logger.Printf("trappsec: Trigger: %v", err)
		}
		if len(positional) > 0 {
			if v, ok := positional[0].(string); ok {
				intent = v
			} else {
				s.logger.Printf("trappsec: Trigger: intent must be a string, got %T", positional[0])
			}
		}
		if len(positional) > 1 {
			metadata = positional[1]
		}
		ctx, _ := s.newEvent(req, "trappsec.rule_hit")
		ctx.Reason = reason
		ctx.Intent = intent
		ctx.Metadata = metadata
		s.emit(ctx, s.getContext(req))
	})
}

// triggerTrapEvent emits a trap_hit event and returns the response body and config.
// Called by framework integration packages. It never panics: failures in
// callbacks degrade to an empty `{}` body.
func (s *Sentry) triggerTrapEvent(req any, trap TrapConfig) (payload []byte, cfg ResponseTemplate) {
	cfg = trap.ResponseUnauthenticated
	payload = []byte("{}")
	defer func() {
		if r := recover(); r != nil {
			s.logger.Printf("trappsec: panic in triggerTrapEvent: %v", r)
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
	payload = normalizePayload(bodyVal)
	return payload, cfg
}

// triggerWatchEvent emits a watch_hit event. Called by framework integration packages.
func (s *Sentry) triggerWatchEvent(req any, found []FoundField) {
	s.guard("triggerWatchEvent", func() {
		ctx, _ := s.newEvent(req, "trappsec.watch_hit")
		ctx.Found = found
		s.emit(ctx, s.getContext(req))
	})
}

// detectHoneyFields scans data for fields matching the watch rules and returns
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
func (s *Sentry) detectHoneyFields(data map[string]any, rules map[string]WatchFieldRule, requestObj any, source ...string) (map[string]any, []FoundField, bool) {
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
				Value:  SafeValue(reportedValue(value)),
				Intent: rule.Intent,
			})
		}
	}
	return data, found, touched
}

// detectHoneyFieldsAny is detectHoneyFields for a decoded top-level JSON
// value: an object is inspected, an array has each object element inspected
// (watched keys stripped inside them), anything else is returned untouched.
// It never panics for any input shape.
func (s *Sentry) detectHoneyFieldsAny(data any, rules map[string]WatchFieldRule, requestObj any, source ...string) (any, []FoundField, bool) {
	switch v := data.(type) {
	case map[string]any:
		return s.detectHoneyFields(v, rules, requestObj, source...)
	case []any:
		var all []FoundField
		touched := false
		for _, el := range v {
			if m, ok := el.(map[string]any); ok {
				_, f, t := s.detectHoneyFields(m, rules, requestObj, source...)
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

// reportedValue returns the value recorded for a violation: a one-element
// list is reported as its element, matching how it is compared.
func reportedValue(v any) any {
	switch l := v.(type) {
	case []any:
		if len(l) == 1 {
			return l[0]
		}
	case []string:
		if len(l) == 1 {
			return l[0]
		}
	}
	return v
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
	_, ok := v.(noDefault)
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
	}
	return esNumber(n.f), true
}

// esNumber formats f like ECMAScript Number::toString, the text JavaScript
// (and so the Node SDK) produces, so canonical matching agrees across SDKs.
func esNumber(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	case f == 0:
		return "0"
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	// Shortest round-trip digits: "d.ddde±XX".
	mant, expText, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	digits := strings.Replace(mant, ".", "", 1)
	e, _ := strconv.Atoi(expText)
	k, n := len(digits), e+1 // value = 0.digits * 10^n
	var text string
	switch {
	case k <= n && n <= 21:
		text = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		text = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		text = "0." + strings.Repeat("0", -n) + digits
	default:
		exp := strconv.Itoa(n - 1)
		if n-1 >= 0 {
			exp = "+" + exp
		}
		if k == 1 {
			text = digits + "e" + exp
		} else {
			text = digits[:1] + "." + digits[1:] + "e" + exp
		}
	}
	return sign + text
}

// valuesMatch implements C3 values_match(actual, expected). Values nested
// deeper than maxDepth containers never match.
func valuesMatch(actual, expected any) bool {
	return valuesMatchAt(actual, expected, 0)
}

// valuesMatchAt compares with depth containers already entered.
func valuesMatchAt(actual, expected any, depth int) bool {
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
			if depth >= maxDepth || len(av) != len(ev) {
				return false
			}
			for i := range av {
				if !valuesMatchAt(av[i], ev[i], depth+1) {
					return false
				}
			}
			return true
		}
	case map[string]any:
		if ev, ok := expected.(map[string]any); ok {
			if depth >= maxDepth || len(av) != len(ev) {
				return false
			}
			for k, v := range av {
				e, ok := ev[k]
				if !ok || !valuesMatchAt(v, e, depth+1) {
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
// JSON string truncated to 1024; anything else becomes "<TypeName>". A list or
// map nested deeper than maxDepth containers is replaced by "<nested>".
func SafeValue(v any) any {
	return safeValueAt(v, 0)
}

// safeValueAt is SafeValue with depth containers already entered.
func safeValueAt(v any, depth int) any {
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
		if depth >= maxDepth {
			return nestedMarker
		}
		n := rv.Len()
		if n > maxListItems {
			n = maxListItems
		}
		out := make([]any, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, safeValueAt(rv.Index(i).Interface(), depth+1))
		}
		return out
	case reflect.Map:
		// Same text as Python and Node: compact, sorted keys, no HTML escaping.
		if depth >= maxDepth {
			return nestedMarker
		}
		clipped := clipDepth(rv, depth)
		b, err := marshalJSON(clipped)
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

const nestedMarker = "<nested>"

// clipDepth returns v (a map) with every list or map nested deeper than
// maxDepth replaced by nestedMarker, ready to marshal. depth is the number of
// containers enclosing v. Other values are returned as they are.
func clipDepth(rv reflect.Value, depth int) any {
	for rv.Kind() == reflect.Interface && !rv.IsNil() {
		rv = rv.Elem()
	}
	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		if (rv.Kind() == reflect.Slice && rv.IsNil()) || rv.Type().Elem().Kind() == reflect.Uint8 {
			return rv.Interface() // null / []byte: marshalled as they are
		}
		if depth >= maxDepth {
			return nestedMarker
		}
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = clipDepth(rv.Index(i), depth+1)
		}
		return out
	case reflect.Map:
		if rv.IsNil() {
			return rv.Interface()
		}
		if depth >= maxDepth {
			return nestedMarker
		}
		anyType := reflect.TypeOf((*any)(nil)).Elem()
		out := reflect.MakeMapWithSize(reflect.MapOf(rv.Type().Key(), anyType), rv.Len())
		for it := rv.MapRange(); it.Next(); {
			val := reflect.Zero(anyType) // SetMapIndex(zero Value) would delete the key
			if c := clipDepth(it.Value(), depth+1); c != nil {
				val = reflect.ValueOf(c)
			}
			out.SetMapIndex(it.Key(), val)
		}
		return out.Interface()
	}
	if !rv.IsValid() || !rv.CanInterface() {
		return nil
	}
	return rv.Interface()
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

// requestFuncs returns the Request extractors as set now.
func (s *Sentry) requestFuncs() RequestContext {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Request
}

func (s *Sentry) getRequest(req any) extractedRequest {
	r := s.requestFuncs()
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
	fn := s.requestFuncs().Context
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
func normalizePayload(body any) []byte {
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
