package trappsec

import (
	"fmt"
	"strings"
)

type ResponseTemplate struct {
	StatusCode int
	Body       any
	MIMEType   string
	// Headers are extra response headers. A Content-Type header replaces
	// MIMEType; Content-Length and Transfer-Encoding are ignored.
	Headers map[string]string
}

type ResponseConfig struct {
	Status   int
	Body     any
	MIMEType string
	Template string
	// Headers replaces the response's headers when non-nil (see
	// ResponseTemplate.Headers).
	Headers map[string]string
}

// TrapRequest is what a TrapResponseHook knows about a trap hit besides the
// request itself.
type TrapRequest struct {
	Authenticated bool
	User          string
	Role          string
}

// TrapResponse overrides parts of a trap's static response. Zero fields keep
// the static value: Status 0, Body nil and MIMEType "". Headers are merged
// into the static headers (names compare case-insensitively).
type TrapResponse struct {
	Status   int
	Body     any
	MIMEType string
	Headers  map[string]string
}

// TrapResponseHook picks a trap's response per request. req is what the
// adapter passes to IdentifyUser (*http.Request, *gin.Context, *echo.Context).
// Return nil to send the static response for the auth state. A panic, or an
// invalid status or header, also sends the static response.
type TrapResponseHook func(req any, ctx TrapRequest) *TrapResponse

type TrapConfig struct {
	Path                    string
	Methods                 []string
	Intent                  string
	ResponseAuthenticated   ResponseTemplate
	ResponseUnauthenticated ResponseTemplate
	// FallbackAuthenticated and FallbackUnauthenticated are the Sentry's
	// default responses, sent when the trap's own body cannot be produced.
	FallbackAuthenticated   ResponseTemplate
	FallbackUnauthenticated ResponseTemplate
	ResponseHook            TrapResponseHook
}

type WatchFieldRule struct {
	Default any
	Intent  string
}

type WatchConfig struct {
	Path        string
	QueryFields map[string]WatchFieldRule
	BodyFields  map[string]WatchFieldRule
}

type FoundField struct {
	Type   string `json:"type"`
	Field  string `json:"field"`
	Value  any    `json:"value"`
	Intent string `json:"intent"`
}

type TrapBuilder struct {
	ts      *Sentry
	path    string
	methods []string
	intent  string
	// Response customisations are recorded as ordered operations and applied
	// to the Sentry's default responses when the trap is built, so the order
	// of SetDefault* / Trap() calls does not matter.
	authOps   []func(*ResponseTemplate)
	unauthOps []func(*ResponseTemplate)
	hook      TrapResponseHook
}

func newTrapBuilder(ts *Sentry, path string) *TrapBuilder {
	return &TrapBuilder{ts: ts, path: path, methods: []string{"GET", "POST"}}
}

func (b *TrapBuilder) Methods(methods ...string) *TrapBuilder {
	cleaned := make([]string, 0, len(methods))
	for _, m := range methods {
		m = strings.TrimSpace(strings.ToUpper(m))
		if m != "" {
			cleaned = append(cleaned, m)
		}
	}
	if len(cleaned) > 0 {
		b.ts.mu.Lock()
		b.methods = cleaned
		b.ts.trapGen++
		b.ts.mu.Unlock()
	}
	return b
}

func (b *TrapBuilder) Intent(intent string) *TrapBuilder {
	b.ts.mu.Lock()
	b.intent = intent
	b.ts.mu.Unlock()
	return b
}

// Respond customises the response for authenticated requests. See
// applyResponse for the "provided" semantics. It panics if cfg.Template names
// a template that has not been registered with Sentry.Template.
func (b *TrapBuilder) Respond(cfg ResponseConfig) *TrapBuilder {
	op := b.ts.responseOp(cfg)
	b.ts.mu.Lock()
	b.authOps = append(b.authOps, op)
	b.ts.mu.Unlock()
	return b
}

// IfUnauthenticated customises the response for unauthenticated requests.
func (b *TrapBuilder) IfUnauthenticated(cfg ResponseConfig) *TrapBuilder {
	op := b.ts.responseOp(cfg)
	b.ts.mu.Lock()
	b.unauthOps = append(b.unauthOps, op)
	b.ts.mu.Unlock()
	return b
}

// RespondWith sets a hook that may change the trap's status, body and
// headers on every hit, for example to answer 404 for an unknown parent ID or
// 201 to the owner of a project, as the real sibling route would. It must not
// block. Pass nil to remove it.
func (b *TrapBuilder) RespondWith(hook TrapResponseHook) *TrapBuilder {
	b.ts.mu.Lock()
	b.hook = hook
	b.ts.mu.Unlock()
	return b
}

// Build resolves the trap's configuration, applying the Sentry's current
// default responses. It is called at bootstrap time, so defaults configured
// after Trap() are honoured.
func (b *TrapBuilder) Build() TrapConfig {
	b.ts.mu.RLock()
	defer b.ts.mu.RUnlock()
	resolve := func(key string, ops []func(*ResponseTemplate)) ResponseTemplate {
		t := cloneTemplate(b.ts.defaultResponses[key])
		for _, op := range ops {
			op(&t)
		}
		if t.MIMEType == "" {
			t.MIMEType = "application/json"
		}
		return t
	}
	return TrapConfig{
		Path:                    b.path,
		Methods:                 append([]string(nil), b.methods...),
		Intent:                  b.intent,
		ResponseAuthenticated:   resolve("authenticated", b.authOps),
		ResponseUnauthenticated: resolve("unauthenticated", b.unauthOps),
		FallbackAuthenticated:   resolve("authenticated", nil),
		FallbackUnauthenticated: resolve("unauthenticated", nil),
		ResponseHook:            b.hook,
	}
}

// responseOp turns a ResponseConfig into an operation on a ResponseTemplate.
//
// A named Template replaces the whole response (and is looked up now, so a
// missing template fails at configuration time with a panic naming it).
// Otherwise only provided fields override the defaults: Status != 0, Body !=
// nil (so "", 0, false and empty maps are honoured), MIMEType != "" and
// Headers != nil. A zero Status means "not provided"; it is never a valid
// HTTP status anyway. Invalid headers panic at configuration time.
func (s *Sentry) responseOp(cfg ResponseConfig) func(*ResponseTemplate) {
	if cfg.Template != "" {
		s.mu.RLock()
		t, ok := s.templates[cfg.Template]
		s.mu.RUnlock()
		if !ok {
			panic(fmt.Sprintf("trappsec: response template %q not found; register it with Sentry.Template(name, ...) before referencing it", cfg.Template))
		}
		t = cloneTemplate(t)
		return func(dst *ResponseTemplate) { *dst = cloneTemplate(t) }
	}
	body := deepCopyValue(cfg.Body)
	var headers map[string]string
	if cfg.Headers != nil {
		var err error
		if headers, err = checkHeaders(cfg.Headers); err != nil {
			panic("trappsec: " + err.Error())
		}
	}
	return func(dst *ResponseTemplate) {
		if headers != nil {
			dst.Headers = cloneHeaders(headers)
		}
		if cfg.Status != 0 {
			dst.StatusCode = cfg.Status
		}
		if cfg.Body != nil {
			dst.Body = deepCopyValue(body)
		}
		if cfg.MIMEType != "" {
			dst.MIMEType = cfg.MIMEType
		}
	}
}

type WatchBuilder struct {
	ts     *Sentry
	config WatchConfig
}

func newWatchBuilder(ts *Sentry, path string) *WatchBuilder {
	return &WatchBuilder{
		ts: ts,
		config: WatchConfig{
			Path:        path,
			QueryFields: map[string]WatchFieldRule{},
			BodyFields:  map[string]WatchFieldRule{},
		},
	}
}

// Query watches a query-string field. Pass Default(v) to alert only when the
// value differs from v, and Intent(s) to label the alert:
//
//	watch.Query("debug", trappsec.Default("false"), trappsec.Intent("Recon"))
//
// The positional form Query(name, defaultValue, intent) is still accepted.
func (b *WatchBuilder) Query(name string, opts ...any) *WatchBuilder {
	rule := b.ts.fieldRule("Query", name, opts)
	b.ts.mu.Lock()
	b.config.QueryFields[name] = rule
	b.ts.mu.Unlock()
	return b
}

// Body watches a request-body field. It takes the same options as Query.
func (b *WatchBuilder) Body(name string, opts ...any) *WatchBuilder {
	rule := b.ts.fieldRule("Body", name, opts)
	b.ts.mu.Lock()
	b.config.BodyFields[name] = rule
	b.ts.mu.Unlock()
	return b
}

// Build returns a snapshot of the watch configuration.
func (b *WatchBuilder) Build() WatchConfig {
	b.ts.mu.RLock()
	defer b.ts.mu.RUnlock()
	cfg := WatchConfig{
		Path:        b.config.Path,
		QueryFields: make(map[string]WatchFieldRule, len(b.config.QueryFields)),
		BodyFields:  make(map[string]WatchFieldRule, len(b.config.BodyFields)),
	}
	for k, v := range b.config.QueryFields {
		cfg.QueryFields[k] = v
	}
	for k, v := range b.config.BodyFields {
		cfg.BodyFields[k] = v
	}
	return cfg
}
