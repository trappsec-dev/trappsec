package trappsec

import (
	"fmt"
	"strings"
)

type ResponseTemplate struct {
	StatusCode int
	Body       any
	MIMEType   string
}

type ResponseConfig struct {
	Status   int
	Body     any
	MIMEType string
	Template string
}

type TrapConfig struct {
	Path                    string
	Methods                 []string
	Intent                  string
	ResponseAuthenticated   ResponseTemplate
	ResponseUnauthenticated ResponseTemplate
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
	}
}

// responseOp turns a ResponseConfig into an operation on a ResponseTemplate.
//
// A named Template replaces the whole response (and is looked up now, so a
// missing template fails at configuration time with a panic naming it).
// Otherwise only provided fields override the defaults: Status != 0, Body !=
// nil (so "", 0, false and empty maps are honoured) and MIMEType != "". A zero
// Status means "not provided"; it is never a valid HTTP status anyway.
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
	return func(dst *ResponseTemplate) {
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
