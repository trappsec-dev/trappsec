package trappsec

import "strings"

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
	Intent string `json:"intent,omitempty"`
}

type TrapBuilder struct {
	ts     *Sentry
	config TrapConfig
}

func newTrapBuilder(ts *Sentry, path string) *TrapBuilder {
	return &TrapBuilder{
		ts: ts,
		config: TrapConfig{
			Path:                    path,
			Methods:                 []string{"GET", "POST"},
			Intent:                  "",
			ResponseAuthenticated:   cloneTemplate(ts.defaultResponses["authenticated"]),
			ResponseUnauthenticated: cloneTemplate(ts.defaultResponses["unauthenticated"]),
		},
	}
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
		b.config.Methods = cleaned
		b.ts.touchConfig()
	}
	return b
}

func (b *TrapBuilder) Intent(intent string) *TrapBuilder {
	b.config.Intent = intent
	b.ts.touchConfig()
	return b
}

func (b *TrapBuilder) Respond(cfg ResponseConfig) *TrapBuilder {
	b.applyResponse("authenticated", cfg)
	return b
}

func (b *TrapBuilder) IfUnauthenticated(cfg ResponseConfig) *TrapBuilder {
	b.applyResponse("unauthenticated", cfg)
	return b
}

func (b *TrapBuilder) Build() TrapConfig {
	return b.config
}

func (b *TrapBuilder) applyResponse(key string, cfg ResponseConfig) {
	var target *ResponseTemplate
	if key == "authenticated" {
		target = &b.config.ResponseAuthenticated
	} else {
		target = &b.config.ResponseUnauthenticated
	}

	if cfg.Template != "" {
		b.ts.mu.RLock()
		t, ok := b.ts.templates[cfg.Template]
		b.ts.mu.RUnlock()
		if !ok {
			panic("response_builder: template not found: " + cfg.Template)
		}
		*target = cloneTemplate(t)
		b.ts.touchConfig()
		return
	}

	if cfg.Status > 0 {
		target.StatusCode = cfg.Status
	}
	if cfg.Body != nil {
		target.Body = cfg.Body
	}
	if cfg.MIMEType != "" {
		target.MIMEType = cfg.MIMEType
	}
	b.ts.touchConfig()
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

func (b *WatchBuilder) Query(name string, defaultValue any, intent string) *WatchBuilder {
	b.config.QueryFields[name] = WatchFieldRule{Default: defaultValue, Intent: intent}
	b.ts.touchConfig()
	return b
}

func (b *WatchBuilder) Body(name string, defaultValue any, intent string) *WatchBuilder {
	b.config.BodyFields[name] = WatchFieldRule{Default: defaultValue, Intent: intent}
	b.ts.touchConfig()
	return b
}

func (b *WatchBuilder) Build() WatchConfig {
	return b.config
}
