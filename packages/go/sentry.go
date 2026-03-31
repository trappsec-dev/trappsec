package trappsec

import (
	"encoding/json"
	"log"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"
)

var NoDefault = struct{}{}

type AuthContext struct {
	User string
	Role string
}

type TriggerContext struct {
	Timestamp float64      `json:"timestamp"`
	Event     string       `json:"event"`
	Type      string       `json:"type"`
	Reason    string       `json:"reason,omitempty"`
	Intent    string       `json:"intent,omitempty"`
	Path      string       `json:"path"`
	Method    string       `json:"method"`
	IP        string       `json:"ip,omitempty"`
	User      string       `json:"user,omitempty"`
	Role      string       `json:"role,omitempty"`
	UserAgent string       `json:"user_agent,omitempty"`
	Found     []FoundField `json:"found_fields,omitempty"`
	Metadata  any          `json:"metadata,omitempty"`
	App       AppInfo      `json:"app"`
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
	s.bodyResolver = fn
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
	s.defaultResponses["unauthenticated"] = ResponseTemplate{StatusCode: statusCode, Body: body, MIMEType: mimeType}
}

func (s *Sentry) SetDefaultAuthenticated(statusCode int, body any, mimeType string) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	s.mu.Lock()
	defer s.mu.Unlock()
	builder := newTrapBuilder(s, path)
	s.traps = append(s.traps, builder)
	return builder
}

func (s *Sentry) Watch(path string) *WatchBuilder {
	s.mu.Lock()
	defer s.mu.Unlock()
	builder := newWatchBuilder(s, path)
	s.watches = append(s.watches, builder)
	return builder
}

func (s *Sentry) AddWebhook(url string, opts *WebhookOptions) *Sentry {
	localOpts := &WebhookOptions{}
	if opts == nil {
		opts = localOpts
	}
	*localOpts = *opts
	if localOpts.Service == "" {
		localOpts.Service = s.service
	}
	if localOpts.Environment == "" {
		localOpts.Environment = s.environment
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

func (s *Sentry) IdentifyUser(fn func(any) *AuthContext) *Sentry {
	s.Identity.Auth = fn
	return s
}

func (s *Sentry) OverrideSourceIP(fn func(any) string) *Sentry {
	s.Identity.IP = fn
	return s
}

func (s *Sentry) Traps() []TrapConfig {
	out := make([]TrapConfig, 0, len(s.traps))
	for _, t := range s.traps {
		out = append(out, t.Build())
	}
	return out
}

func (s *Sentry) Watches() []WatchConfig {
	out := make([]WatchConfig, 0, len(s.watches))
	for _, w := range s.watches {
		out = append(out, w.Build())
	}
	return out
}

func (s *Sentry) Trigger(req any, reason, intent string, metadata any) {
	identity := s.getIdentity(req)
	request := s.getRequest(req)
	ctx := TriggerContext{
		Timestamp: float64(time.Now().UnixNano()) / 1e9,
		Event:     "trappsec.rule_hit",
		Type:      "signal",
		Reason:    reason,
		Intent:    intent,
		Path:      request.Path,
		Method:    request.Method,
		UserAgent: request.UserAgent,
		IP:        identity.IP,
		Metadata:  metadata,
	}
	if identity.User != "" {
		ctx.Type = "alert"
		ctx.User = identity.User
		ctx.Role = identity.Role
	}
	s.emit(ctx)
}

// TriggerTrapEvent emits a trap_hit event and returns the response body and config.
// Called by framework integration packages.
func (s *Sentry) TriggerTrapEvent(req any, trap TrapConfig) ([]byte, ResponseTemplate) {
	identity := s.getIdentity(req)
	request := s.getRequest(req)
	ctx := TriggerContext{
		Timestamp: float64(time.Now().UnixNano()) / 1e9,
		Event:     "trappsec.trap_hit",
		Type:      "signal",
		Path:      request.Path,
		Method:    request.Method,
		UserAgent: request.UserAgent,
		IP:        identity.IP,
		Intent:    trap.Intent,
	}

	key := "response.unauthenticated"
	if identity.User != "" {
		ctx.Type = "alert"
		ctx.User = identity.User
		ctx.Role = identity.Role
		key = "response.authenticated"
	}

	s.emit(ctx)
	cfg := trap.ResponseUnauthenticated
	if key == "response.authenticated" {
		cfg = trap.ResponseAuthenticated
	}

	bodyVal := s.resolveDynamicBody(cfg.Body, req)
	payload := normalizePayload(cfg.MIMEType, bodyVal)
	return payload, cfg
}

// TriggerWatchEvent emits a watch_hit event. Called by framework integration packages.
func (s *Sentry) TriggerWatchEvent(req any, found []FoundField) {
	identity := s.getIdentity(req)
	request := s.getRequest(req)
	ctx := TriggerContext{
		Timestamp: float64(time.Now().UnixNano()) / 1e9,
		Event:     "trappsec.watch_hit",
		Type:      "signal",
		Path:      request.Path,
		Method:    request.Method,
		UserAgent: request.UserAgent,
		IP:        identity.IP,
		Found:     found,
	}
	if identity.User != "" {
		ctx.Type = "alert"
		ctx.User = identity.User
		ctx.Role = identity.Role
	}
	s.emit(ctx)
}

// DetectHoneyFields scans data for fields matching the watch rules and returns
// the sanitized map, any triggered fields, and whether any watched key was present.
// Called by framework integration packages.
func (s *Sentry) DetectHoneyFields(data map[string]any, rules map[string]WatchFieldRule, requestObj any) (map[string]any, []FoundField, bool) {
	if len(data) == 0 {
		return data, nil, false
	}
	found := make([]FoundField, 0)
	touched := false
	for key, value := range data {
		rule, ok := rules[key]
		if !ok {
			continue
		}
		touched = true

		expected := rule.Default
		if fn, ok := expected.(func(any) any); ok {
			expected = fn(requestObj)
		}

		if expected == NoDefault || !reflect.DeepEqual(value, expected) {
			found = append(found, FoundField{
				Type:   "body",
				Field:  key,
				Value:  value,
				Intent: rule.Intent,
			})
		}
		delete(data, key)
	}
	return data, found, touched
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
	id := extractedIdentity{}
	if s.Identity.Auth != nil {
		if auth := s.Identity.Auth(req); auth != nil {
			id.User = auth.User
			id.Role = auth.Role
		}
	}
	if s.Identity.IP != nil {
		id.IP = s.Identity.IP(req)
	}
	return id
}

func (s *Sentry) getRequest(req any) extractedRequest {
	return extractedRequest{
		Path:      s.Request.Path(req),
		Method:    s.Request.Method(req),
		UserAgent: s.Request.UserAgent(req),
	}
}

func (s *Sentry) emit(ctx TriggerContext) {
	ctx.App = AppInfo{Service: s.service, Environment: s.environment, Hostname: s.hostname}

	s.mu.RLock()
	handlers := append([]EventHandler(nil), s.handlers...)
	s.mu.RUnlock()

	for _, h := range handlers {
		if err := h.Emit(ctx); err != nil {
			s.logger.Printf("error invoking handler: %v", err)
		}
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

func normalizePayload(mimeType string, body any) []byte {
	if body == nil {
		body = map[string]any{}
	}

	switch v := body.(type) {
	case []byte:
		return v
	case string:
		return []byte(v)
	default:
		if strings.EqualFold(mimeType, "application/json") {
			b, err := json.Marshal(v)
			if err == nil {
				return b
			}
		}
		b, _ := json.Marshal(v)
		return b
	}
}

func (s *Sentry) resolveDynamicBody(body any, req any) any {
	// Framework-specific resolver runs first (e.g. func(*gin.Context) any).
	// If the resolver does not recognise the body type it returns body unchanged,
	// and the generic func(any) any case below handles it.
	// NOTE: never compare the returned value to body — function types are
	// uncomparable in Go and will panic at runtime.
	if s.bodyResolver != nil {
		body = s.bodyResolver(body, req)
	}
	if fn, ok := body.(func(any) any); ok {
		return fn(req)
	}
	return body
}
