package trappsec

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/labstack/echo/v4"
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

	defaultResponses map[string]ResponseTemplate
	traps            []*TrapBuilder
	watches          []*WatchBuilder
	templates        map[string]ResponseTemplate
	handlers         []EventHandler
	configVersion    uint64
	cachedTraps      []TrapConfig
	cachedWatches    []WatchConfig
	cachedTrapIndex  map[string][]TrapConfig
	cachedWatchIndex map[string][]WatchConfig
	cacheVersion     uint64

	integration integration
	mu          sync.RWMutex
}

type integration interface{}

func NewSentry(app any, service, environment string) *Sentry {
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
		traps:            []*TrapBuilder{},
		watches:          []*WatchBuilder{},
		templates:        map[string]ResponseTemplate{},
		handlers:         []EventHandler{},
		cachedTraps:      []TrapConfig{},
		cachedWatches:    []WatchConfig{},
		cachedTrapIndex:  map[string][]TrapConfig{},
		cachedWatchIndex: map[string][]WatchConfig{},
	}

	s.handlers = append(s.handlers, &LogHandler{logger: s.logger})
	s.register(app)
	return s
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
	s.touchConfigLocked()
	return builder
}

func (s *Sentry) Watch(path string) *WatchBuilder {
	s.mu.Lock()
	defer s.mu.Unlock()
	builder := newWatchBuilder(s, path)
	s.watches = append(s.watches, builder)
	s.touchConfigLocked()
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
	return s.trapsSnapshot()
}

func (s *Sentry) Watches() []WatchConfig {
	return s.watchesSnapshot()
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

func (s *Sentry) triggerTrapEvent(req any, trap TrapConfig) ([]byte, ResponseTemplate) {
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

	bodyVal := resolveDynamicBody(cfg.Body, req)
	payload := normalizePayload(cfg.MIMEType, bodyVal)
	return payload, cfg
}

func (s *Sentry) triggerWatchEvent(req any, found []FoundField) {
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

func (s *Sentry) detectHoneyFields(data map[string]any, rules map[string]WatchFieldRule, requestObj any) (map[string]any, []FoundField) {
	if data == nil || len(data) == 0 {
		return data, nil
	}
	found := make([]FoundField, 0)
	for key, value := range data {
		rule, ok := rules[key]
		if !ok {
			continue
		}

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
			delete(data, key)
		}
	}
	return data, found
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

func (s *Sentry) register(app any) {
	switch a := app.(type) {
	case *http.Server:
		s.integration = newNetHTTPServerIntegration(s, a)
	case *gin.Engine:
		s.integration = newGinIntegration(s, a)
	case *echo.Echo:
		s.integration = newEchoIntegration(s, a)
	default:
		t := reflect.TypeOf(app)
		if t == nil {
			panic("trappsec error: nil app instance")
		}
		panic(fmt.Sprintf("trappsec error: unknown framework type %s", runtimeTypeName(t)))
	}
}

func runtimeTypeName(t reflect.Type) string {
	if t == nil {
		return "<nil>"
	}
	if t.PkgPath() == "" {
		return t.String()
	}
	return strings.TrimSpace(t.PkgPath() + "." + t.Name())
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

func cloneWatchRules(src map[string]WatchFieldRule) map[string]WatchFieldRule {
	out := make(map[string]WatchFieldRule, len(src))
	for k, rule := range src {
		out[k] = WatchFieldRule{
			Default: deepCopyValue(rule.Default),
			Intent:  rule.Intent,
		}
	}
	return out
}

func cloneTrapConfig(src TrapConfig) TrapConfig {
	methods := make([]string, len(src.Methods))
	copy(methods, src.Methods)
	return TrapConfig{
		Path:                    src.Path,
		Methods:                 methods,
		Intent:                  src.Intent,
		ResponseAuthenticated:   cloneTemplate(src.ResponseAuthenticated),
		ResponseUnauthenticated: cloneTemplate(src.ResponseUnauthenticated),
	}
}

func cloneWatchConfig(src WatchConfig) WatchConfig {
	return WatchConfig{
		Path:        src.Path,
		QueryFields: cloneWatchRules(src.QueryFields),
		BodyFields:  cloneWatchRules(src.BodyFields),
	}
}

func cloneTrapSlice(src []TrapConfig) []TrapConfig {
	out := make([]TrapConfig, len(src))
	for i := range src {
		out[i] = cloneTrapConfig(src[i])
	}
	return out
}

func cloneWatchSlice(src []WatchConfig) []WatchConfig {
	out := make([]WatchConfig, len(src))
	for i := range src {
		out[i] = cloneWatchConfig(src[i])
	}
	return out
}

func (s *Sentry) touchConfig() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.touchConfigLocked()
}

func (s *Sentry) touchConfigLocked() {
	s.configVersion++
}

func (s *Sentry) rebuildConfigCacheLocked() {
	if s.cacheVersion == s.configVersion {
		return
	}

	traps := make([]TrapConfig, 0, len(s.traps))
	trapIndex := make(map[string][]TrapConfig, len(s.traps))
	for _, t := range s.traps {
		cfg := cloneTrapConfig(t.Build())
		traps = append(traps, cfg)
		trapIndex[cfg.Path] = append(trapIndex[cfg.Path], cfg)
	}

	watches := make([]WatchConfig, 0, len(s.watches))
	watchIndex := make(map[string][]WatchConfig, len(s.watches))
	for _, w := range s.watches {
		cfg := cloneWatchConfig(w.Build())
		watches = append(watches, cfg)
		watchIndex[cfg.Path] = append(watchIndex[cfg.Path], cfg)
	}

	s.cachedTraps = traps
	s.cachedWatches = watches
	s.cachedTrapIndex = trapIndex
	s.cachedWatchIndex = watchIndex
	s.cacheVersion = s.configVersion
}

func (s *Sentry) trapsSnapshot() []TrapConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rebuildConfigCacheLocked()
	return cloneTrapSlice(s.cachedTraps)
}

func (s *Sentry) watchesSnapshot() []WatchConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rebuildConfigCacheLocked()
	return cloneWatchSlice(s.cachedWatches)
}

func (s *Sentry) watchesForPath(path string) []WatchConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rebuildConfigCacheLocked()
	return cloneWatchSlice(s.cachedWatchIndex[path])
}

func (s *Sentry) trapsForPath(path string) []TrapConfig {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rebuildConfigCacheLocked()
	return cloneTrapSlice(s.cachedTrapIndex[path])
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

func resolveDynamicBody(body any, req any) any {
	switch fn := body.(type) {
	case func(any) any:
		return fn(req)
	case func(*http.Request) any:
		if r, ok := req.(*http.Request); ok {
			return fn(r)
		}
	case func(*gin.Context) any:
		if c, ok := req.(*gin.Context); ok {
			return fn(c)
		}
	case func(echo.Context) any:
		if c, ok := req.(echo.Context); ok {
			return fn(c)
		}
	}
	return body
}
