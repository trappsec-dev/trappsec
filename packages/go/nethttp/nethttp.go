// Package trappsecnethttp integrates trappsec with the standard net/http server.
//
// Usage:
//
//	server := &http.Server{Addr: ":8080", Handler: mux}
//	ts := trappsecnethttp.NewSentry(server, "my-service", "production")
package trappsecnethttp

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	core "github.com/trappsec-dev/trappsec/packages/go"
)

// Re-export core types as aliases so callers need only one import.
type (
	Sentry        = core.Sentry
	AuthContext    = core.AuthContext
	ResponseConfig = core.ResponseConfig
	TrapConfig     = core.TrapConfig
	WatchConfig    = core.WatchConfig
	WatchFieldRule = core.WatchFieldRule
	FoundField     = core.FoundField
	TriggerContext = core.TriggerContext
	AppInfo        = core.AppInfo
	WebhookOptions = core.WebhookOptions
	EventHandler   = core.EventHandler
)

// NoDefault is re-exported from core so callers need only one import.
var NoDefault = core.NoDefault

// NewSentry creates a Sentry and wires trappsec middleware onto the given http.Server.
func NewSentry(server *http.Server, service, environment string) *Sentry {
	s := core.NewSentry(service, environment)
	newNetHTTPServerIntegration(s, server)
	return s
}

// WrapHTTPHandler wraps an existing http.Handler with trappsec middleware.
// Use this when you manage the handler yourself rather than using http.Server.
func WrapHTTPHandler(s *Sentry, next http.Handler) http.Handler {
	in := &netHTTPServerIntegration{ts: s}
	return in.wrap(next)
}

type netHTTPServerIntegration struct {
	ts       *core.Sentry
	once     sync.Once
	trapIdx  map[string]core.TrapConfig
	watchIdx map[string]core.WatchConfig
}

func newNetHTTPServerIntegration(ts *core.Sentry, server *http.Server) *netHTTPServerIntegration {
	in := &netHTTPServerIntegration{ts: ts}

	if ts.Identity.IP == nil {
		ts.Identity.IP = func(req any) string {
			r, ok := req.(*http.Request)
			if !ok || r == nil {
				return "0.0.0.0"
			}
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err == nil {
				return host
			}
			return r.RemoteAddr
		}
	}

	ts.Request.Path = func(req any) string {
		r, _ := req.(*http.Request)
		if r == nil {
			return ""
		}
		return r.URL.Path
	}
	ts.Request.UserAgent = func(req any) string {
		r, _ := req.(*http.Request)
		if r == nil {
			return ""
		}
		return r.UserAgent()
	}
	ts.Request.Method = func(req any) string {
		r, _ := req.(*http.Request)
		if r == nil {
			return ""
		}
		return r.Method
	}

	next := server.Handler
	if next == nil {
		next = http.DefaultServeMux
	}
	server.Handler = in.wrap(next)
	return in
}

func (in *netHTTPServerIntegration) buildIndexes() {
	in.once.Do(func() {
		in.trapIdx = make(map[string]core.TrapConfig)
		for _, t := range in.ts.Traps() {
			in.trapIdx[t.Path] = t
		}
		in.watchIdx = make(map[string]core.WatchConfig)
		for _, w := range in.ts.Watches() {
			in.watchIdx[w.Path] = w
		}
	})
}

func (in *netHTTPServerIntegration) wrap(next http.Handler) http.Handler {
	mux, _ := next.(*http.ServeMux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in.buildIndexes()
		path := r.URL.Path
		method := strings.ToUpper(r.Method)

		if trap, ok := in.trapIdx[path]; ok && core.MethodAllowed(method, trap.Methods) {
			body, cfg := in.ts.TriggerTrapEvent(r, trap)
			if cfg.MIMEType != "" {
				w.Header().Set("Content-Type", cfg.MIMEType)
			}
			w.WriteHeader(cfg.StatusCode)
			_, _ = w.Write(body)
			return
		}

		watchPath := path
		if mux != nil {
			_, watchPath = mux.Handler(r)
		}

		if watch, ok := in.watchIdx[watchPath]; ok {
			found := make([]core.FoundField, 0)

			if len(watch.QueryFields) > 0 {
				qData := core.QueryToMap(r.URL.Query())
				sanitized, f := in.ts.DetectHoneyFields(qData, watch.QueryFields, r)
				if len(f) > 0 {
					for i := range f {
						f[i].Type = "query"
					}
					found = append(found, f...)
					r.URL.RawQuery = core.MapToQuery(sanitized)
				}
			}

			if len(watch.BodyFields) > 0 {
				contentType := r.Header.Get("Content-Type")
				bodyBytes := core.ReadBody(r)
				if len(bodyBytes) > 0 {
					if strings.Contains(contentType, "application/json") {
						var data map[string]any
						if err := json.Unmarshal(bodyBytes, &data); err == nil {
							sanitized, f := in.ts.DetectHoneyFields(data, watch.BodyFields, r)
							if len(f) > 0 {
								for i := range f {
									f[i].Type = "body"
								}
								found = append(found, f...)
								newBody, _ := json.Marshal(sanitized)
								core.ResetBody(r, newBody)
							}
						}
					} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
						vals, err := url.ParseQuery(string(bodyBytes))
						if err == nil {
							form := core.QueryToMap(vals)
							sanitized, f := in.ts.DetectHoneyFields(form, watch.BodyFields, r)
							if len(f) > 0 {
								for i := range f {
									f[i].Type = "body"
								}
								found = append(found, f...)
								core.ResetBody(r, []byte(core.MapToQuery(sanitized)))
							}
						}
					}
				}
			}

			if len(found) > 0 {
				in.ts.TriggerWatchEvent(r, found)
			}
		}

		next.ServeHTTP(w, r)
	})
}
