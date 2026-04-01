// Package trappsecnethttp integrates trappsec with the standard net/http server.
//
// Usage:
//
//	mux := http.NewServeMux()
//	app := trappsecnethttp.InstallSentry(mux, "my-service", "production")
//	app.HandleFunc("/real-route", handler)
//	app.Trap("/fake-config").Methods("GET").Intent("Reconnaissance").Respond(...)
//	app.ListenAndServe(":8080")
package trappsecnethttp

import (
	"encoding/json"
	core "github.com/trappsec-dev/trappsec/packages/go"
	"net"
	"net/http"
	"net/url"
	"strings"
)

// Re-export core types as aliases so callers need only one import.
type (
	Sentry         = core.Sentry
	AuthContext    = core.AuthContext
	ResponseConfig = core.ResponseConfig
	TrapConfig     = core.TrapConfig
	WatchConfig    = core.WatchConfig
	WatchFieldRule = core.WatchFieldRule
	FoundField     = core.FoundField
	TriggerContext = core.TriggerContext
	AppInfo        = core.AppInfo
	WebhookOptions = core.WebhookOptions
	SlackOptions   = core.SlackOptions
	EventHandler   = core.EventHandler
)

// NoDefault is re-exported from core so callers need only one import.
var NoDefault = core.NoDefault

// App wraps a ServeMux and a trappsec Sentry. All ServeMux methods (HandleFunc,
// Handle, etc.) and all Sentry methods (Trap, Watch, IdentifyUser, etc.) are promoted
// directly — no inner field access needed. ServeHTTP is shadowed to inject watch
// inspection, and the ListenAndServe* / Serve* methods register trap routes
// transparently before the server starts accepting requests.
type App struct {
	*core.Sentry
	*http.ServeMux
	integration *netHTTPIntegration
}

// InstallSentry creates a Sentry, wires trappsec onto the given ServeMux, and returns
// an *App that embeds both. Use app.ListenAndServe() (not http.ListenAndServe) to start
// the server — this ensures trap routes are registered before requests are served.
//
// Trap routes are registered using Go 1.22+ method-qualified patterns ("GET /path"),
// giving them the same 405 Method Not Allowed behaviour as real routes registered with
// method patterns.
func InstallSentry(mux *http.ServeMux, service, environment string) *App {
	s := core.NewSentry(service, environment)
	in := &netHTTPIntegration{ts: s}

	if s.Identity.IP == nil {
		s.Identity.IP = func(req any) string {
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

	s.Request.Path = func(req any) string {
		r, _ := req.(*http.Request)
		if r == nil {
			return ""
		}
		return r.URL.Path
	}
	s.Request.UserAgent = func(req any) string {
		r, _ := req.(*http.Request)
		if r == nil {
			return ""
		}
		return r.UserAgent()
	}
	s.Request.Method = func(req any) string {
		r, _ := req.(*http.Request)
		if r == nil {
			return ""
		}
		return r.Method
	}

	return &App{Sentry: s, ServeMux: mux, integration: in}
}

type netHTTPIntegration struct {
	ts       *core.Sentry
	watchIdx map[string]core.WatchConfig
}

// bootstrap registers all configured trap routes with the ServeMux and builds the
// watch index. Called transparently from ListenAndServe* / Serve* methods.
func (a *App) bootstrap() {
	a.integration.watchIdx = make(map[string]core.WatchConfig)
	for _, w := range a.Sentry.Watches() {
		a.integration.watchIdx[w.Path] = w
	}
	// Register each trap as a real route using Go 1.22+ method-qualified patterns.
	// This gives traps identical ServeMux behaviour to real routes: correct 405
	// responses for wrong methods, participation in the same routing pipeline, and
	// consistent response headers from any middleware wrapping the App handler.
	for _, trap := range a.Sentry.Traps() {
		t := trap
		for _, method := range trap.Methods {
			pattern := strings.ToUpper(method) + " " + trap.Path
			a.ServeMux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
				body, cfg := a.Sentry.TriggerTrapEvent(r, t)
				if cfg.MIMEType != "" {
					w.Header().Set("Content-Type", cfg.MIMEType)
				}
				w.WriteHeader(cfg.StatusCode)
				_, _ = w.Write(body)
			})
		}
	}
}

// ServeHTTP shadows *http.ServeMux's ServeHTTP to inject watch inspection before
// the request is dispatched. Pass app (not app.ServeMux) as the http.Handler when
// constructing a custom http.Server to ensure watches fire.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Resolve the matched route pattern before dispatch so watches can use it.
	_, pattern := a.ServeMux.Handler(r)

	// Strip optional "METHOD " prefix — Go 1.22+ patterns may be method-qualified
	// (e.g. "GET /users/{id}"), but watches are indexed by path pattern only.
	watchPath := pattern
	if idx := strings.IndexByte(watchPath, ' '); idx != -1 {
		watchPath = watchPath[idx+1:]
	}

	if watch, ok := a.integration.watchIdx[watchPath]; ok {
		found := make([]core.FoundField, 0)

		if len(watch.QueryFields) > 0 {
			qData := core.QueryToMap(r.URL.Query())
			sanitized, f, touched := a.integration.ts.DetectHoneyFields(qData, watch.QueryFields, r)
			if len(f) > 0 {
				for i := range f {
					f[i].Type = "query"
				}
				found = append(found, f...)
			}
			if touched {
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
						sanitized, f, touched := a.integration.ts.DetectHoneyFields(data, watch.BodyFields, r)
						if len(f) > 0 {
							for i := range f {
								f[i].Type = "body"
							}
							found = append(found, f...)
						}
						if touched {
							newBody, _ := json.Marshal(sanitized)
							core.ResetBody(r, newBody)
						}
					}
				} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
					vals, err := url.ParseQuery(string(bodyBytes))
					if err == nil {
						form := core.QueryToMap(vals)
						sanitized, f, touched := a.integration.ts.DetectHoneyFields(form, watch.BodyFields, r)
						if len(f) > 0 {
							for i := range f {
								f[i].Type = "body"
							}
							found = append(found, f...)
						}
						if touched {
							core.ResetBody(r, []byte(core.MapToQuery(sanitized)))
						}
					}
				} else if strings.Contains(contentType, "multipart/form-data") {
					form := core.ParseMultipartFields(r)
					if form != nil {
						sanitized, f, touched := a.integration.ts.DetectHoneyFields(form, watch.BodyFields, r)
						if len(f) > 0 {
							for i := range f {
								f[i].Type = "body"
							}
							found = append(found, f...)
						}
						if touched {
							core.RebuildMultipartBody(r, sanitized)
						}
					}
				}
			}
		}

		if len(found) > 0 {
			a.integration.ts.TriggerWatchEvent(r, found)
		}
	}

	a.ServeMux.ServeHTTP(w, r)
}

// ListenAndServe calls bootstrap (registering trap routes) then starts the HTTP server.
// Use this instead of http.ListenAndServe to ensure traps are active before serving.
func (a *App) ListenAndServe(addr string) error {
	a.bootstrap()
	return http.ListenAndServe(addr, a)
}

// ListenAndServeTLS calls bootstrap then starts an HTTPS server.
func (a *App) ListenAndServeTLS(addr, certFile, keyFile string) error {
	a.bootstrap()
	return http.ListenAndServeTLS(addr, certFile, keyFile, a)
}

// Serve calls bootstrap then accepts incoming connections on the given listener.
func (a *App) Serve(l net.Listener) error {
	a.bootstrap()
	return http.Serve(l, a)
}

// ServeTLS calls bootstrap then accepts TLS connections on the given listener.
func (a *App) ServeTLS(l net.Listener, certFile, keyFile string) error {
	a.bootstrap()
	return http.ServeTLS(l, a, certFile, keyFile)
}
