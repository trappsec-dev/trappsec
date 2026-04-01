// Package trappsececho integrates trappsec with the Echo web framework.
//
// Usage:
//
//	e := echo.New()
//	app := trappsececho.InstallSentry(e, "my-service", "production")
//	app.GET("/real-route", handler)
//	app.Trap("/fake-config").Methods("GET").Intent("Reconnaissance").Respond(...)
//	app.Start(":8080")
package trappsececho

import (
	"encoding/json"
	"github.com/labstack/echo/v4"
	core "github.com/trappsec-dev/trappsec/packages/go"
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
	EventHandler   = core.EventHandler
)

// NoDefault is re-exported from core so callers need only one import.
var NoDefault = core.NoDefault

// App wraps an Echo instance and a trappsec Sentry. All Echo methods (GET, POST,
// Use, Group, etc.) and all Sentry methods (Trap, Watch, IdentifyUser, etc.) are
// promoted directly — no inner field access needed. The Start* methods are shadowed
// to register trap routes transparently before the server starts accepting requests.
type App struct {
	*core.Sentry
	*echo.Echo
	integration *echoIntegration
}

// InstallSentry creates a Sentry, wires trappsec watch middleware onto the given Echo
// instance, and returns an *App that embeds both. Use app.Start() (not e.Start()) to
// start the server — this ensures trap routes are registered before requests are served.
func InstallSentry(e *echo.Echo, service, environment string) *App {
	s := core.NewSentry(service, environment)
	in := &echoIntegration{ts: s}

	if s.Identity.IP == nil {
		s.Identity.IP = func(req any) string {
			if c, ok := req.(echo.Context); ok {
				return c.RealIP()
			}
			return "0.0.0.0"
		}
	}

	s.Request.Path = func(req any) string {
		if c, ok := req.(echo.Context); ok {
			return c.Request().URL.Path
		}
		return ""
	}
	s.Request.UserAgent = func(req any) string {
		if c, ok := req.(echo.Context); ok {
			return c.Request().UserAgent()
		}
		return ""
	}
	s.Request.Method = func(req any) string {
		if c, ok := req.(echo.Context); ok {
			return c.Request().Method
		}
		return ""
	}

	s.SetBodyResolver(func(body any, req any) any {
		if fn, ok := body.(func(echo.Context) any); ok {
			if c, ok := req.(echo.Context); ok {
				return fn(c)
			}
		}
		return body
	})

	// Post-routing: watches need the resolved route pattern from c.Path().
	e.Use(in.watchMiddleware())

	return &App{Sentry: s, Echo: e, integration: in}
}

// Use wires up the trappsec watch middleware on the given Echo instance.
// Prefer InstallSentry, which also returns an *App whose Start* methods register
// trap routes transparently before the server starts.
func Use(s *core.Sentry, app *echo.Echo) {
	in := &echoIntegration{ts: s}

	if s.Identity.IP == nil {
		s.Identity.IP = func(req any) string {
			if c, ok := req.(echo.Context); ok {
				return c.RealIP()
			}
			return "0.0.0.0"
		}
	}

	s.Request.Path = func(req any) string {
		if c, ok := req.(echo.Context); ok {
			return c.Request().URL.Path
		}
		return ""
	}
	s.Request.UserAgent = func(req any) string {
		if c, ok := req.(echo.Context); ok {
			return c.Request().UserAgent()
		}
		return ""
	}
	s.Request.Method = func(req any) string {
		if c, ok := req.(echo.Context); ok {
			return c.Request().Method
		}
		return ""
	}

	s.SetBodyResolver(func(body any, req any) any {
		if fn, ok := body.(func(echo.Context) any); ok {
			if c, ok := req.(echo.Context); ok {
				return fn(c)
			}
		}
		return body
	})

	app.Use(in.watchMiddleware())
}

type echoIntegration struct {
	ts       *core.Sentry
	watchIdx map[string]core.WatchConfig
}

// bootstrap registers all configured trap routes with the Echo instance and builds the
// watch index. Called transparently from Start* methods.
func (a *App) bootstrap() {
	a.integration.watchIdx = make(map[string]core.WatchConfig)
	for _, w := range a.Sentry.Watches() {
		a.integration.watchIdx[w.Path] = w
	}
	// Register each trap as a real Echo route for each declared method.
	// By going through Echo's router, traps participate in the full middleware chain
	// (CORS, auth, rate limiting, etc.) and Echo's native 405 handling — ensuring
	// trap behavior is always consistent with real application routes.
	for _, trap := range a.Sentry.Traps() {
		t := trap
		for _, method := range trap.Methods {
			a.Echo.Add(strings.ToUpper(method), trap.Path, echoTrapHandler(a.Sentry, t))
		}
	}
}

// echoTrapHandler returns an Echo handler for a trap route.
func echoTrapHandler(ts *core.Sentry, trap core.TrapConfig) echo.HandlerFunc {
	return func(c echo.Context) error {
		body, cfg := ts.TriggerTrapEvent(c, trap)
		return c.Blob(cfg.StatusCode, cfg.MIMEType, body)
	}
}

// Start calls bootstrap (registering trap routes) then starts the HTTP server.
// Use this instead of e.Start() to ensure traps are active before serving.
func (a *App) Start(address string) error {
	a.bootstrap()
	return a.Echo.Start(address)
}

// StartTLS calls bootstrap then starts an HTTPS server.
func (a *App) StartTLS(address, certFile, keyFile string) error {
	a.bootstrap()
	return a.Echo.StartTLS(address, certFile, keyFile)
}

// StartAutoTLS calls bootstrap then starts a server with automatic TLS via Let's Encrypt.
func (a *App) StartAutoTLS(address string) error {
	a.bootstrap()
	return a.Echo.StartAutoTLS(address)
}

// StartServer calls bootstrap then starts a server using a custom http.Server.
func (a *App) StartServer(s *http.Server) error {
	a.bootstrap()
	return a.Echo.StartServer(s)
}

// watchMiddleware returns an Echo middleware that inspects requests for honey fields
// on watched routes. It runs via app.Use() — after Echo's router has matched the route —
// so c.Path() carries the route pattern (e.g. /users/:id) rather than the raw URL.
func (in *echoIntegration) watchMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			path := c.Path()

			if watch, ok := in.watchIdx[path]; ok {
				found := make([]core.FoundField, 0)

				if len(watch.QueryFields) > 0 {
					qData := core.QueryToMap(c.Request().URL.Query())
					sanitized, f, touched := in.ts.DetectHoneyFields(qData, watch.QueryFields, c)
					if len(f) > 0 {
						for i := range f {
							f[i].Type = "query"
						}
						found = append(found, f...)
					}
					if touched {
						c.Request().URL.RawQuery = core.MapToQuery(sanitized)
					}
				}

				if len(watch.BodyFields) > 0 {
					r := c.Request()
					bodyBytes := core.ReadBody(r)
					contentType := r.Header.Get("Content-Type")
					if len(bodyBytes) > 0 {
						if strings.Contains(contentType, "application/json") {
							var data map[string]any
							if err := json.Unmarshal(bodyBytes, &data); err == nil {
								sanitized, f, touched := in.ts.DetectHoneyFields(data, watch.BodyFields, c)
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
								sanitized, f, touched := in.ts.DetectHoneyFields(form, watch.BodyFields, c)
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
								sanitized, f, touched := in.ts.DetectHoneyFields(form, watch.BodyFields, c)
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
					in.ts.TriggerWatchEvent(c, found)
				}
			}

			return next(c)
		}
	}
}
