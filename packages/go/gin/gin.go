// Package trappsecgin integrates trappsec with the Gin web framework.
//
// Usage:
//
//	r := gin.New()
//	app := trappsecgin.InstallSentry(r, "my-service", "production")
//	app.GET("/real-route", handler)
//	app.Trap("/fake-config").Methods("GET").Intent("Reconnaissance").Respond(...)
//	app.Run(":8080")
package trappsecgin

import (
	"encoding/json"
	"net"
	"net/url"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	core "github.com/trappsec-dev/trappsec/packages/go"
)

// Re-export core types as aliases so callers need only one import.
type (
	Sentry         = core.Sentry
	AuthContext     = core.AuthContext
	ResponseConfig  = core.ResponseConfig
	TrapConfig      = core.TrapConfig
	WatchConfig     = core.WatchConfig
	WatchFieldRule  = core.WatchFieldRule
	FoundField      = core.FoundField
	TriggerContext  = core.TriggerContext
	AppInfo         = core.AppInfo
	WebhookOptions  = core.WebhookOptions
	EventHandler    = core.EventHandler
)

// NoDefault is re-exported from core so callers need only one import.
var NoDefault = core.NoDefault

// App wraps a Gin engine and a trappsec Sentry. All Gin engine methods (GET, POST,
// Use, Group, NoRoute, etc.) and all Sentry methods (Trap, Watch, IdentifyUser, etc.)
// are promoted directly — no inner field access needed. The Run* methods are shadowed
// to register trap routes transparently before the server starts accepting requests.
type App struct {
	*core.Sentry
	*gin.Engine
	integration *ginIntegration
}

// InstallSentry creates a Sentry, wires trappsec watch middleware onto the given Gin
// engine, and returns an *App that embeds both. Use app.Run() (not r.Run()) to start
// the server — this ensures trap routes are registered before the server accepts requests.
func InstallSentry(engine *gin.Engine, service, environment string) *App {
	s := core.NewSentry(service, environment)
	in := &ginIntegration{ts: s}

	if s.Identity.IP == nil {
		s.Identity.IP = func(req any) string {
			if c, ok := req.(*gin.Context); ok {
				return c.ClientIP()
			}
			return "0.0.0.0"
		}
	}

	s.Request.Path = func(req any) string {
		if c, ok := req.(*gin.Context); ok {
			return c.Request.URL.Path
		}
		return ""
	}
	s.Request.UserAgent = func(req any) string {
		if c, ok := req.(*gin.Context); ok {
			return c.Request.UserAgent()
		}
		return ""
	}
	s.Request.Method = func(req any) string {
		if c, ok := req.(*gin.Context); ok {
			return c.Request.Method
		}
		return ""
	}

	s.SetBodyResolver(func(body any, req any) any {
		if fn, ok := body.(func(*gin.Context) any); ok {
			if c, ok := req.(*gin.Context); ok {
				return fn(c)
			}
		}
		return body
	})

	engine.Use(in.watchMiddleware())

	return &App{Sentry: s, Engine: engine, integration: in}
}

// Use wires up the trappsec watch middleware on the given Gin engine.
// Prefer InstallSentry, which also returns an *App whose Run* methods register
// trap routes transparently before the server starts.
func Use(s *core.Sentry, app *gin.Engine) {
	in := &ginIntegration{ts: s}

	if s.Identity.IP == nil {
		s.Identity.IP = func(req any) string {
			if c, ok := req.(*gin.Context); ok {
				return c.ClientIP()
			}
			return "0.0.0.0"
		}
	}

	s.Request.Path = func(req any) string {
		if c, ok := req.(*gin.Context); ok {
			return c.Request.URL.Path
		}
		return ""
	}
	s.Request.UserAgent = func(req any) string {
		if c, ok := req.(*gin.Context); ok {
			return c.Request.UserAgent()
		}
		return ""
	}
	s.Request.Method = func(req any) string {
		if c, ok := req.(*gin.Context); ok {
			return c.Request.Method
		}
		return ""
	}

	s.SetBodyResolver(func(body any, req any) any {
		if fn, ok := body.(func(*gin.Context) any); ok {
			if c, ok := req.(*gin.Context); ok {
				return fn(c)
			}
		}
		return body
	})

	app.Use(in.watchMiddleware())
}

type ginIntegration struct {
	ts       *core.Sentry
	once     sync.Once
	watchIdx map[string]core.WatchConfig
}

// bootstrap registers all configured trap routes with the Gin engine and builds the
// watch index. Called transparently from Run* methods. Safe to call multiple times —
// sync.Once ensures only the first call has any effect.
func (a *App) bootstrap() {
	a.integration.once.Do(func() {
		a.integration.watchIdx = make(map[string]core.WatchConfig)
		for _, w := range a.Sentry.Watches() {
			a.integration.watchIdx[w.Path] = w
		}
		// Register each trap as a real Gin route for each declared method.
		// By going through the engine's router, traps participate in the full middleware
		// chain (CORS, auth, rate limiting, etc.) and inherit the engine's
		// HandleMethodNotAllowed configuration — ensuring trap behavior is always
		// consistent with real application routes.
		for _, trap := range a.Sentry.Traps() {
			t := trap
			for _, method := range trap.Methods {
				a.Engine.Handle(strings.ToUpper(method), trap.Path, ginTrapHandler(a.Sentry, t))
			}
		}
	})
}

// ginTrapHandler returns a Gin handler for a trap route.
func ginTrapHandler(ts *core.Sentry, trap core.TrapConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		body, cfg := ts.TriggerTrapEvent(c, trap)
		c.Data(cfg.StatusCode, cfg.MIMEType, body)
	}
}

// Run calls bootstrap (registering trap routes) then starts the HTTP server.
// Use this instead of engine.Run() to ensure traps are active before serving.
func (a *App) Run(addr ...string) error {
	a.bootstrap()
	return a.Engine.Run(addr...)
}

// RunTLS calls bootstrap then starts an HTTPS server.
func (a *App) RunTLS(addr, certFile, keyFile string) error {
	a.bootstrap()
	return a.Engine.RunTLS(addr, certFile, keyFile)
}

// RunUnix calls bootstrap then starts a Unix socket server.
func (a *App) RunUnix(file string) error {
	a.bootstrap()
	return a.Engine.RunUnix(file)
}

// RunFd calls bootstrap then starts a server using a file descriptor.
func (a *App) RunFd(fd int) error {
	a.bootstrap()
	return a.Engine.RunFd(fd)
}

// RunListener calls bootstrap then starts a server using a custom net.Listener.
func (a *App) RunListener(listener net.Listener) error {
	a.bootstrap()
	return a.Engine.RunListener(listener)
}

// watchMiddleware returns a Gin middleware that inspects requests for honey fields
// on watched routes. It runs after route matching so c.FullPath() carries the route
// pattern (e.g. /users/:id) rather than the raw URL.
func (in *ginIntegration) watchMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}

		if watch, ok := in.watchIdx[path]; ok {
			found := make([]core.FoundField, 0)

			if len(watch.QueryFields) > 0 {
				qData := core.QueryToMap(c.Request.URL.Query())
				sanitized, f := in.ts.DetectHoneyFields(qData, watch.QueryFields, c)
				if len(f) > 0 {
					for i := range f {
						f[i].Type = "query"
					}
					found = append(found, f...)
					c.Request.URL.RawQuery = core.MapToQuery(sanitized)
				}
			}

			if len(watch.BodyFields) > 0 {
				bodyBytes := core.ReadBody(c.Request)
				contentType := c.GetHeader("Content-Type")
				if len(bodyBytes) > 0 {
					if strings.Contains(contentType, "application/json") {
						var data map[string]any
						if err := json.Unmarshal(bodyBytes, &data); err == nil {
							sanitized, f := in.ts.DetectHoneyFields(data, watch.BodyFields, c)
							if len(f) > 0 {
								for i := range f {
									f[i].Type = "body"
								}
								found = append(found, f...)
								newBody, _ := json.Marshal(sanitized)
								core.ResetBody(c.Request, newBody)
							}
						}
					} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
						vals, err := url.ParseQuery(string(bodyBytes))
						if err == nil {
							form := core.QueryToMap(vals)
							sanitized, f := in.ts.DetectHoneyFields(form, watch.BodyFields, c)
							if len(f) > 0 {
								for i := range f {
									f[i].Type = "body"
								}
								found = append(found, f...)
								core.ResetBody(c.Request, []byte(core.MapToQuery(sanitized)))
							}
						}
					}
				}
			}

			if len(found) > 0 {
				in.ts.TriggerWatchEvent(c, found)
			}
		}

		c.Next()
	}
}
