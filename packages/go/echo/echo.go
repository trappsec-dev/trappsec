// Package trappsececho integrates trappsec with Echo v4.
//
// Deprecated: Echo v4 gets upstream fixes only until 2026-12-31. Use
// github.com/trappsec-dev/trappsec/packages/go/echov5 with Echo v5; the
// package name and API are the same.
//
// Usage:
//
//	e := echo.New()
//	app := trappsececho.InstallSentry(e, "my-service", "production")
//	app.GET("/real-route", handler)
//	app.Trap("/fake-config").Methods("GET").Intent("Reconnaissance").Respond(...)
//	app.Start(":8080")
//
// Always serve through the returned *App (app.Start, or app as the http.Handler for
// http.Server / httptest). The App bootstraps lazily on the first request. The
// watch middleware is installed at bootstrap, after any middleware you added with
// Use, and Echo applies Use middleware to every route regardless of registration
// order, so routes registered before InstallSentry are covered.
package trappsececho

import (
	"context"
	"fmt"
	"github.com/labstack/echo/v4"
	core "github.com/trappsec-dev/trappsec/packages/go"
	"github.com/trappsec-dev/trappsec/packages/go/internal/adapter"
	"golang.org/x/net/http2"
	"log"
	"net/http"
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
	Option         = core.Option
)

// NoDefault, Default, Intent and Metadata are re-exported from core so callers
// need only one import.
var (
	NoDefault = core.NoDefault
	Default   = core.Default
	Intent    = core.Intent
	Metadata  = core.Metadata
)

// App wraps an Echo instance and a trappsec Sentry. All Echo methods (GET, POST,
// Use, Group, etc.) and all Sentry methods (Trap, Watch, IdentifyUser, etc.) are
// promoted directly, except where both define the name: Logger() returns the
// trappsec logger (Echo's logger is EchoLogger()), and Close(ctx) flushes and
// stops trappsec handlers only (stop the server with Shutdown(ctx) or
// app.Echo.Close()).
type App struct {
	*core.Sentry
	*echo.Echo
	integration *echoIntegration
}

// Logger returns the trappsec logger. Echo's own logger is available as
// EchoLogger() (or app.Echo.Logger).
func (a *App) Logger() *log.Logger { return a.Sentry.Logger() }

// Close flushes and stops trappsec's handlers (see Sentry.Close). It does not
// stop the server: use Shutdown(ctx) or app.Echo.Close() for that.
func (a *App) Close(ctx context.Context) error { return a.Sentry.Close(ctx) }

// EchoLogger returns Echo's logger.
func (a *App) EchoLogger() echo.Logger { return a.Echo.Logger }

// InstallSentry creates a Sentry, wires trappsec onto the given Echo instance and
// returns an *App that embeds both.
func InstallSentry(e *echo.Echo, service, environment string) *App {
	return Use(core.NewSentry(service, environment), e)
}

// Use wires an existing Sentry onto the Echo instance and returns the *App to
// serve through (app.Start*, or app as an http.Handler). Traps and watches only
// become active through the returned App.
func Use(s *core.Sentry, e *echo.Echo) *App {
	in := &echoIntegration{ts: s}

	adapter.InstallRequestAccessors(s, requestOf)

	adapter.SetBodyResolver(s, func(body any, req any) any {
		if fn, ok := body.(func(echo.Context) any); ok {
			if c, ok := req.(echo.Context); ok {
				return fn(c)
			}
		}
		return body
	})

	return &App{Sentry: s, Echo: e, integration: in}
}

func requestOf(req any) *http.Request {
	switch t := req.(type) {
	case echo.Context:
		if t != nil {
			return t.Request()
		}
	case *http.Request:
		return t
	}
	return nil
}

type echoIntegration struct {
	ts       *core.Sentry
	watchIdx map[string]core.WatchConfig
	trapIdx  map[string]bool // "METHOD path" of every trap route
	maxBody  adapter.MaxBody
	once     adapter.Once
}

// Bootstrap registers trap routes and the watch middleware and builds the watch
// index. It is idempotent and safe for concurrent use, and runs automatically on
// the first request and from Start*. It panics with a clear message if a trap
// duplicates an existing route (instead of silently replacing it); later calls
// repeat the same panic.
func (a *App) Bootstrap() { a.integration.once.Do(a.install) }

func (a *App) install() {
	in := a.integration
	idx := make(map[string]core.WatchConfig)
	for _, w := range in.ts.Watches() {
		idx[w.Path] = w
	}

	existing := map[string]bool{}
	traps := map[string]bool{}
	for _, ri := range a.Echo.Routes() {
		existing[ri.Method+" "+ri.Path] = true
	}
	for _, trap := range in.ts.Traps() {
		t := trap
		for _, method := range trap.Methods {
			method = strings.ToUpper(method)
			if existing[method+" "+trap.Path] {
				panic(fmt.Sprintf("trappsec: trap %s %s duplicates an existing route; "+
					"rename the trap or remove the real route", method, trap.Path))
			}
			a.Echo.Add(method, trap.Path, echoTrapHandler(in.ts, t))
			existing[method+" "+trap.Path] = true
			traps[method+" "+trap.Path] = true
		}
	}
	in.watchIdx = idx
	in.trapIdx = traps
	paths := make([]string, 0, len(a.Echo.Routes()))
	for _, ri := range a.Echo.Routes() {
		paths = append(paths, ri.Path)
	}
	adapter.WarnUnmatchedWatches(in.ts, idx, paths)
	a.Echo.Use(in.watchMiddleware())
	if len(idx) > 0 {
		a.Echo.Pre(in.preMiddleware())
	}
}

// IsTrap reports whether the request matched a trap route. Use it as the
// Skipper of middleware that would otherwise reject a trap before it can
// answer, such as CSRF protection (R22): a trap that returns 403 is both
// disabled and easy to fingerprint.
//
//	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{Skipper: app.IsTrap}))
//
// It bootstraps lazily, so it is safe to call before the first request. Once
// Echo has routed the request it answers from the matched route, so a real
// route that only looks like a trap (POST /users/me next to a trap POST
// /users/:id) is never reported as one. Before routing (e.Pre middleware) it
// falls back to Sentry.IsTrap's path matching.
func (a *App) IsTrap(c echo.Context) bool {
	a.Bootstrap()
	if route := c.Path(); route != "" {
		return a.integration.trapIdx[strings.ToUpper(c.Request().Method)+" "+route]
	}
	return a.Sentry.IsTrap(c)
}

// SetMaxBodyBytes sets the largest request body that watch inspection buffers
// (default 1 MiB). Larger bodies pass through intact but uninspected.
func (a *App) SetMaxBodyBytes(n int64) { a.integration.maxBody.Set(n) }

// echoTrapHandler returns an Echo handler for a trap route.
func echoTrapHandler(ts *core.Sentry, trap core.TrapConfig) echo.HandlerFunc {
	return func(c echo.Context) error {
		body, cfg := adapter.TriggerTrapEvent(ts, c, trap)
		return c.Blob(cfg.StatusCode, cfg.MIMEType, body)
	}
}

// ServeHTTP bootstraps lazily on the first request, then dispatches to Echo.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.Bootstrap()
	a.Echo.ServeHTTP(w, r)
}

// Start calls Bootstrap then starts the HTTP server.
func (a *App) Start(address string) error {
	a.Bootstrap()
	return a.Echo.Start(address)
}

// StartH2CServer calls Bootstrap then starts an HTTP/2 cleartext server. It
// shadows Echo's promoted method, which would serve the bare Echo instance and
// bypass trappsec.
func (a *App) StartH2CServer(address string, h2s *http2.Server) error {
	a.Bootstrap()
	return a.Echo.StartH2CServer(address, h2s)
}

// StartTLS calls Bootstrap then starts an HTTPS server.
func (a *App) StartTLS(address string, certFile, keyFile any) error {
	a.Bootstrap()
	return a.Echo.StartTLS(address, certFile, keyFile)
}

// StartAutoTLS calls Bootstrap then starts a server with automatic TLS via Let's Encrypt.
func (a *App) StartAutoTLS(address string) error {
	a.Bootstrap()
	return a.Echo.StartAutoTLS(address)
}

// StartServer calls Bootstrap then starts a server using a custom http.Server.
func (a *App) StartServer(s *http.Server) error {
	a.Bootstrap()
	return a.Echo.StartServer(s)
}

// watchMiddleware inspects requests for honey fields on watched routes. Echo runs
// Use middleware after routing, so c.Path() carries the route pattern
// (e.g. /users/:id) rather than the raw URL.
func (in *echoIntegration) watchMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if watch, ok := in.watchIdx[c.Path()]; ok {
				c.Set(inspectedMarker, true)
				adapter.InspectWatch(in.ts, c.Request(), c, watch, in.maxBody.Get())
			}
			return next(c)
		}
	}
}

const inspectedMarker = "trappsec.inspected"

// preMiddleware catches requests that an earlier middleware (auth, rate
// limit, CSRF) rejected before the watch middleware ran. Echo has no
// pre-routing route lookup short of a second match, and inspecting before
// the Use chain would hide values that middleware stores with c.Set from
// IdentifyUser, so the request is inspected after the chain returns instead:
// by then routing has resolved c.Path() and the context carries whatever the
// middleware stored. The response of such a request is already decided, so
// there is nothing left to strip.
func (in *echoIntegration) preMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			err := next(c)
			if watch, ok := in.watchIdx[c.Path()]; ok && c.Get(inspectedMarker) == nil {
				adapter.InspectWatch(in.ts, c.Request(), c, watch, in.maxBody.Get())
			}
			return err
		}
	}
}
