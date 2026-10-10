// Package trappsececho integrates trappsec with the Echo web framework.
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
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
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

	if s.Identity.IP == nil {
		s.Identity.IP = defaultIP
	}

	s.Request.Path = func(req any) string {
		if r := requestOf(req); r != nil {
			return r.URL.Path
		}
		return ""
	}
	s.Request.UserAgent = func(req any) string {
		if r := requestOf(req); r != nil {
			return r.UserAgent()
		}
		return ""
	}
	s.Request.Method = func(req any) string {
		if r := requestOf(req); r != nil {
			return r.Method
		}
		return ""
	}
	s.Request.Context = func(req any) context.Context {
		if r := requestOf(req); r != nil {
			return r.Context()
		}
		return context.Background()
	}

	s.SetBodyResolver(func(body any, req any) any {
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

// defaultIP returns the connection's RemoteAddr host. It deliberately ignores
// X-Forwarded-For / X-Real-IP (spoofable; echo's RealIP trusts them by default).
// Use OverrideSourceIP, e.g. with c.RealIP() plus e.IPExtractor, behind a trusted proxy.
func defaultIP(req any) string {
	r := requestOf(req)
	if r == nil {
		return "0.0.0.0"
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

type echoIntegration struct {
	ts       *core.Sentry
	watchIdx map[string]core.WatchConfig
	maxBody  int64

	done atomic.Bool
	mu   sync.Mutex
	err  any
}

// Bootstrap registers trap routes and the watch middleware and builds the watch
// index. It is idempotent and safe for concurrent use, and runs automatically on
// the first request and from Start*. It panics with a clear message if a trap
// duplicates an existing route (instead of silently replacing it); later calls
// repeat the same panic.
func (a *App) Bootstrap() {
	in := a.integration
	if in.done.Load() {
		if in.err != nil {
			panic(in.err)
		}
		return
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.done.Load() {
		if in.err != nil {
			panic(in.err)
		}
		return
	}
	defer func() {
		if p := recover(); p != nil {
			in.err = p
			in.done.Store(true)
			panic(p)
		}
		in.done.Store(true)
	}()

	idx := make(map[string]core.WatchConfig)
	for _, w := range in.ts.Watches() {
		idx[w.Path] = w
	}

	existing := map[string]bool{}
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
		}
	}
	in.watchIdx = idx
	a.Echo.Use(in.watchMiddleware())
}

// SetMaxBodyBytes sets the largest request body that watch inspection buffers
// (default 1 MiB). Larger bodies pass through intact but uninspected.
func (a *App) SetMaxBodyBytes(n int64) { atomic.StoreInt64(&a.integration.maxBody, n) }

// echoTrapHandler returns an Echo handler for a trap route.
func echoTrapHandler(ts *core.Sentry, trap core.TrapConfig) echo.HandlerFunc {
	return func(c echo.Context) error {
		body, cfg := ts.TriggerTrapEvent(c, trap)
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
				core.InspectWatch(in.ts, c.Request(), c, watch, atomic.LoadInt64(&in.maxBody))
			}
			return next(c)
		}
	}
}
