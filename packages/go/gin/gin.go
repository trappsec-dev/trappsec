// Package trappsecgin integrates trappsec with the Gin web framework.
//
// Usage:
//
//	r := gin.New()
//	app := trappsecgin.InstallSentry(r, "my-service", "production")
//	app.GET("/real-route", handler)
//	app.Trap("/fake-config").Methods("GET").Intent("Reconnaissance").Respond(...)
//	app.Run(":8080")
//
// Always serve through the returned *App (app.Run, or app as the http.Handler for
// http.Server / httptest). The App bootstraps lazily on the first request, so
// custom servers are protected too. Serving the raw *gin.Engine bypasses trappsec.
//
// Routes registered before InstallSentry are covered: gin's Use only applies to
// routes registered afterwards, so App.ServeHTTP inspects those routes itself
// (resolving the route pattern with a shadow router). For those pre-install
// routes IdentifyUser runs before the application's middleware chain, so values
// stored with c.Set by app middleware are not visible to it; headers and cookies
// are. Install trappsec first to get full middleware context. Route groups
// created (not just routes registered) before InstallSentry also lack the watch
// middleware and are not covered; create groups after InstallSentry.
package trappsecgin

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	core "github.com/trappsec-dev/trappsec/packages/go"
	"net"
	"net/http"
	"os"
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

// App wraps a Gin engine and a trappsec Sentry. All Gin engine methods (GET, POST,
// Use, Group, NoRoute, etc.) and all Sentry methods (Trap, Watch, IdentifyUser, etc.)
// are promoted directly. ServeHTTP and the Run* methods are shadowed to bootstrap
// trappsec and to inspect routes registered before InstallSentry.
type App struct {
	*core.Sentry
	*gin.Engine
	integration *ginIntegration
}

// InstallSentry creates a Sentry, wires trappsec onto the given Gin engine and
// returns an *App that embeds both.
func InstallSentry(engine *gin.Engine, service, environment string) *App {
	return Use(core.NewSentry(service, environment), engine)
}

// Use wires an existing Sentry onto the engine and returns the *App to serve
// through (app.Run*, or app as an http.Handler). Traps and watches only become
// active through the returned App.
func Use(s *core.Sentry, engine *gin.Engine) *App {
	in := &ginIntegration{ts: s, engine: engine, preInstall: map[string]bool{}}
	for _, ri := range engine.Routes() {
		in.preInstall[ri.Method+" "+ri.Path] = true
	}

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

func requestOf(req any) *http.Request {
	switch t := req.(type) {
	case *gin.Context:
		if t != nil {
			return t.Request
		}
	case *http.Request:
		return t
	}
	return nil
}

// defaultIP returns the connection's RemoteAddr host. It deliberately ignores
// X-Forwarded-For / X-Real-IP (spoofable); use OverrideSourceIP, or c.ClientIP()
// with engine.SetTrustedProxies, if you sit behind a trusted proxy.
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

type ginIntegration struct {
	ts     *core.Sentry
	engine *gin.Engine

	watchIdx   map[string]core.WatchConfig
	preInstall map[string]bool // "METHOD /pattern" registered before InstallSentry
	shadow     *gin.Engine     // matcher over all routes, for pre-install routes
	maxBody    int64

	done atomic.Bool
	mu   sync.Mutex
	err  any
}

// Bootstrap registers trap routes and builds the watch index. It is idempotent and
// safe for concurrent use, and runs automatically on the first request and from
// Run*. It panics (with a clear message) if a trap duplicates an existing route;
// later calls repeat the same panic.
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
	for _, ri := range a.Engine.Routes() {
		existing[ri.Method+" "+ri.Path] = true
	}
	// Register each trap as a real Gin route for each declared method.
	for _, trap := range in.ts.Traps() {
		t := trap
		for _, method := range trap.Methods {
			method = strings.ToUpper(method)
			if existing[method+" "+trap.Path] {
				panic(fmt.Sprintf("trappsec: trap %s %s duplicates an existing route; "+
					"rename the trap or remove the real route", method, trap.Path))
			}
			func() {
				defer func() {
					if p := recover(); p != nil {
						panic(fmt.Sprintf("trappsec: cannot register trap %s %s: %v", method, trap.Path, p))
					}
				}()
				a.Engine.Handle(method, trap.Path, ginTrapHandler(in.ts, t))
			}()
			existing[method+" "+trap.Path] = true
		}
	}

	if len(in.preInstall) > 0 && len(idx) > 0 {
		in.shadow = in.buildShadow()
	}
	in.watchIdx = idx
}

// SetMaxBodyBytes sets the largest request body that watch inspection buffers
// (default 1 MiB). Larger bodies pass through intact but uninspected.
func (a *App) SetMaxBodyBytes(n int64) { atomic.StoreInt64(&a.integration.maxBody, n) }

const patternHeader = "X-Trappsec-Pattern"

var shadowMu sync.Mutex

// buildShadow mirrors the engine's route table into a handler-less engine so the
// matched route pattern can be resolved with gin's own matching rules before the
// real engine dispatches.
func (in *ginIntegration) buildShadow() *gin.Engine {
	sh := gin.New()
	e := in.engine
	sh.RedirectTrailingSlash = e.RedirectTrailingSlash
	sh.RedirectFixedPath = e.RedirectFixedPath
	sh.HandleMethodNotAllowed = false
	sh.UseRawPath = e.UseRawPath
	sh.UnescapePathValues = e.UnescapePathValues
	sh.RemoveExtraSlash = e.RemoveExtraSlash
	h := func(c *gin.Context) { c.Writer.Header().Set(patternHeader, c.FullPath()) }

	shadowMu.Lock()
	prev := gin.DebugPrintRouteFunc
	gin.DebugPrintRouteFunc = func(string, string, string, int) {}
	defer func() { gin.DebugPrintRouteFunc = prev; shadowMu.Unlock() }()
	for _, ri := range e.Routes() {
		sh.Handle(ri.Method, ri.Path, h)
	}
	return sh
}

type probeWriter struct{ h http.Header }

func (p *probeWriter) Header() http.Header         { return p.h }
func (p *probeWriter) Write(b []byte) (int, error) { return len(b), nil }
func (p *probeWriter) WriteHeader(int)             {}

// ginTrapHandler returns a Gin handler for a trap route.
func ginTrapHandler(ts *core.Sentry, trap core.TrapConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		body, cfg := ts.TriggerTrapEvent(c, trap)
		c.Data(cfg.StatusCode, cfg.MIMEType, body)
	}
}

// ServeHTTP bootstraps lazily, inspects routes registered before InstallSentry
// (which engine.Use middleware cannot reach), then dispatches to the engine.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.Bootstrap()
	in := a.integration
	if in.shadow != nil {
		pw := &probeWriter{h: http.Header{}}
		in.shadow.ServeHTTP(pw, r)
		if pat := pw.h.Get(patternHeader); pat != "" && in.preInstall[r.Method+" "+pat] {
			if watch, ok := in.watchIdx[pat]; ok {
				c := gin.CreateTestContextOnly(&probeWriter{h: http.Header{}}, in.engine)
				c.Request = r
				core.InspectWatch(in.ts, r, c, watch, atomic.LoadInt64(&in.maxBody))
			}
		}
	}
	a.Engine.ServeHTTP(w, r)
}

func resolveAddr(addr []string) string {
	switch len(addr) {
	case 0:
		if p := os.Getenv("PORT"); p != "" {
			return ":" + p
		}
		return ":8080"
	case 1:
		return addr[0]
	}
	panic("too many parameters")
}

// Run calls Bootstrap then starts the HTTP server (serving through the App).
func (a *App) Run(addr ...string) error {
	a.Bootstrap()
	return http.ListenAndServe(resolveAddr(addr), a)
}

// RunTLS calls Bootstrap then starts an HTTPS server.
func (a *App) RunTLS(addr, certFile, keyFile string) error {
	a.Bootstrap()
	return http.ListenAndServeTLS(addr, certFile, keyFile, a)
}

// RunUnix calls Bootstrap then starts a Unix socket server.
func (a *App) RunUnix(file string) error {
	a.Bootstrap()
	_ = os.Remove(file)
	l, err := net.Listen("unix", file)
	if err != nil {
		return err
	}
	defer l.Close()
	defer os.Remove(file)
	return http.Serve(l, a)
}

// RunFd calls Bootstrap then starts a server using a file descriptor.
func (a *App) RunFd(fd int) error {
	a.Bootstrap()
	f := os.NewFile(uintptr(fd), fmt.Sprintf("fd@%d", fd))
	l, err := net.FileListener(f)
	if err != nil {
		return err
	}
	defer l.Close()
	return http.Serve(l, a)
}

// RunListener calls Bootstrap then starts a server using a custom net.Listener.
func (a *App) RunListener(listener net.Listener) error {
	a.Bootstrap()
	return http.Serve(listener, a)
}

// watchMiddleware inspects requests for honey fields on watched routes registered
// after InstallSentry. It runs after route matching so c.FullPath() carries the
// route pattern (e.g. /users/:id) rather than the raw URL. Routes registered
// before InstallSentry are handled by App.ServeHTTP instead.
func (in *ginIntegration) watchMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if in.done.Load() && in.watchIdx != nil {
			path := c.FullPath()
			if path == "" {
				path = c.Request.URL.Path
			}
			if watch, ok := in.watchIdx[path]; ok && !in.preInstall[c.Request.Method+" "+path] {
				core.InspectWatch(in.ts, c.Request, c, watch, atomic.LoadInt64(&in.maxBody))
			}
		}
		c.Next()
	}
}
