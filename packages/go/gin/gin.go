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
// are. Install trappsec first to get full middleware context. Routes added to
// a group created before InstallSentry never get the watch middleware either;
// App.ServeHTTP inspects them the same way, so they are covered too. Which
// routes lack the middleware is decided once, at bootstrap, from the engine's
// route table, so every request (including the first) is inspected in exactly
// one place, and an app with no such routes pays no per-request routing cost.
package trappsecgin

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	core "github.com/trappsec-dev/trappsec/packages/go"
	"github.com/trappsec-dev/trappsec/packages/go/internal/adapter"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"net"
	"net/http"
	"os"
	"reflect"
	"strings"
	"sync"
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
	in := &ginIntegration{ts: s, engine: engine}
	adapter.InstallRequestAccessors(s, requestOf)

	adapter.SetBodyResolver(s, func(body any, req any) any {
		if fn, ok := body.(func(*gin.Context) any); ok {
			if c, ok := req.(*gin.Context); ok {
				return fn(c)
			}
		}
		return body
	})

	mw := in.watchMiddleware()
	in.marker = reflect.ValueOf(mw).Pointer()
	engine.Use(mw)

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

type ginIntegration struct {
	ts     *core.Sentry
	engine *gin.Engine

	watchIdx map[string]core.WatchConfig
	trapIdx  map[string]bool // "METHOD /pattern" of every trap route
	// uncovered holds "METHOD /pattern" of every watched route whose handler
	// chain lacks the watch middleware (registered before InstallSentry, or on
	// a group created before it). ServeHTTP inspects exactly those.
	uncovered map[string]bool
	shadow    *gin.Engine // matcher over all routes; nil when uncovered is empty
	marker    uintptr     // code pointer of the watch middleware, to recognise it in a chain
	maxBody   adapter.MaxBody
	once      adapter.Once
}

// Bootstrap registers trap routes and builds the watch index. It is idempotent and
// safe for concurrent use, and runs automatically on the first request and from
// Run*. It panics (with a clear message) if a trap duplicates an existing route;
// later calls repeat the same panic.
func (a *App) Bootstrap() { a.integration.once.Do(a.install) }

func (a *App) install() {
	in := a.integration
	idx := make(map[string]core.WatchConfig)
	for _, w := range in.ts.Watches() {
		idx[w.Path] = w
	}

	existing := map[string]bool{}
	for _, ri := range a.Engine.Routes() {
		existing[ri.Method+" "+ri.Path] = true
	}
	// Register each trap as a real Gin route for each declared method.
	trapIdx := map[string]bool{}
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
			trapIdx[method+" "+trap.Path] = true
		}
	}
	in.trapIdx = trapIdx

	in.watchIdx = idx

	routes := a.Engine.Routes()
	paths := make([]string, 0, len(routes))
	for _, ri := range routes {
		paths = append(paths, ri.Path)
	}
	adapter.WarnUnmatchedWatches(in.ts, idx, paths)

	// Decide, once, which watched routes the middleware cannot reach.
	chains, known := in.scanChains(len(routes))
	in.uncovered = map[string]bool{}
	for _, ri := range routes {
		key := ri.Method + " " + ri.Path
		if _, ok := idx[ri.Path]; ok && !(known && chains[key]) {
			in.uncovered[key] = true
		}
	}
	if len(in.uncovered) > 0 {
		in.shadow = in.buildShadow(routes)
	}
}

// scanChains reports, for every route, whether its handler chain contains the
// watch middleware. gin exposes only a route's last handler publicly, so this
// reads the engine's route trees by reflection. known is false (and the caller
// falls back to inspecting every watched route in ServeHTTP) if gin's internal
// layout is not what this code expects.
func (in *ginIntegration) scanChains(wantRoutes int) (chains map[string]bool, known bool) {
	defer func() {
		if recover() != nil {
			chains, known = nil, false
		}
	}()
	trees := reflect.ValueOf(in.engine).Elem().FieldByName("trees")
	chains = map[string]bool{}
	var walk func(method string, n reflect.Value)
	walk = func(method string, n reflect.Value) {
		n = n.Elem()
		if h := n.FieldByName("handlers"); h.Len() > 0 {
			has := false
			for i := 0; i < h.Len(); i++ {
				if h.Index(i).Pointer() == in.marker {
					has = true
				}
			}
			chains[method+" "+n.FieldByName("fullPath").String()] = has
		}
		ch := n.FieldByName("children")
		for i := 0; i < ch.Len(); i++ {
			walk(method, ch.Index(i))
		}
	}
	for i := 0; i < trees.Len(); i++ {
		t := trees.Index(i)
		walk(t.FieldByName("method").String(), t.FieldByName("root"))
	}
	return chains, len(chains) == wantRoutes
}

// IsTrap reports whether the request targets a trap. Use it to let traps
// through middleware that would otherwise reject them before they can answer,
// such as CSRF protection:
//
//	engine.Use(func(c *gin.Context) {
//		if app.IsTrap(c) {
//			c.Next()
//			return
//		}
//		csrfMiddleware(c)
//	})
//
// It bootstraps lazily. Once Gin has routed the request it answers from the
// matched route, so a real route that only looks like a trap (POST /users/me
// next to a trap POST /users/:id) is never reported as one; otherwise it
// falls back to Sentry.IsTrap's path matching.
func (a *App) IsTrap(c *gin.Context) bool {
	a.Bootstrap()
	if route := c.FullPath(); route != "" {
		return a.integration.trapIdx[strings.ToUpper(c.Request.Method)+" "+route]
	}
	return a.Sentry.IsTrap(c)
}

// SetMaxBodyBytes sets the largest request body that watch inspection buffers
// (default 1 MiB). Larger bodies pass through intact but uninspected.
func (a *App) SetMaxBodyBytes(n int64) { a.integration.maxBody.Set(n) }

const patternHeader = "X-Trappsec-Pattern"

// buildShadow mirrors the engine's route table into a handler-less engine so the
// matched route pattern can be resolved with gin's own matching rules before the
// real engine dispatches. In gin debug mode the mirrored routes are echoed to the
// log a second time: silencing that would mean swapping gin's global
// DebugPrintRouteFunc, which races with other goroutines registering routes.
func (in *ginIntegration) buildShadow(routes gin.RoutesInfo) *gin.Engine {
	sh := gin.New()
	e := in.engine
	sh.RedirectTrailingSlash = e.RedirectTrailingSlash
	sh.RedirectFixedPath = e.RedirectFixedPath
	sh.HandleMethodNotAllowed = false
	sh.UseRawPath = e.UseRawPath
	sh.UnescapePathValues = e.UnescapePathValues
	sh.RemoveExtraSlash = e.RemoveExtraSlash
	for _, ri := range routes {
		pattern := []string{ri.Path} // allocated once, so a match allocates nothing
		sh.Handle(ri.Method, ri.Path, func(c *gin.Context) { c.Writer.Header()[patternHeader] = pattern })
	}
	return sh
}

// probeWriter receives the shadow engine's answer: the matched pattern in a header.
type probeWriter struct{ h http.Header }

func (p *probeWriter) Header() http.Header         { return p.h }
func (p *probeWriter) Write(b []byte) (int, error) { return len(b), nil }
func (p *probeWriter) WriteHeader(int)             {}

var probePool = sync.Pool{New: func() any { return &probeWriter{h: http.Header{}} }}

// ginTrapHandler returns a Gin handler for a trap route.
func ginTrapHandler(ts *core.Sentry, trap core.TrapConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		body, cfg := adapter.TriggerTrapEvent(ts, c, trap)
		// Not c.Data: it sets Content-Length itself, which net/http then writes
		// before Date, unlike the c.JSON / c.String responses of real routes.
		c.Status(cfg.StatusCode)
		if h := c.Writer.Header(); len(h["Content-Type"]) == 0 {
			h["Content-Type"] = []string{cfg.MIMEType}
		}
		if !bodyAllowedForStatus(cfg.StatusCode) {
			c.Writer.WriteHeaderNow()
			return
		}
		_, _ = c.Writer.Write(body)
	}
}

// bodyAllowedForStatus mirrors Gin's rule for c.Render.
func bodyAllowedForStatus(status int) bool {
	switch {
	case status >= 100 && status <= 199, status == http.StatusNoContent, status == http.StatusNotModified:
		return false
	}
	return true
}

type inspectedKey struct{}

// ServeHTTP bootstraps lazily, inspects watched routes the engine.Use
// middleware cannot reach (registered before InstallSentry, or added to a
// group created before it), then dispatches to the engine.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.Bootstrap()
	in := a.integration
	if in.shadow != nil {
		pw := probePool.Get().(*probeWriter)
		in.shadow.ServeHTTP(pw, r)
		pat := pw.h.Get(patternHeader)
		clear(pw.h)
		probePool.Put(pw)
		if pat != "" {
			if watch, ok := in.watchIdx[pat]; ok && in.uncovered[r.Method+" "+pat] {
				c := gin.CreateTestContextOnly(&probeWriter{h: http.Header{}}, in.engine)
				c.Request = r
				adapter.InspectWatch(in.ts, r, c, watch, in.maxBody.Get())
				r = r.WithContext(context.WithValue(r.Context(), inspectedKey{}, true))
			}
		}
	}
	a.Engine.ServeHTTP(w, r)
}

// Handler returns the http.Handler to serve: the App itself, wrapped for
// HTTP/2 cleartext when the engine's UseH2C is set (as gin's own Handler does).
// Unlike the promoted Engine.Handler it never returns the bare engine, which
// would bypass trappsec.
func (a *App) Handler() http.Handler {
	if !a.Engine.UseH2C {
		return a
	}
	return h2c.NewHandler(a, &http2.Server{})
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
	return http.ListenAndServe(resolveAddr(addr), a.Handler())
}

// RunTLS calls Bootstrap then starts an HTTPS server.
func (a *App) RunTLS(addr, certFile, keyFile string) error {
	a.Bootstrap()
	return http.ListenAndServeTLS(addr, certFile, keyFile, a.Handler())
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
	return http.Serve(l, a.Handler())
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
	return http.Serve(l, a.Handler())
}

// RunListener calls Bootstrap then starts a server using a custom net.Listener.
func (a *App) RunListener(listener net.Listener) error {
	a.Bootstrap()
	return http.Serve(listener, a.Handler())
}

// watchMiddleware inspects requests for honey fields on watched routes registered
// after InstallSentry. It runs after route matching so c.FullPath() carries the
// route pattern (e.g. /users/:id) rather than the raw URL. Routes whose chain
// lacks it (see ginIntegration.uncovered) are handled by App.ServeHTTP instead.
func (in *ginIntegration) watchMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if in.once.Done() && in.watchIdx != nil {
			path := c.FullPath()
			if path == "" {
				path = c.Request.URL.Path
			}
			if watch, ok := in.watchIdx[path]; ok && c.Request.Context().Value(inspectedKey{}) == nil {
				adapter.InspectWatch(in.ts, c.Request, c, watch, in.maxBody.Get())
			}
		}
		c.Next()
	}
}
