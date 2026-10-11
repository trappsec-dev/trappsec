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
	"context"
	"fmt"
	core "github.com/trappsec-dev/trappsec/packages/go"
	"github.com/trappsec-dev/trappsec/packages/go/internal/adapter"
	"net"
	"net/http"
	"net/url"
	"regexp"
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

// Bootstrap installs trap routes and builds the watch index. It is idempotent and
// safe for concurrent use; it runs automatically on the first request (ServeHTTP)
// and from ListenAndServe*/Serve*. Call it explicitly to fail fast on route
// conflicts at startup. It panics if a trap would shadow or duplicate an existing
// route; the same panic is repeated on later calls (the App is never left
// half-installed and silently unprotected).
func (a *App) Bootstrap() { a.integration.bootstrap(a) }

// IsTrap reports whether the mux would route r to a trap. Use it to let traps
// through middleware that would otherwise reject them before they can answer,
// such as CSRF protection. It bootstraps lazily, and asks the mux which
// pattern matches, so a real route that only looks like a trap (POST /users/me
// next to a trap POST /users/{id}) is never reported as one.
func (a *App) IsTrap(r *http.Request) bool {
	a.Bootstrap()
	if r == nil {
		return false
	}
	_, pattern := a.ServeMux.Handler(r)
	return a.integration.trapIdx[pattern]
}

// SetMaxBodyBytes sets the largest request body that watch inspection buffers
// (default core.DefaultMaxBodyBytes, 1 MiB). Larger bodies pass through intact
// but uninspected. n <= 0 restores the default.
func (a *App) SetMaxBodyBytes(n int64) { atomic.StoreInt64(&a.integration.maxBody, n) }

// InstallSentry creates a Sentry, wires trappsec onto the given ServeMux, and returns
// an *App that embeds both. Use app.ListenAndServe() (not http.ListenAndServe) to start
// the server — this ensures trap routes are registered before requests are served.
//
// Trap routes are registered using Go 1.22+ method-qualified patterns ("GET /path"),
// giving them the same 405 Method Not Allowed behaviour as real routes registered with
// method patterns.
func InstallSentry(mux *http.ServeMux, service, environment string) *App {
	return Use(core.NewSentry(service, environment), mux)
}

// Use wires an existing Sentry onto the ServeMux and returns the *App to serve
// through (app.ListenAndServe*, or app as an http.Handler). Traps and watches
// only become active through the returned App.
func Use(s *core.Sentry, mux *http.ServeMux) *App {
	in := &netHTTPIntegration{ts: s, mux: mux}

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
	s.Request.Context = func(req any) context.Context {
		r, _ := req.(*http.Request)
		if r == nil {
			return context.Background()
		}
		return r.Context()
	}

	return &App{Sentry: s, ServeMux: mux, integration: in}
}

type netHTTPIntegration struct {
	ts       *core.Sentry
	mux      *http.ServeMux
	watchIdx map[string]core.WatchConfig
	trapIdx  map[string]bool // registered trap patterns, "METHOD /path"
	maxBody  int64

	done atomic.Bool
	mu   sync.Mutex
	err  any
}

func (in *netHTTPIntegration) bootstrap(a *App) {
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
		// Mark done (even on failure) so concurrent callers observe the same
		// failure instead of re-running a partially applied install.
		if p := recover(); p != nil {
			in.err = p
			in.done.Store(true)
			panic(p)
		}
		in.done.Store(true)
	}()

	idx := make(map[string]core.WatchConfig)
	for _, w := range in.ts.Watches() {
		idx[patternPath(w.Path)] = w
	}

	// Register each trap as a real route using Go 1.22+ method-qualified patterns.
	trapIdx := map[string]bool{}
	for _, trap := range in.ts.Traps() {
		t := trap
		for _, method := range trap.Methods {
			method = strings.ToUpper(method)
			pattern := method + " " + trap.Path
			in.checkConflict(method, trap.Path)
			trapIdx[pattern] = true
			in.register(pattern, func(w http.ResponseWriter, r *http.Request) {
				body, cfg := adapter.TriggerTrapEvent(in.ts, r, t)
				if cfg.MIMEType != "" {
					w.Header().Set("Content-Type", cfg.MIMEType)
				}
				w.WriteHeader(cfg.StatusCode)
				_, _ = w.Write(body)
			})
		}
	}
	in.watchIdx = idx
	in.trapIdx = trapIdx
	in.warnUnreachableWatches()
}

// warnUnreachableWatches logs every watch whose path no route on this mux
// serves: such a watch can never fire. The usual cause is a route inside a
// sub-mux mounted with Handle("/prefix/", ...), which this mux only knows by
// the mount pattern.
func (in *netHTTPIntegration) warnUnreachableWatches() {
	for _, w := range in.ts.Watches() {
		want := patternPath(w.Path)
		u, err := url.Parse(wildcardRe.ReplaceAllString(want, "x"))
		if err != nil {
			continue
		}
		served, nearest := false, ""
		for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
			_, got := in.mux.Handler(&http.Request{Method: m, URL: u, Header: http.Header{}})
			if patternPath(got) == want {
				served = true
				break
			}
			if got != "" && nearest == "" {
				nearest = got
			}
		}
		if served {
			continue
		}
		hint := ""
		if nearest != "" {
			hint = fmt.Sprintf(" (requests to it are served by %q; if that mounts a sub-mux, watch %q or register the routes on the App)",
				nearest, patternPath(nearest))
		}
		in.ts.Logger().Printf("trappsec: watch %s matches no route on this mux and will never fire%s", w.Path, hint)
	}
}

func (in *netHTTPIntegration) register(pattern string, h http.HandlerFunc) {
	defer func() {
		if p := recover(); p != nil {
			panic(fmt.Sprintf("trappsec: cannot register trap %q: %v", pattern, p))
		}
	}()
	in.mux.HandleFunc(pattern, h)
}

var wildcardRe = regexp.MustCompile(`\{[^}]*\}`)

// patternPath reduces a ServeMux pattern ("[METHOD ][HOST]/path") to its path part.
func patternPath(p string) string {
	if i := strings.IndexByte(p, ' '); i != -1 && i < strings.IndexByte(p+"/", '/') {
		p = strings.TrimLeft(p[i+1:], " \t")
	}
	if i := strings.IndexByte(p, '/'); i > 0 {
		p = p[i:] // strip host
	}
	return p
}

// checkConflict panics if the mux already has a handler for exactly the trap's
// path (any method, any host qualifier): registering the more specific
// "METHOD /path" pattern would silently override it.
func (in *netHTTPIntegration) checkConflict(method, path string) {
	sample := wildcardRe.ReplaceAllString(path, "x")
	if !strings.HasPrefix(sample, "/") {
		sample = patternPath(sample)
	}
	u, err := url.Parse(sample)
	if err != nil {
		return
	}
	req := &http.Request{Method: method, URL: u, Header: http.Header{}}
	if _, existing := in.mux.Handler(req); existing != "" && patternPath(existing) == patternPath(path) {
		panic(fmt.Sprintf("trappsec: trap %s %s conflicts with an existing route registered as %q; "+
			"rename the trap or remove the real route", method, path, existing))
	}
}

// ServeHTTP shadows *http.ServeMux's ServeHTTP to inject watch inspection before
// the request is dispatched, bootstrapping lazily on the first request. Pass app
// (not app.ServeMux) as the http.Handler when constructing a custom http.Server or
// httptest server so traps and watches are active.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.Bootstrap()
	// Resolve the matched route pattern before dispatch so watches can use it.
	_, pattern := a.ServeMux.Handler(r)
	if watch, ok := a.integration.watchIdx[patternPath(pattern)]; ok {
		adapter.InspectWatch(a.integration.ts, r, r, watch, atomic.LoadInt64(&a.integration.maxBody))
	}
	a.ServeMux.ServeHTTP(w, r)
}

// ListenAndServe calls Bootstrap then starts the HTTP server.
func (a *App) ListenAndServe(addr string) error {
	a.Bootstrap()
	return http.ListenAndServe(addr, a)
}

// ListenAndServeTLS calls Bootstrap then starts an HTTPS server.
func (a *App) ListenAndServeTLS(addr, certFile, keyFile string) error {
	a.Bootstrap()
	return http.ListenAndServeTLS(addr, certFile, keyFile, a)
}

// Serve calls Bootstrap then accepts incoming connections on the given listener.
func (a *App) Serve(l net.Listener) error {
	a.Bootstrap()
	return http.Serve(l, a)
}

// ServeTLS calls Bootstrap then accepts TLS connections on the given listener.
func (a *App) ServeTLS(l net.Listener, certFile, keyFile string) error {
	a.Bootstrap()
	return http.ServeTLS(l, a, certFile, keyFile)
}
