// Package trappsechandler integrates trappsec with any net/http router: chi,
// gorilla/mux, httprouter, or anything else that is an http.Handler.
//
// Usage:
//
//	r := chi.NewRouter()
//	r.Get("/real-route", handler)
//	app := trappsechandler.InstallSentry(r, "my-service", "production")
//	app.MatchRoutes(func(req *http.Request) string {
//		return r.Find(chi.NewRouteContext(), req.Method, req.URL.Path)
//	})
//	app.Trap("/fake-config").Methods("GET").Intent("Reconnaissance").Respond(...)
//	http.ListenAndServe(":8080", app)
//
// The App wraps the router: it answers traps itself and inspects watched
// requests before handing them to the router. Always serve through the App;
// serving the router directly bypasses trappsec.
//
// Traps and watches are matched against the request path, with :id, {id},
// <id> and *rest segments matching any value. Without a RouteMatcher a
// trailing slash is ignored, as in Sentry.IsTrap; with one, a trap does not
// answer a path with a trailing slash, as chi and gorilla/mux do not. A router that can report the
// route a request matches should be given to MatchRoutes: then a real route
// that is at least as specific as a trap (POST /users/me next to a trap POST
// /users/{id}) wins over it, a trap that duplicates a real route fails loudly
// at Bootstrap, and watches apply only to requests the router serves from the
// watched route.
//
// Because the App runs before the router, IdentifyUser sees the request as it
// arrives (headers, cookies), not values that the router's middleware adds to
// its context.
//
// Traps are not routes on the router, so a trap path requested with a method
// the trap does not declare gets the router's answer for an unknown path
// (usually 404) where a real route would answer 405. Declare every method a
// real route at that path would plausibly accept.
package trappsechandler

import (
	"fmt"
	"net"
	"net/http"
	"strings"

	core "github.com/trappsec-dev/trappsec/packages/go"
	"github.com/trappsec-dev/trappsec/packages/go/internal/adapter"
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

// RouteMatcher reports the pattern of the route the router would serve r
// from, such as "/users/{id}", or "" when no route matches r (including when
// the path matches but the method does not).
type RouteMatcher func(r *http.Request) string

// App wraps an http.Handler and a trappsec Sentry. All Sentry methods (Trap,
// Watch, IdentifyUser, etc.) are promoted. Handler is the wrapped router.
type App struct {
	*core.Sentry
	Handler     http.Handler
	integration *handlerIntegration
}

// InstallSentry creates a Sentry, wraps the given handler and returns the *App
// to serve through.
func InstallSentry(h http.Handler, service, environment string) *App {
	return Use(core.NewSentry(service, environment), h)
}

// Use wraps the handler with an existing Sentry and returns the *App to serve
// through (app.ListenAndServe*, or app as an http.Handler). Traps and watches
// only become active through the returned App.
func Use(s *core.Sentry, h http.Handler) *App {
	adapter.InstallRequestAccessors(s, requestOf)
	return &App{Sentry: s, Handler: h, integration: &handlerIntegration{ts: s}}
}

func requestOf(req any) *http.Request {
	r, _ := req.(*http.Request)
	return r
}

// MatchRoutes tells the App how to ask the router which route a request
// matches. Call it before the first request (or Bootstrap). For chi:
//
//	app.MatchRoutes(func(req *http.Request) string {
//		return r.Find(chi.NewRouteContext(), req.Method, req.URL.Path)
//	})
//
// For gorilla/mux:
//
//	app.MatchRoutes(func(req *http.Request) string {
//		var m mux.RouteMatch
//		if !r.Match(req, &m) || m.MatchErr != nil || m.Route == nil {
//			return ""
//		}
//		tpl, _ := m.Route.GetPathTemplate()
//		return tpl
//	})
func (a *App) MatchRoutes(m RouteMatcher) *App {
	if a.integration.once.Done() {
		panic("trappsec: MatchRoutes called after Bootstrap; call it before serving")
	}
	a.integration.match = m
	return a
}

// SetMaxBodyBytes sets the largest request body that watch inspection buffers
// (default core.DefaultMaxBodyBytes, 1 MiB). Larger bodies pass through intact
// but uninspected. n <= 0 restores the default.
func (a *App) SetMaxBodyBytes(n int64) { a.integration.maxBody.Set(n) }

// Bootstrap builds the trap and watch indexes. It is idempotent and safe for
// concurrent use; it runs automatically on the first request and from
// ListenAndServe*/Serve*. Call it explicitly to fail fast at startup: with a
// RouteMatcher it panics if a trap duplicates a real route, and repeats the
// same panic on later calls.
func (a *App) Bootstrap() { a.integration.once.Do(a.integration.install) }

// IsTrap reports whether the App would answer r with a trap. Use it to let
// traps through middleware wrapped around the App that would otherwise reject
// them before they can answer, such as CSRF protection. With a RouteMatcher, a
// real route that only looks like a trap is never reported as one.
func (a *App) IsTrap(r *http.Request) bool {
	a.Bootstrap()
	if r == nil {
		return false
	}
	_, ok := a.integration.trapFor(r)
	return ok
}

// ServeHTTP answers traps, inspects watched requests, and hands everything
// else to the wrapped handler.
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.Bootstrap()
	in := a.integration
	if len(in.traps) > 0 {
		if trap, ok := in.trapFor(r); ok {
			body, cfg := adapter.TriggerTrapEvent(in.ts, r, trap)
			if cfg.MIMEType != "" {
				w.Header().Set("Content-Type", cfg.MIMEType)
			}
			w.WriteHeader(cfg.StatusCode)
			_, _ = w.Write(body)
			return
		}
	}
	if len(in.watches) > 0 {
		if watch, ok := in.watchFor(r); ok {
			adapter.InspectWatch(in.ts, r, r, watch, in.maxBody.Get())
		}
	}
	a.Handler.ServeHTTP(w, r)
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

// handlerIntegration indexes traps and watches so that a request costs one
// map lookup: literal paths are map keys, and only the patterns with
// parameter segments are matched one by one, as in Sentry.IsTrap.
type handlerIntegration struct {
	ts      *core.Sentry
	match   RouteMatcher
	traps   []trapRoute
	watches []watchRoute

	trapExact     map[string]map[string]int // literal path -> method -> index in traps
	trapPatterns  []int                     // traps with parameter segments
	watchByShape  map[string]int            // route shape -> index in watches (with a RouteMatcher)
	watchPatterns []int                     // watches with parameter segments (without one)

	maxBody adapter.MaxBody
	once    adapter.Once
}

type trapRoute struct {
	methods map[string]bool
	pat     pattern
	cfg     core.TrapConfig
}

type watchRoute struct {
	pat pattern
	cfg core.WatchConfig
}

func (in *handlerIntegration) install() {
	for _, t := range in.ts.Traps() {
		methods := make(map[string]bool, len(t.Methods))
		for _, m := range t.Methods {
			methods[strings.ToUpper(m)] = true
		}
		pat := parsePattern(t.Path)
		if in.match != nil {
			for m := range methods {
				if got := in.matchSample(m, pat); got != "" && parsePattern(got).shape() == pat.shape() {
					panic(fmt.Sprintf("trappsec: trap %s %s duplicates an existing route registered as %q; "+
						"rename the trap or remove the real route", m, t.Path, got))
				}
			}
		}
		in.traps = append(in.traps, trapRoute{methods: methods, pat: pat, cfg: t})
	}
	for _, w := range in.ts.Watches() {
		in.watches = append(in.watches, watchRoute{pat: parsePattern(w.Path), cfg: w})
	}

	in.trapExact = map[string]map[string]int{}
	for i, t := range in.traps {
		if !t.pat.literal() {
			in.trapPatterns = append(in.trapPatterns, i)
			continue
		}
		key := t.pat.shape()
		if in.trapExact[key] == nil {
			in.trapExact[key] = map[string]int{}
		}
		for m := range t.methods {
			in.trapExact[key][m] = i
		}
	}
	in.watchByShape = map[string]int{}
	for i, w := range in.watches {
		in.watchByShape[w.pat.shape()] = i
		if !w.pat.literal() {
			in.watchPatterns = append(in.watchPatterns, i)
		}
	}
	in.warnUnreachableWatches()
}

// warnUnreachableWatches logs every watch whose route the router does not
// serve: such a watch can never fire. It needs a RouteMatcher.
func (in *handlerIntegration) warnUnreachableWatches() {
	if in.match == nil {
		return
	}
	for _, w := range in.watches {
		served := false
		for _, m := range []string{"GET", "POST", "PUT", "PATCH", "DELETE"} {
			if got := in.matchSample(m, w.pat); got != "" && parsePattern(got).shape() == w.pat.shape() {
				served = true
				break
			}
		}
		if !served {
			in.ts.Logger().Printf("trappsec: watch %s matches no route on the router and will never fire "+
				"(watch paths are full route patterns, including mount prefixes)", w.cfg.Path)
		}
	}
}

// trapFor returns the most specific trap matching r, unless the router serves
// r from a real route at least as specific as that trap.
func (in *handlerIntegration) trapFor(r *http.Request) (core.TrapConfig, bool) {
	// Routers that report their routes (chi, gorilla/mux by default) treat a
	// trailing slash as a different path and answer it with 404, so a trap must
	// not answer it either: that difference would give the trap away.
	if in.match != nil && len(r.URL.Path) > 1 && strings.HasSuffix(r.URL.Path, "/") {
		return core.TrapConfig{}, false
	}
	method := strings.ToUpper(r.Method)
	segs := splitPath(r.URL.Path)
	// A literal trap is more specific than any pattern matching the same path.
	best, ok := in.trapExact[pathKey(segs)][method]
	if !ok {
		best = -1
		for _, i := range in.trapPatterns {
			t := in.traps[i]
			if t.methods[method] && t.pat.matches(segs) && (best < 0 || t.pat.compare(in.traps[best].pat) > 0) {
				best = i
			}
		}
	}
	if best < 0 {
		return core.TrapConfig{}, false
	}
	if in.match != nil {
		if got := in.match(r); got != "" && parsePattern(got).compare(in.traps[best].pat) >= 0 {
			return core.TrapConfig{}, false
		}
	}
	return in.traps[best].cfg, true
}

// watchFor returns the watch for r: with a RouteMatcher, the watch on the
// route the router matched; otherwise the most specific watch whose path
// matches the request path.
func (in *handlerIntegration) watchFor(r *http.Request) (core.WatchConfig, bool) {
	if in.match != nil {
		got := in.match(r)
		if got == "" {
			return core.WatchConfig{}, false
		}
		i, ok := in.watchByShape[parsePattern(got).shape()]
		if !ok {
			return core.WatchConfig{}, false
		}
		return in.watches[i].cfg, true
	}
	segs := splitPath(r.URL.Path)
	best, ok := in.watchByShape[pathKey(segs)]
	if !ok || !in.watches[best].pat.literal() {
		best = -1
		for _, i := range in.watchPatterns {
			w := in.watches[i]
			if w.pat.matches(segs) && (best < 0 || w.pat.compare(in.watches[best].pat) > 0) {
				best = i
			}
		}
	}
	if best < 0 {
		return core.WatchConfig{}, false
	}
	return in.watches[best].cfg, true
}

// sampleRequest builds a request whose path the pattern matches, with every
// parameter segment filled in. It returns nil if the path is not a valid URL.
func sampleRequest(method string, p pattern) *http.Request {
	var b strings.Builder
	for _, s := range p.segs {
		b.WriteByte('/')
		if s.kind == segLit {
			b.WriteString(s.lit)
		} else {
			b.WriteString("1") // digits satisfy most parameter regexes ({id:[0-9]+})
		}
	}
	if b.Len() == 0 {
		b.WriteByte('/')
	}
	r, err := http.NewRequest(method, b.String(), nil)
	if err != nil {
		return nil
	}
	return r
}

// matchSample asks the router which route serves a sample request for p.
func (in *handlerIntegration) matchSample(method string, p pattern) string {
	r := sampleRequest(method, p)
	if r == nil {
		return ""
	}
	return in.match(r)
}
