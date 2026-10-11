// Package adapter is the API the framework adapters (nethttp, gin, echo) use
// to drive a Sentry. It is internal so that it is not part of the
// application-facing API.
package adapter

import (
	"context"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	core "github.com/trappsec-dev/trappsec/packages/go"
	"github.com/trappsec-dev/trappsec/packages/go/internal/hooks"
)

// InspectWatch applies a watch to the request: it detects and strips honey
// fields in the query and body and emits a watch_hit event.
func InspectWatch(s *core.Sentry, r *http.Request, reqObj any, watch core.WatchConfig, maxBody int64) {
	hooks.InspectWatch(s, r, reqObj, watch, maxBody)
}

// TriggerTrapEvent emits a trap_hit event and returns the response to send.
func TriggerTrapEvent(s *core.Sentry, req any, trap core.TrapConfig) ([]byte, core.ResponseTemplate) {
	payload, cfg := hooks.TriggerTrapEvent(s, req, trap)
	return payload, cfg.(core.ResponseTemplate)
}

// SetBodyResolver registers the adapter's resolver for framework-typed
// dynamic response bodies (e.g. func(*gin.Context) any).
func SetBodyResolver(s *core.Sentry, fn func(body any, req any) any) {
	hooks.SetBodyResolver(s, fn)
}

// Once runs an adapter's bootstrap exactly once. Unlike sync.Once it records a
// panic and replays it on every later call, so an App whose bootstrap failed
// (e.g. a trap duplicates a route) is never left half-installed and silently
// unprotected. The zero value is ready to use.
type Once struct {
	done atomic.Bool
	mu   sync.Mutex
	err  any
}

// Do runs f if it has not run yet. Concurrent callers wait for the first call
// to finish and observe its outcome.
func (o *Once) Do(f func()) {
	if o.done.Load() {
		o.replay()
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.done.Load() {
		o.replay()
		return
	}
	defer func() {
		// Mark done (even on failure) so concurrent callers observe the same
		// failure instead of re-running a partially applied install.
		if p := recover(); p != nil {
			o.err = p
			o.done.Store(true)
			panic(p)
		}
		o.done.Store(true)
	}()
	f()
}

// Done reports whether Do has completed (successfully or not).
func (o *Once) Done() bool { return o.done.Load() }

func (o *Once) replay() {
	if o.err != nil {
		panic(o.err)
	}
}

// MaxBody stores the SetMaxBodyBytes limit. The zero value means "default".
type MaxBody struct{ n atomic.Int64 }

// Set stores the limit.
func (m *MaxBody) Set(n int64) { m.n.Store(n) }

// Get returns the stored limit.
func (m *MaxBody) Get() int64 { return m.n.Load() }

// InstallRequestAccessors points the Sentry's request extractors (path, user
// agent, method, context) and, unless the application set one, the source-IP
// resolver at the *http.Request that requestOf finds inside the framework's
// request value. The default IP is the connection's RemoteAddr host: it
// deliberately ignores X-Forwarded-For / X-Real-IP (spoofable).
func InstallRequestAccessors(s *core.Sentry, requestOf func(any) *http.Request) {
	if s.Identity.IP == nil {
		s.Identity.IP = func(req any) string {
			r := requestOf(req)
			if r == nil {
				return "0.0.0.0"
			}
			if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
				return host
			}
			return r.RemoteAddr
		}
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
}

// WarnUnmatchedWatches logs every watch whose path is not among the registered
// route patterns: such a watch can never fire.
func WarnUnmatchedWatches(s *core.Sentry, watches map[string]core.WatchConfig, routePaths []string) {
	routes := make(map[string]bool, len(routePaths))
	for _, p := range routePaths {
		routes[p] = true
	}
	for path := range watches {
		if !routes[path] {
			s.Logger().Printf("trappsec: watch %s matches no registered route and will never fire "+
				"(watch paths are full route patterns, including group prefixes, e.g. /api/users/:id)", path)
		}
	}
}
