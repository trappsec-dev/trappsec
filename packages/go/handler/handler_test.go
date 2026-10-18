package trappsechandler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	core "github.com/trappsec-dev/trappsec/packages/go"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuf) count(name string) int {
	n := 0
	for _, line := range strings.Split(s.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["event"] == name {
			n++
		}
	}
	return n
}

func (s *syncBuf) waitEvent(t *testing.T, name string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if s.count(name) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %s event; logs: %s", name, s.String())
}

// router is a stand-in for a third-party router: a ServeMux that records
// which requests reached it.
type router struct {
	*http.ServeMux
	mu   sync.Mutex
	hits []string
	body []byte
}

func newRouter(patterns ...string) *router {
	rt := &router{ServeMux: http.NewServeMux()}
	for _, p := range patterns {
		rt.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			rt.mu.Lock()
			rt.hits = append(rt.hits, r.Method+" "+r.URL.Path)
			rt.body = b
			rt.mu.Unlock()
			w.WriteHeader(200)
		})
	}
	return rt
}

func (rt *router) reached() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return len(rt.hits)
}

// match reports the ServeMux pattern without its method, the way chi and
// gorilla/mux report route templates.
func (rt *router) match(r *http.Request) string {
	_, p := rt.Handler(r)
	if _, path, ok := strings.Cut(p, " "); ok {
		return path
	}
	return p
}

func newApp(t *testing.T, rt *router, matcher bool) (*App, *syncBuf) {
	t.Helper()
	app := InstallSentry(rt, "svc", "test")
	logs := &syncBuf{}
	app.Logger().SetOutput(logs)
	if matcher {
		app.MatchRoutes(rt.match)
	}
	return app, logs
}

func do(app http.Handler, method, target, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	return rec
}

func TestTrapAnsweredBeforeRouter(t *testing.T) {
	for _, matcher := range []bool{false, true} {
		t.Run(fmt.Sprint("matcher=", matcher), func(t *testing.T) {
			rt := newRouter("GET /real")
			app, logs := newApp(t, rt, matcher)
			app.Trap("/api/v1/config").Methods("GET").
				IfUnauthenticated(core.ResponseConfig{Status: 200, Body: map[string]any{"ok": true}})

			rec := do(app, "GET", "/api/v1/config", "")
			if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ok"`) {
				t.Fatalf("trap response = %d %q", rec.Code, rec.Body.String())
			}
			if rt.reached() != 0 {
				t.Fatalf("trap request reached the router")
			}
			logs.waitEvent(t, "trappsec.trap_hit")

			if do(app, "GET", "/real", "").Code != 200 || rt.reached() != 1 {
				t.Fatalf("real route not served")
			}
			do(app, "POST", "/api/v1/config", "")
			if rt.reached() != 1 || logs.count("trappsec.trap_hit") != 1 {
				t.Fatalf("trap fired for a method it does not declare")
			}
		})
	}
}

func TestParameterisedTrap(t *testing.T) {
	rt := newRouter()
	app, logs := newApp(t, rt, false)
	app.Trap("/internal/users/:id/role").Methods("PUT")
	if do(app, "PUT", "/internal/users/42/role", "").Code == 200 {
		t.Fatalf("expected the default trap response")
	}
	logs.waitEvent(t, "trappsec.trap_hit")
	if !app.IsTrap(httptest.NewRequest("PUT", "/internal/users/7/role/", nil)) {
		t.Fatalf("trailing slash should still match")
	}
	if app.IsTrap(httptest.NewRequest("PUT", "/internal/users//role", nil)) {
		t.Fatalf("empty segment matched a parameter")
	}
}

func TestMoreSpecificRealRouteWins(t *testing.T) {
	rt := newRouter("POST /users/me")
	app, logs := newApp(t, rt, true)
	app.Trap("/users/{id}").Methods("POST")

	do(app, "POST", "/users/me", "")
	if rt.reached() != 1 || logs.count("trappsec.trap_hit") != 0 {
		t.Fatalf("trap shadowed the more specific real route")
	}
	if app.IsTrap(httptest.NewRequest("POST", "/users/me", nil)) {
		t.Fatalf("IsTrap reported a real route")
	}
	do(app, "POST", "/users/42", "")
	logs.waitEvent(t, "trappsec.trap_hit")
	if rt.reached() != 1 {
		t.Fatalf("trap request reached the router")
	}
}

func TestMoreSpecificTrapWins(t *testing.T) {
	rt := newRouter("GET /users/{id}", "/")
	app, logs := newApp(t, rt, true)
	app.Trap("/users/admin").Methods("GET")
	app.Trap("/debug/vars").Methods("GET")

	do(app, "GET", "/users/admin", "")
	do(app, "GET", "/debug/vars", "") // the catch-all "/" must not hide it
	if rt.reached() != 0 {
		t.Fatalf("router served a trap path: %v", rt.hits)
	}
	if n := logs.count("trappsec.trap_hit"); n != 2 {
		t.Fatalf("trap_hit events = %d, want 2", n)
	}
}

func TestDuplicateTrapPanics(t *testing.T) {
	rt := newRouter("GET /users/{id}")
	app, _ := newApp(t, rt, true)
	app.Trap("/users/:uid").Methods("GET")
	msg := mustPanic(t, app.Bootstrap)
	if !strings.Contains(msg, "/users/:uid") || !strings.Contains(msg, "duplicates") {
		t.Fatalf("unclear message: %q", msg)
	}
	if again := mustPanic(t, app.Bootstrap); again != msg {
		t.Fatalf("later Bootstrap did not repeat the panic: %q", again)
	}
}

func TestWatchStripsHoneyField(t *testing.T) {
	for _, matcher := range []bool{false, true} {
		t.Run(fmt.Sprint("matcher=", matcher), func(t *testing.T) {
			rt := newRouter("POST /users/{id}")
			app, logs := newApp(t, rt, matcher)
			app.Watch("/users/{id}").Body("is_admin", false)

			do(app, "POST", "/users/42", `{"name":"a","is_admin":true}`)
			logs.waitEvent(t, "trappsec.watch_hit")
			if strings.Contains(string(rt.body), "is_admin") {
				t.Fatalf("honey field reached the handler: %s", rt.body)
			}
		})
	}
}

func TestWatchFollowsMatchedRoute(t *testing.T) {
	rt := newRouter("POST /users/me", "POST /users/{id}")
	app, logs := newApp(t, rt, true)
	app.Watch("/users/{id}").Body("is_admin", false)

	do(app, "POST", "/users/me", `{"is_admin":true}`)
	if !strings.Contains(string(rt.body), "is_admin") || logs.count("trappsec.watch_hit") != 0 {
		t.Fatalf("watch applied to a different route")
	}
}

func TestUnreachableWatchWarns(t *testing.T) {
	rt := newRouter("POST /users/{id}")
	app, logs := newApp(t, rt, true)
	app.Watch("/accounts/{id}").Body("is_admin", false)
	app.Bootstrap()
	if !strings.Contains(logs.String(), "watch /accounts/{id} matches no route") {
		t.Fatalf("no warning; logs: %s", logs.String())
	}
}

func TestMatchRoutesAfterBootstrapPanics(t *testing.T) {
	rt := newRouter()
	app, _ := newApp(t, rt, false)
	app.Bootstrap()
	mustPanic(t, func() { app.MatchRoutes(rt.match) })
}

func TestPatternCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int // sign
	}{
		{"/users/me", "/users/{id}", 1},
		{"/users/{id}", "/users/:uid", 0},
		{"/files/*", "/files/{name}", -1},
		{"/static", "/static/admin", -1}, // a prefix route loses to a full path
		{"/", "/anything", -1},
	}
	for _, c := range cases {
		got := parsePattern(c.a).compare(parsePattern(c.b))
		if (got > 0) != (c.want > 0) || (got < 0) != (c.want < 0) {
			t.Errorf("compare(%s, %s) = %d, want sign %d", c.a, c.b, got, c.want)
		}
	}
	if parsePattern("/a/{id:[0-9]+}/<int:n>/*rest").shape() != "/a/{}/{}/*" {
		t.Errorf("shape = %s", parsePattern("/a/{id:[0-9]+}/<int:n>/*rest").shape())
	}
}

func mustPanic(t *testing.T, fn func()) (msg string) {
	t.Helper()
	defer func() {
		p := recover()
		if p == nil {
			t.Fatalf("expected panic")
		}
		msg = fmt.Sprint(p)
	}()
	fn()
	return
}

// TestIsTrapConformance checks the adapter's own path matching against the
// shared is_trap cases every SDK loads.
func TestIsTrapConformance(t *testing.T) {
	raw, err := os.ReadFile("../../../tests/conformance/is_trap.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Traps []struct {
			Path    string   `json:"path"`
			Methods []string `json:"methods"`
		} `json:"traps"`
		Cases []struct {
			Method string `json:"method"`
			Path   string `json:"path"`
			IsTrap bool   `json:"is_trap"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	app, _ := newApp(t, newRouter(), false)
	for _, tr := range fx.Traps {
		app.Trap(tr.Path).Methods(tr.Methods...)
	}
	for _, c := range fx.Cases {
		req := httptest.NewRequest("GET", "/", nil)
		req.Method, req.URL.Path = c.Method, strings.SplitN(c.Path, "?", 2)[0]
		if got := app.IsTrap(req); got != c.IsTrap {
			t.Errorf("IsTrap(%s %s) = %v, want %v", c.Method, c.Path, got, c.IsTrap)
		}
	}
}

func TestLiteralTrapBeatsPattern(t *testing.T) {
	app, _ := newApp(t, newRouter(), false)
	app.Trap("/a/{id}").Methods("GET").IfUnauthenticated(core.ResponseConfig{Status: 403})
	app.Trap("/a/b").Methods("GET").IfUnauthenticated(core.ResponseConfig{Status: 418})
	if got := do(app, "GET", "/a/b", "").Code; got != 418 {
		t.Fatalf("literal trap: %d", got)
	}
	if got := do(app, "GET", "/a/c", "").Code; got != 403 {
		t.Fatalf("pattern trap: %d", got)
	}
}

func httpReq(req any) *http.Request {
	r, _ := req.(*http.Request)
	return r
}

func TestTrapHeadersResponseHookAndFallback(t *testing.T) {
	app, _ := newApp(t, newRouter("GET /real"), false)
	configureMirror(app.Sentry)
	checkMirror(t, app)
}

// configureMirror sets up trap response headers, a response hook and a
// failing body callback (R16, R23); checkMirror serves them through h.
func configureMirror(s *core.Sentry) {
	s.IdentifyUser(func(req any) *core.AuthContext {
		r := httpReq(req)
		if r == nil || r.Header.Get("x-user") == "" {
			return nil
		}
		return &core.AuthContext{User: r.Header.Get("x-user"), Role: r.Header.Get("x-role")}
	})
	s.DefaultUnauthenticatedResponse(core.ResponseConfig{Status: 401, Body: map[string]any{"detail": "Not authenticated"},
		Headers: map[string]string{"WWW-Authenticate": "Bearer"}})
	s.DefaultResponse(core.ResponseConfig{Status: 403, Body: "forbidden", MIMEType: "text/plain",
		Headers: map[string]string{"X-Default": "1"}})
	s.Trap("/api/v1/projects/export").Methods("GET").
		Respond(core.ResponseConfig{Status: 403, Body: map[string]any{"detail": "Forbidden"}, MIMEType: "application/json",
			Headers: map[string]string{"Allow": "GET, POST", "Vary": "Accept"}}).
		RespondWith(func(req any, ctx core.TrapRequest) *core.TrapResponse {
			if httpReq(req) == nil {
				panic("hook got no request")
			}
			switch ctx.Role {
			case "owner":
				return &core.TrapResponse{Status: 201, Body: map[string]any{"id": 1}}
			case "ghost":
				return &core.TrapResponse{Status: 404, Body: map[string]any{"detail": "Not found."}}
			}
			return nil
		})
	s.Trap("/api/v1/broken").Methods("GET").Respond(core.ResponseConfig{Status: 200,
		Body: func(any) any { panic("boom") }, Headers: map[string]string{"X-Trap": "1"}})
}

func checkMirror(t *testing.T, h http.Handler) {
	t.Helper()
	get := func(path, user, role string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		if user != "" {
			req.Header.Set("x-user", user)
			req.Header.Set("x-role", role)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	want := func(rec *httptest.ResponseRecorder, status int, body string, headers map[string]string) {
		t.Helper()
		if rec.Code != status || strings.TrimSpace(rec.Body.String()) != body {
			t.Fatalf("got %d %q, want %d %q", rec.Code, rec.Body.String(), status, body)
		}
		for k, v := range headers {
			if got := rec.Header().Get(k); got != v {
				t.Fatalf("header %s = %q, want %q (all: %v)", k, got, v, rec.Header())
			}
		}
	}
	want(get("/api/v1/projects/export", "", ""), 401, `{"detail":"Not authenticated"}`, map[string]string{"WWW-Authenticate": "Bearer"})
	want(get("/api/v1/projects/export", "bob", "member"), 403, `{"detail":"Forbidden"}`,
		map[string]string{"Allow": "GET, POST", "Vary": "Accept", "WWW-Authenticate": ""})
	want(get("/api/v1/projects/export", "bob", "owner"), 201, `{"id":1}`, map[string]string{"Allow": "GET, POST"})
	want(get("/api/v1/projects/export", "bob", "ghost"), 404, `{"detail":"Not found."}`, nil)
	// A failing body callback sends the default response, never "{}".
	rec := get("/api/v1/broken", "bob", "member")
	want(rec, 403, "forbidden", map[string]string{"X-Default": "1", "X-Trap": ""})
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q", ct)
	}
}
