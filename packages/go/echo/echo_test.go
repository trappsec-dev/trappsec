package trappsececho

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	core "github.com/trappsec-dev/trappsec/packages/go"
	"golang.org/x/net/http2"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type route struct {
	method, path string
	fn           http.HandlerFunc
}

type env struct {
	h      http.Handler
	app    interface{ Bootstrap() }
	s      *core.Sentry
	logs   *syncBuf
	add    func(method, path string, fn http.HandlerFunc)
	setMax func(int64)
}

func httpReq(req any) *http.Request { return requestOf(req) }

func newEnv(t *testing.T, pre []route) *env {
	e := echo.New()
	e.HideBanner = true
	for _, r := range pre {
		e.Add(r.method, r.path, echo.WrapHandler(r.fn))
	}
	app := InstallSentry(e, "svc", "test")
	logs := &syncBuf{}
	app.Logger().SetOutput(logs)
	return &env{h: app, app: app, s: app.Sentry, logs: logs, setMax: app.SetMaxBodyBytes,
		add: func(m, p string, fn http.HandlerFunc) { app.Add(m, p, echo.WrapHandler(fn)) }}
}

func TestLoggerAmbiguityResolved(t *testing.T) {
	e := newEnv(t, nil)
	app := e.app.(*App)
	if app.Logger() == nil || app.EchoLogger() == nil {
		t.Fatal("nil logger")
	}
	if err := app.Close(nil); err != nil {
		t.Fatal(err)
	}
}

func TestStandaloneUseWorks(t *testing.T) {
	ec := echo.New()
	ec.HideBanner = true
	s := core.NewSentry("svc", "test")
	s.Trap("/t").Methods("GET")
	app := Use(s, ec)
	if rec := do(t, app, "GET", "/t", "", nil); rec.Code != 401 {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestMiddlewareRunsBeforeWatchAndTrap(t *testing.T) {
	ec := echo.New()
	ec.HideBanner = true
	app := InstallSentry(ec, "svc", "test")
	logs := &syncBuf{}
	app.Logger().SetOutput(logs)
	app.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error { c.Set("u", "carol"); return next(c) }
	})
	app.IdentifyUser(func(req any) *core.AuthContext {
		if c, ok := req.(echo.Context); ok {
			if u, _ := c.Get("u").(string); u != "" {
				return &core.AuthContext{User: u}
			}
		}
		return nil
	})
	app.Trap("/t").Methods("GET")
	do(t, app, "GET", "/t", "", nil)
	ev := logs.waitEvent(t, "trappsec.trap_hit")
	if ev["user"] != "carol" {
		t.Fatalf("app middleware identity not visible: %v", ev)
	}
}

// ---- shared test body (identical across adapters) ----

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) events() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []map[string]any
	for _, line := range strings.Split(s.b.String(), "\n") {
		var m map[string]any
		if json.Unmarshal([]byte(line), &m) == nil && m["event"] != nil {
			out = append(out, m)
		}
	}
	return out
}

func (s *syncBuf) waitEvent(t *testing.T, name string) map[string]any {
	t.Helper()
	for i := 0; i < 200; i++ {
		for _, e := range s.events() {
			if e["event"] == name {
				return e
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %s event; got %v", name, s.events())
	return nil
}

func (s *syncBuf) count(name string) int {
	n := 0
	for _, e := range s.events() {
		if e["event"] == name {
			n++
		}
	}
	return n
}

type seen struct {
	mu          sync.Mutex
	body        []byte
	query       string
	contentType string
	contentLen  int64
	header      http.Header
	readErr     error
	calls       int
}

func (s *seen) handler(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(r.Body)
	s.mu.Lock()
	s.body, s.readErr = b, err
	s.query = r.URL.RawQuery
	s.contentType = r.Header.Get("Content-Type")
	s.contentLen = r.ContentLength
	s.header = r.Header.Clone()
	s.calls++
	s.mu.Unlock()
	w.WriteHeader(200)
	_, _ = w.Write([]byte("ok"))
}

func do(t *testing.T, h http.Handler, method, target, ct string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, bytes.NewReader(body))
	if ct != "" {
		req.Header.Set("Content-Type", ct)
	}
	req.RemoteAddr = "198.51.100.7:4242"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func userID(req any) *core.AuthContext {
	r := httpReq(req)
	if r == nil {
		return nil
	}
	if u := r.Header.Get("x-user"); u != "" {
		return &core.AuthContext{User: u, Role: "member"}
	}
	return nil
}

func forModes(t *testing.T, fn func(t *testing.T, pre bool)) {
	t.Run("route-after-install", func(t *testing.T) { fn(t, false) })
	t.Run("route-before-install", func(t *testing.T) { fn(t, true) })
}

// watchEnv builds an env with POST /submit watched (+ /search for queries),
// the route registered before or after install.
func watchEnv(t *testing.T, pre bool, setup func(s *core.Sentry)) (*env, *seen) {
	t.Helper()
	sn := &seen{}
	routes := []route{
		{"POST", "/submit", sn.handler},
		{"GET", "/search", sn.handler},
	}
	var e *env
	if pre {
		e = newEnv(t, routes)
	} else {
		e = newEnv(t, nil)
		for _, r := range routes {
			e.add(r.method, r.path, r.fn)
		}
	}
	e.s.Watch("/submit").Body("honey", core.NoDefault, "mass assignment").Body("role", "user", "priv esc")
	e.s.Watch("/search").Query("debug", core.NoDefault, "recon")
	if setup != nil {
		setup(e.s)
	}
	return e, sn
}

func TestTrapUnauthAndAuth(t *testing.T) {
	e := newEnv(t, nil)
	e.s.IdentifyUser(userID)
	e.s.SetDefaultUnauthenticated(401, map[string]any{"error": "no"}, "application/json")
	e.s.Trap("/admin/secret").Methods("GET").Intent("recon")

	rec := do(t, e.h, "GET", "/admin/secret", "", nil)
	if rec.Code != 401 || !strings.Contains(rec.Body.String(), `"error":"no"`) {
		t.Fatalf("unauth: %d %s", rec.Code, rec.Body.String())
	}
	ev := e.logs.waitEvent(t, "trappsec.trap_hit")
	if ev["type"] != "signal" || ev["ip"] != "198.51.100.7" {
		t.Fatalf("unexpected event %v", ev)
	}

	req := httptest.NewRequest("GET", "/admin/secret", nil)
	req.Header.Set("x-user", "alice")
	rec2 := httptest.NewRecorder()
	e.h.ServeHTTP(rec2, req)
	if rec2.Code != 200 {
		t.Fatalf("auth: %d", rec2.Code)
	}
	found := false
	for i := 0; i < 100 && !found; i++ {
		for _, ev := range e.logs.events() {
			if ev["type"] == "alert" && ev["user"] == "alice" {
				found = true
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !found {
		t.Fatalf("no alert for authenticated trap hit: %v", e.logs.events())
	}
	// wrong method on a trap path behaves like a real route (405 / 404 family, not 200)
	if rec := do(t, e.h, "DELETE", "/admin/secret", "", nil); rec.Code == 200 {
		t.Fatalf("DELETE should not hit GET-only trap")
	}
}

func TestWatchQueryStrip(t *testing.T) {
	forModes(t, func(t *testing.T, pre bool) {
		e, sn := watchEnv(t, pre, nil)
		rec := do(t, e.h, "GET", "/search?q=x&debug=1&tag=a&tag=b", "", nil)
		if rec.Code != 200 {
			t.Fatalf("code %d", rec.Code)
		}
		if strings.Contains(sn.query, "debug") || !strings.Contains(sn.query, "q=x") || !strings.Contains(sn.query, "tag=a") || !strings.Contains(sn.query, "tag=b") {
			t.Fatalf("query after strip: %q", sn.query)
		}
		ev := e.logs.waitEvent(t, "trappsec.watch_hit")
		ff, _ := json.Marshal(ev["found_fields"])
		if !strings.Contains(string(ff), `"debug"`) || !strings.Contains(string(ff), `"query"`) {
			t.Fatalf("found_fields: %s", ff)
		}
	})
}

func TestWatchJSONStripAndContentLength(t *testing.T) {
	forModes(t, func(t *testing.T, pre bool) {
		e, sn := watchEnv(t, pre, nil)
		body := []byte(`{"name":"bob","honey":"x","role":"admin","big":9007199254740993,"html":"<b>&</b>"}`)
		do(t, e.h, "POST", "/submit", "application/json", body)
		var got map[string]json.RawMessage
		if err := json.Unmarshal(sn.body, &got); err != nil {
			t.Fatalf("handler body not JSON: %s", sn.body)
		}
		if _, ok := got["honey"]; ok {
			t.Fatalf("honey not stripped: %s", sn.body)
		}
		if _, ok := got["role"]; ok {
			t.Fatalf("role not stripped: %s", sn.body)
		}
		if string(got["big"]) != "9007199254740993" {
			t.Fatalf("large int lost precision: %s", sn.body)
		}
		if string(got["html"]) != `"<b>&</b>"` {
			t.Fatalf("html escaped: %s", sn.body)
		}
		if sn.contentLen != int64(len(sn.body)) || sn.header.Get("Content-Length") != fmt.Sprint(len(sn.body)) {
			t.Fatalf("stale Content-Length: %d / %q for %d bytes", sn.contentLen, sn.header.Get("Content-Length"), len(sn.body))
		}
		e.logs.waitEvent(t, "trappsec.watch_hit")
	})
}

func TestBenignBodyUntouchedByteForByte(t *testing.T) {
	forModes(t, func(t *testing.T, pre bool) {
		e, sn := watchEnv(t, pre, nil)
		body := []byte("{ \"z\": 1,\n  \"a\" : [1, 2,3], \"big\": 12345678901234567890 }")
		do(t, e.h, "POST", "/submit", "application/json", body)
		if !bytes.Equal(sn.body, body) {
			t.Fatalf("body modified:\n%q\n%q", sn.body, body)
		}
		if e.logs.count("trappsec.watch_hit") != 0 {
			t.Fatalf("unexpected watch hit")
		}
	})
}

func TestJSONContentTypeBypassClosed(t *testing.T) {
	forModes(t, func(t *testing.T, pre bool) {
		for _, ct := range []string{"text/plain", "application/vnd.api+json", "application/json; charset=utf-8", "", "application/octet-stream", "APPLICATION/JSON"} {
			e, sn := watchEnv(t, pre, nil)
			do(t, e.h, "POST", "/submit", ct, []byte(`  {"name":"bob","HONEY":"x"}`))
			if strings.Contains(strings.ToLower(string(sn.body)), "honey") {
				t.Fatalf("ct=%q: honey reached handler: %s", ct, sn.body)
			}
			e.logs.waitEvent(t, "trappsec.watch_hit")
		}
	})
}

func TestJSONTopLevelArray(t *testing.T) {
	forModes(t, func(t *testing.T, pre bool) {
		e, sn := watchEnv(t, pre, nil)
		do(t, e.h, "POST", "/submit", "application/json", []byte(`[{"a":1,"honey":"x"},{"a":2},3]`))
		if strings.Contains(string(sn.body), "honey") {
			t.Fatalf("array element not stripped: %s", sn.body)
		}
		var arr []any
		if err := json.Unmarshal(sn.body, &arr); err != nil || len(arr) != 3 {
			t.Fatalf("bad array: %s", sn.body)
		}
		e.logs.waitEvent(t, "trappsec.watch_hit")
	})
}

func TestFormStripPreservesMultiValues(t *testing.T) {
	forModes(t, func(t *testing.T, pre bool) {
		e, sn := watchEnv(t, pre, nil)
		do(t, e.h, "POST", "/submit", "application/x-www-form-urlencoded", []byte("name=bob&honey=1&tag=a&tag=b"))
		vals, _ := url.ParseQuery(string(sn.body))
		if vals.Get("honey") != "" || len(vals["tag"]) != 2 || vals.Get("name") != "bob" {
			t.Fatalf("form after strip: %s", sn.body)
		}
		if sn.contentLen != int64(len(sn.body)) {
			t.Fatalf("stale Content-Length")
		}
		e.logs.waitEvent(t, "trappsec.watch_hit")
	})
}

func TestMultipartStripPreservesPartHeaders(t *testing.T) {
	forModes(t, func(t *testing.T, pre bool) {
		e, sn := watchEnv(t, pre, nil)
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		_ = w.WriteField("name", "bob")
		_ = w.WriteField("honey", "x")
		h := textproto.MIMEHeader{}
		h.Set("Content-Disposition", `form-data; name="file"; filename="a.png"`)
		h.Set("Content-Type", "image/png")
		pw, _ := w.CreatePart(h)
		_, _ = pw.Write([]byte("\x89PNGdata"))
		_ = w.Close()
		do(t, e.h, "POST", "/submit", w.FormDataContentType(), buf.Bytes())

		req := httptest.NewRequest("POST", "/", bytes.NewReader(sn.body))
		req.Header.Set("Content-Type", sn.contentType)
		if err := req.ParseMultipartForm(1 << 20); err != nil {
			t.Fatalf("rewritten multipart invalid: %v", err)
		}
		defer req.MultipartForm.RemoveAll()
		if req.MultipartForm.Value["name"][0] != "bob" {
			t.Fatalf("name lost: %v", req.MultipartForm.Value)
		}
		if _, ok := req.MultipartForm.Value["honey"]; ok {
			t.Fatalf("honey not stripped")
		}
		fh := req.MultipartForm.File["file"]
		if len(fh) != 1 || fh[0].Header.Get("Content-Type") != "image/png" || fh[0].Filename != "a.png" {
			t.Fatalf("file part headers lost: %+v", fh)
		}
		f, _ := fh[0].Open()
		data, _ := io.ReadAll(f)
		f.Close()
		if string(data) != "\x89PNGdata" {
			t.Fatalf("file content changed: %q", data)
		}
		if sn.contentLen != int64(len(sn.body)) {
			t.Fatalf("stale Content-Length")
		}
		e.logs.waitEvent(t, "trappsec.watch_hit")
	})
}

func TestBodyOverLimitPassesThroughIntact(t *testing.T) {
	forModes(t, func(t *testing.T, pre bool) {
		e, sn := watchEnv(t, pre, nil)
		e.setMax(200)
		big := []byte(`{"honey":"x","pad":"` + strings.Repeat("a", 5000) + `"}`)
		for _, chunked := range []bool{false, true} {
			var rd io.Reader = bytes.NewReader(big)
			req := httptest.NewRequest("POST", "/submit", rd)
			if chunked {
				req.Body = io.NopCloser(bytes.NewReader(big))
				req.ContentLength = -1
			}
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			e.h.ServeHTTP(rec, req)
			if !bytes.Equal(sn.body, big) || sn.readErr != nil {
				t.Fatalf("chunked=%v: body not intact (%d vs %d bytes, err=%v)", chunked, len(sn.body), len(big), sn.readErr)
			}
		}
		if e.logs.count("trappsec.watch_hit") != 0 {
			t.Fatalf("oversized body should not be inspected")
		}
	})
}

type failingReader struct {
	data []byte
	err  error
	pos  int
}

func (f *failingReader) Read(p []byte) (int, error) {
	if f.pos >= len(f.data) {
		return 0, f.err
	}
	n := copy(p, f.data[f.pos:])
	f.pos += n
	return n, nil
}

func TestTruncatedBodyErrorReachesHandler(t *testing.T) {
	e, sn := watchEnv(t, false, nil)
	boom := errors.New("boom")
	req := httptest.NewRequest("POST", "/submit", nil)
	req.Body = io.NopCloser(&failingReader{data: []byte(`{"honey":"x"`), err: boom})
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	e.h.ServeHTTP(httptest.NewRecorder(), req)
	if !errors.Is(sn.readErr, boom) {
		t.Fatalf("handler did not observe read error, got %v", sn.readErr)
	}
	if e.logs.count("trappsec.watch_hit") != 0 {
		t.Fatalf("truncated body must not be treated as complete")
	}
}

func TestBootstrapViaHTTPServerWithoutRun(t *testing.T) {
	sn := &seen{}
	e := newEnv(t, nil)
	e.add("POST", "/submit", sn.handler)
	e.s.Watch("/submit").Body("honey", core.NoDefault, "x")
	e.s.Trap("/internal/keys").Methods("GET")

	srv := httptest.NewServer(e.h) // never calls Run/Start/ListenAndServe
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/internal/keys")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatalf("trap not installed lazily: status %d", resp.StatusCode)
	}
	resp, err = http.Post(srv.URL+"/submit", "application/json", strings.NewReader(`{"honey":"x","a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if strings.Contains(string(sn.body), "honey") {
		t.Fatalf("watch not active without Run: %s", sn.body)
	}
	e.logs.waitEvent(t, "trappsec.watch_hit")

	// http.Server{Handler: app} (graceful-shutdown style) works the same way.
	e2 := newEnv(t, nil)
	e2.s.Trap("/t2").Methods("GET")
	s2 := httptest.NewUnstartedServer(nil)
	s2.Config = &http.Server{Handler: e2.h}
	s2.Start()
	defer s2.Close()
	r2, err := http.Get(s2.URL + "/t2")
	if err != nil {
		t.Fatal(err)
	}
	r2.Body.Close()
	if r2.StatusCode != 401 {
		t.Fatalf("http.Server{Handler: app}: status %d", r2.StatusCode)
	}
}

func TestDoubleAndConcurrentBootstrap(t *testing.T) {
	e := newEnv(t, nil)
	e.s.Trap("/t").Methods("GET")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.app.Bootstrap()
		}()
	}
	wg.Wait()
	e.app.Bootstrap()
	if rec := do(t, e.h, "GET", "/t", "", nil); rec.Code != 401 {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestSpoofedForwardedForIgnored(t *testing.T) {
	e := newEnv(t, nil)
	e.s.Trap("/t").Methods("GET")
	req := httptest.NewRequest("GET", "/t", nil)
	req.RemoteAddr = "203.0.113.9:5555"
	req.Header.Set("X-Forwarded-For", "6.6.6.6")
	req.Header.Set("X-Real-IP", "7.7.7.7")
	e.h.ServeHTTP(httptest.NewRecorder(), req)
	ev := e.logs.waitEvent(t, "trappsec.trap_hit")
	if ev["ip"] != "203.0.113.9" {
		t.Fatalf("ip = %v, want RemoteAddr host", ev["ip"])
	}

	// OverrideSourceIP still wins.
	e2 := newEnv(t, nil)
	e2.s.Trap("/t").Methods("GET")
	e2.s.OverrideSourceIP(func(req any) string { return httpReq(req).Header.Get("X-Real-IP") })
	e2.h.ServeHTTP(httptest.NewRecorder(), req)
	ev = e2.logs.waitEvent(t, "trappsec.trap_hit")
	if ev["ip"] != "7.7.7.7" {
		t.Fatalf("override ip = %v", ev["ip"])
	}
}

func TestDuplicateRouteFailsLoud(t *testing.T) {
	e := newEnv(t, nil)
	e.add("GET", "/dup", func(w http.ResponseWriter, r *http.Request) {})
	e.s.Trap("/dup").Methods("GET")
	msg := mustPanic(t, func() { e.app.Bootstrap() })
	if !strings.Contains(msg, "trappsec") || !strings.Contains(msg, "/dup") {
		t.Fatalf("unclear panic message: %q", msg)
	}
	// Never silently half-installed: serving panics/errs too (recorded as the same failure).
	msg2 := mustPanic(t, func() { e.app.Bootstrap() })
	if msg2 != msg {
		t.Fatalf("second bootstrap message differs: %q vs %q", msg2, msg)
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

func TestConcurrentRequestsRace(t *testing.T) {
	forModes(t, func(t *testing.T, pre bool) {
		e, _ := watchEnv(t, pre, nil)
		e.s.Trap("/t").Methods("GET")
		var wg sync.WaitGroup
		for i := 0; i < 40; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				switch i % 3 {
				case 0:
					do(t, e.h, "POST", "/submit", "application/json", []byte(`{"honey":"x","n":1}`))
				case 1:
					do(t, e.h, "GET", "/search?debug=1&q=2", "", nil)
				default:
					do(t, e.h, "GET", "/t", "", nil)
				}
			}(i)
		}
		wg.Wait()
	})
}

func TestCSRFSkipperKeepsTrapsWorking(t *testing.T) {
	for _, skip := range []bool{false, true} {
		e := echo.New()
		app := InstallSentry(e, "svc", "test")
		logs := &syncBuf{}
		app.Logger().SetOutput(logs)
		cfg := middleware.CSRFConfig{}
		if skip {
			cfg.Skipper = app.IsTrap
		}
		e.Use(middleware.CSRFWithConfig(cfg))
		e.POST("/real", func(c echo.Context) error { return c.String(200, "ok") })
		app.Sentry.Trap("/admin/backup").Methods("POST")

		do := func(path string) int {
			rec := httptest.NewRecorder()
			app.ServeHTTP(rec, httptest.NewRequest("POST", path, strings.NewReader("a=1")))
			return rec.Code
		}
		trap, real := do("/admin/backup"), do("/real")
		if real != http.StatusForbidden && real != http.StatusBadRequest {
			t.Fatalf("skip=%v: CSRF must still protect real routes, got %d", skip, real)
		}
		if skip {
			if trap != http.StatusUnauthorized || logs.count("trappsec.trap_hit") != 1 {
				t.Fatalf("with IsTrap skipper: trap = %d, events = %d", trap, logs.count("trappsec.trap_hit"))
			}
		} else if trap == http.StatusUnauthorized {
			t.Fatalf("without the skipper Echo's CSRF middleware is expected to block the trap (got %d)", trap)
		}
	}
	e := echo.New()
	app := InstallSentry(e, "svc", "test")
	app.Sentry.Trap("/t").Methods("GET")
	c := e.NewContext(httptest.NewRequest("GET", "/x", nil), httptest.NewRecorder())
	c.SetPath("/x")
	if app.IsTrap(c) {
		t.Fatal("a non-trap route is not a trap")
	}
}

func TestUnreachableWatchIsLogged(t *testing.T) {
	e := echo.New()
	app := InstallSentry(e, "svc", "test")
	logs := &syncBuf{}
	app.Logger().SetOutput(logs)
	e.Group("/api").POST("/users/:id", func(echo.Context) error { return nil })
	app.Sentry.Watch("/api/users/:id").Body("is_admin", core.NoDefault, "priv")
	app.Sentry.Watch("/users/:id").Body("is_admin", core.NoDefault, "priv") // missing the group prefix
	app.Bootstrap()
	out := logs.String()
	if !strings.Contains(out, "watch /users/:id matches no registered route") || strings.Contains(out, "watch /api/users/:id matches") {
		t.Fatalf("unexpected warnings: %s", out)
	}
}

func TestWatchOnGroupRoute(t *testing.T) {
	e := echo.New()
	app := InstallSentry(e, "svc", "test")
	logs := &syncBuf{}
	app.Logger().SetOutput(logs)
	var bound map[string]any
	e.Group("/api").POST("/users/:id", func(c echo.Context) error {
		bound = nil
		_ = c.Bind(&bound)
		return c.NoContent(200)
	})
	app.Sentry.Watch("/api/users/:id").Body("is_admin", core.NoDefault, "priv")
	req := httptest.NewRequest("POST", "/api/users/7", strings.NewReader(`{"is_admin":true,"n":1}`))
	req.Header.Set("Content-Type", "application/json")
	app.ServeHTTP(httptest.NewRecorder(), req)
	if _, leaked := bound["is_admin"]; leaked || logs.count("trappsec.watch_hit") != 1 {
		t.Fatalf("group route not watched: bound=%v events=%d", bound, logs.count("trappsec.watch_hit"))
	}
}

func TestPanickingCallbacksNeverBreakRequests(t *testing.T) {
	e := echo.New()
	app := InstallSentry(e, "svc", "test")
	app.Logger().SetOutput(&syncBuf{})
	app.IdentifyUser(func(any) *core.AuthContext { panic("identify") })
	app.OverrideSourceIP(func(any) string { panic("ip") })
	app.Sentry.Trap("/admin").Methods("GET").Respond(core.ResponseConfig{Status: 200, Body: func(echo.Context) any { panic("body") }})
	var bound map[string]any
	e.POST("/w", func(c echo.Context) error { bound = nil; _ = c.Bind(&bound); return c.NoContent(200) })
	app.Sentry.Watch("/w").Body("role", func(any) any { panic("default") }, "priv")

	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, httptest.NewRequest("GET", "/admin", nil))
	if rec.Code != 401 {
		t.Fatalf("trap answered %d", rec.Code)
	}
	req := httptest.NewRequest("POST", "/w", strings.NewReader(`{"role":"user","n":1}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if _, leaked := bound["role"]; rec.Code != 200 || leaked || bound["n"] == nil {
		t.Fatalf("watched route: code=%d bound=%v", rec.Code, bound)
	}
}

func TestParameterisedWatchAndEventContext(t *testing.T) {
	e := echo.New()
	app := InstallSentry(e, "svc", "test")
	logs := &syncBuf{}
	app.Logger().SetOutput(logs)
	var seen string
	e.GET("/users/:id", func(c echo.Context) error { seen = c.Request().URL.RawQuery; return nil })
	app.Sentry.Watch("/users/:id").Query("debug", core.NoDefault, "recon")
	req := httptest.NewRequest("GET", "/users/7?debug=1&x=1", nil)
	req.Header.Set("User-Agent", "probe/1.0")
	req.RemoteAddr = "203.0.113.5:4711"
	app.ServeHTTP(httptest.NewRecorder(), req)
	ev := logs.waitEvent(t, "trappsec.watch_hit")
	if seen != "x=1" || ev["path"] != "/users/7" || ev["method"] != "GET" || ev["user_agent"] != "probe/1.0" || ev["ip"] != "203.0.113.5" {
		t.Fatalf("handler saw %q; event %v", seen, ev)
	}
}

// R10: watches declared before traps both work. R13: the indexes are built once
// at startup, so a watch added while serving is never looked up; a per-request
// scan of the configuration would pick it up.
func TestWatchesBeforeTrapsAndIndexBuiltOnce(t *testing.T) {
	e := echo.New()
	app := InstallSentry(e, "svc", "test")
	logs := &syncBuf{}
	app.Logger().SetOutput(logs)
	var seen string
	e.GET("/users/:id", func(c echo.Context) error { seen = c.Request().URL.RawQuery; return nil })
	app.Sentry.Watch("/users/:id").Query("debug", core.NoDefault, "recon")
	app.Sentry.Trap("/admin/backup").Methods("POST")
	do := func(method, path string) int {
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		return rec.Code
	}
	if code := do("POST", "/admin/backup"); code != 401 {
		t.Fatalf("trap answered %d", code)
	}
	logs.waitEvent(t, "trappsec.trap_hit")
	if do("GET", "/users/7?debug=1&x=1"); seen != "x=1" {
		t.Fatalf("watched field reached the handler: %q", seen)
	}
	logs.waitEvent(t, "trappsec.watch_hit")
	app.Sentry.Watch("/users/:id").Query("late", core.NoDefault, "recon")
	if do("GET", "/users/8?late=1"); seen != "late=1" {
		t.Fatalf("a watch added while serving was applied: handler saw %q", seen)
	}
}

// Once routed, IsTrap answers from the matched route: a real route that only
// looks like a trap is not one. Before routing (e.Pre) it matches the path.
func TestAppIsTrapUsesTheMatchedRoute(t *testing.T) {
	e := echo.New()
	app := InstallSentry(e, "svc", "test")
	app.Logger().SetOutput(io.Discard)
	app.Trap("/users/:id").Methods("POST")
	ctx := func(path, route string) echo.Context {
		c := e.NewContext(httptest.NewRequest("POST", path, nil), httptest.NewRecorder())
		c.SetPath(route)
		return c
	}
	if app.IsTrap(ctx("/users/me", "/users/me")) {
		t.Fatal("real route /users/me reported as a trap")
	}
	if !app.IsTrap(ctx("/users/7", "/users/:id")) {
		t.Fatal("routed trap not reported")
	}
	if !app.IsTrap(ctx("/users/7", "")) {
		t.Fatal("unrouted (e.Pre) trap path not reported")
	}
}

// A request rejected by an earlier Use middleware never reaches the watch
// middleware; it is still inspected (after the chain, with the identity the
// rejecting middleware stored), and a request that does reach it is inspected
// exactly once.
func TestRejectedRequestsAreStillInspected(t *testing.T) {
	e := echo.New()
	app := InstallSentry(e, "svc", "test")
	logs := &syncBuf{}
	app.Logger().SetOutput(logs)
	app.IdentifyUser(func(req any) *core.AuthContext {
		if c, ok := req.(echo.Context); ok {
			if u, _ := c.Get("u").(string); u != "" {
				return &core.AuthContext{User: u}
			}
		}
		return nil
	})
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set("u", "mallory")
			if c.Request().Header.Get("X-Key") == "" {
				return echo.ErrUnauthorized
			}
			return next(c)
		}
	})
	e.GET("/search", func(c echo.Context) error { return c.String(200, "ok") })
	app.Watch("/search").Query("debug", core.NoDefault, "recon")

	if rec := do(t, app, "GET", "/search?debug=1", "", nil); rec.Code != 401 {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	ev := logs.waitEvent(t, "trappsec.watch_hit")
	if ev["user"] != "mallory" {
		t.Fatalf("rejected request lost identity: %v", ev)
	}

	req := httptest.NewRequest("GET", "/search?debug=1", nil)
	req.Header.Set("X-Key", "k")
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != 200 || logs.count("trappsec.watch_hit") != 2 {
		t.Fatalf("code %d, watch_hit events %d (want one per request)", rec.Code, logs.count("trappsec.watch_hit"))
	}
}

// Echo's promoted StartH2CServer would serve the bare Echo instance; the
// App's wrapper bootstraps first so traps are live.
func TestStartH2CServerBootstraps(t *testing.T) {
	e := echo.New()
	e.HideBanner, e.HidePort = true, true
	app := InstallSentry(e, "svc", "test")
	app.Trap("/t").Methods("GET")
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = app.StartH2CServer("127.0.0.1:0", &http2.Server{})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for !app.integration.once.Done() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !app.integration.once.Done() {
		t.Fatal("StartH2CServer did not bootstrap")
	}
	_ = e.Close()
	<-done
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest("GET", "/t", nil))
	if rec.Code == http.StatusNotFound {
		t.Fatal("trap route not registered")
	}
}
