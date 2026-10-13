package routertest

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/mux"
	trappsechandler "github.com/trappsec-dev/trappsec/packages/go/handler"
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

func (s *syncBuf) waitFor(t *testing.T, needle string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if strings.Contains(s.String(), needle) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no %q in logs: %s", needle, s.String())
}

// served records what the real handlers received.
type served struct {
	mu   sync.Mutex
	hits []string
	body string
}

func (s *served) handler(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.hits = append(s.hits, name)
		s.body = string(b)
		s.mu.Unlock()
	}
}

func (s *served) last() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.hits) == 0 {
		return "", ""
	}
	return s.hits[len(s.hits)-1], s.body
}

func chiApp(sv *served) *trappsechandler.App {
	r := chi.NewRouter()
	r.Post("/users/me", sv.handler("me"))
	r.Route("/api", func(r chi.Router) {
		r.Mount("/v2", func() http.Handler {
			sub := chi.NewRouter()
			sub.Put("/users/{id}", sv.handler("update"))
			return sub
		}())
	})
	app := trappsechandler.InstallSentry(r, "svc", "test")
	return app.MatchRoutes(func(req *http.Request) string {
		return r.Find(chi.NewRouteContext(), req.Method, req.URL.Path)
	})
}

func gorillaApp(sv *served) *trappsechandler.App {
	r := mux.NewRouter()
	r.HandleFunc("/users/me", sv.handler("me")).Methods("POST")
	sub := r.PathPrefix("/api/v2").Subrouter()
	sub.HandleFunc("/users/{id:[0-9]+}", sv.handler("update")).Methods("PUT")
	app := trappsechandler.InstallSentry(r, "svc", "test")
	return app.MatchRoutes(func(req *http.Request) string {
		var m mux.RouteMatch
		if !r.Match(req, &m) || m.MatchErr != nil || m.Route == nil {
			return ""
		}
		tpl, _ := m.Route.GetPathTemplate()
		return tpl
	})
}

func send(app http.Handler, method, target, body string) {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	app.ServeHTTP(httptest.NewRecorder(), req)
}

func TestRouters(t *testing.T) {
	for name, build := range map[string]func(*served) *trappsechandler.App{"chi": chiApp, "gorilla": gorillaApp} {
		t.Run(name, func(t *testing.T) {
			sv := &served{}
			app := build(sv)
			logs := &syncBuf{}
			app.Logger().SetOutput(logs)
			app.Trap("/users/{id}").Methods("POST")
			app.Watch("/api/v2/users/{id}").Body("role", trappsechandler.NoDefault)

			// A real literal route beats the parameterised trap.
			send(app, "POST", "/users/me", "")
			if got, _ := sv.last(); got != "me" {
				t.Fatalf("POST /users/me served by %q", got)
			}
			send(app, "POST", "/users/42", "")
			logs.waitFor(t, "trappsec.trap_hit")

			// A watch on a route inside a mounted sub-router.
			send(app, "PUT", "/api/v2/users/7", `{"name":"a","role":"admin"}`)
			logs.waitFor(t, "trappsec.watch_hit")
			if got, body := sv.last(); got != "update" || strings.Contains(body, "role") {
				t.Fatalf("watched request: served by %q with body %s", got, body)
			}
			if strings.Contains(logs.String(), "will never fire") {
				t.Fatalf("watch on a mounted route reported unreachable: %s", logs.String())
			}
		})
	}
}

func TestDuplicateTrapPanics(t *testing.T) {
	for name, build := range map[string]func(*served) *trappsechandler.App{"chi": chiApp, "gorilla": gorillaApp} {
		t.Run(name, func(t *testing.T) {
			app := build(&served{})
			app.Trap("/api/v2/users/:id").Methods("PUT")
			defer func() {
				if p := recover(); p == nil || !strings.Contains(p.(string), "duplicates") {
					t.Fatalf("expected a duplicate-route panic, got %v", p)
				}
			}()
			app.Bootstrap()
		})
	}
}

// A trailing slash is a different path to chi and gorilla/mux (404), so a trap
// must not answer it either.
func TestTrailingSlashFallsThroughToRouter(t *testing.T) {
	for name, build := range map[string]func(*served) *trappsechandler.App{"chi": chiApp, "gorilla": gorillaApp} {
		t.Run(name, func(t *testing.T) {
			app := build(&served{})
			app.Logger().SetOutput(io.Discard)
			app.Trap("/deployment/config").Methods("GET")
			for path, want := range map[string]bool{"/deployment/config": true, "/deployment/config/": false} {
				if got := app.IsTrap(httptest.NewRequest("GET", path, nil)); got != want {
					t.Errorf("IsTrap(%s) = %v, want %v", path, got, want)
				}
			}
			rec := httptest.NewRecorder()
			app.ServeHTTP(rec, httptest.NewRequest("GET", "/deployment/config/", nil))
			if rec.Code != http.StatusNotFound {
				t.Fatalf("GET /deployment/config/ = %d, want the router's 404", rec.Code)
			}
		})
	}
}
