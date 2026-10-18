package trappsec

// Trap response headers, the per-request response hook and callback fallback
// (R16, R23), including the shared cases in tests/conformance/trap_response.json.

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"reflect"
	"strings"
	"testing"
)

type fixtureResponse struct {
	Status   int               `json:"status"`
	Body     json.RawMessage   `json:"body"`
	MIMEType string            `json:"mime_type"`
	Headers  map[string]string `json:"headers"`
}

// config turns a fixture response into a ResponseConfig. Bodies: a JSON
// string is a string, {"$callable": ...} a callback, anything else a value.
func (f *fixtureResponse) config(t *testing.T) ResponseConfig {
	t.Helper()
	if f == nil {
		return ResponseConfig{}
	}
	cfg := ResponseConfig{Status: f.Status, MIMEType: f.MIMEType, Headers: f.Headers}
	if len(f.Body) > 0 {
		var v any
		if err := json.Unmarshal(f.Body, &v); err != nil {
			t.Fatal(err)
		}
		if m, ok := v.(map[string]any); ok && m["$callable"] != nil {
			if m["$callable"] == "throws" {
				v = func(any) any { panic("boom") }
			} else {
				value := m["value"]
				v = func(any) any { return value }
			}
		}
		cfg.Body = v
	}
	return cfg
}

func TestConformanceTrapResponse(t *testing.T) {
	var fx struct {
		Cases []struct {
			Name          string           `json:"name"`
			Authenticated bool             `json:"authenticated"`
			Default       *fixtureResponse `json:"default"`
			Trap          *fixtureResponse `json:"trap"`
			Hook          json.RawMessage  `json:"hook"`
			Expect        fixtureResponse  `json:"expect"`
		} `json:"cases"`
	}
	loadConformance(t, "trap_response.json", &fx)
	for _, c := range fx.Cases {
		t.Run(c.Name, func(t *testing.T) {
			s := NewSentry("svc", "test")
			s.logger = log.New(io.Discard, "", 0)
			s.handlers = nil
			s.IdentifyUser(func(any) *AuthContext {
				if c.Authenticated {
					return &AuthContext{User: "u1", Role: "member"}
				}
				return nil
			})
			var b *TrapBuilder
			if c.Authenticated {
				s.DefaultResponse(c.Default.config(t))
				b = s.Trap("/t").Respond(c.Trap.config(t))
			} else {
				s.DefaultUnauthenticatedResponse(c.Default.config(t))
				b = s.Trap("/t").IfUnauthenticated(c.Trap.config(t))
			}
			if len(c.Hook) > 0 {
				var hook any
				if err := json.Unmarshal(c.Hook, &hook); err != nil {
					t.Fatal(err)
				}
				if hook == "throws" {
					b.RespondWith(func(any, TrapRequest) *TrapResponse { panic("hook") })
				} else {
					var ret struct {
						Returns *struct {
							Status   int               `json:"status"`
							Body     any               `json:"body"`
							MIMEType string            `json:"mime_type"`
							Headers  map[string]string `json:"headers"`
						} `json:"returns"`
					}
					if err := json.Unmarshal(c.Hook, &ret); err != nil {
						t.Fatal(err)
					}
					b.RespondWith(func(any, TrapRequest) *TrapResponse {
						if ret.Returns == nil {
							return nil
						}
						r := TrapResponse(*ret.Returns)
						return &r
					})
				}
			}

			body, cfg := s.triggerTrapEvent(nil, b.Build())
			var wantBody string
			if err := json.Unmarshal(c.Expect.Body, &wantBody); err != nil {
				t.Fatal(err)
			}
			if cfg.StatusCode != c.Expect.Status || string(body) != wantBody || cfg.MIMEType != c.Expect.MIMEType ||
				!reflect.DeepEqual(cfg.Headers, c.Expect.Headers) {
				t.Fatalf("got %d %q %q %v, want %d %q %q %v", cfg.StatusCode, body, cfg.MIMEType, cfg.Headers,
					c.Expect.Status, wantBody, c.Expect.MIMEType, c.Expect.Headers)
			}
		})
	}
}

func quietSentry(user, role string) (*Sentry, *bytes.Buffer) {
	s := NewSentry("svc", "test")
	logs := &bytes.Buffer{}
	s.logger = log.New(logs, "", 0)
	s.handlers = nil
	s.IdentifyUser(func(any) *AuthContext {
		if user == "" {
			return nil
		}
		return &AuthContext{User: user, Role: role}
	})
	return s, logs
}

func TestResponseHookGetsTheRequestAndTheIdentity(t *testing.T) {
	s, _ := quietSentry("bob", "owner")
	type req struct{ id int }
	var got []any
	trap := s.Trap("/t").RespondWith(func(r any, ctx TrapRequest) *TrapResponse {
		got = append(got, r, ctx)
		return &TrapResponse{Status: 201}
	}).Build()
	body, cfg := s.triggerTrapEvent(req{7}, trap)
	if cfg.StatusCode != 201 || string(body) != "{}" {
		t.Fatalf("got %d %q", cfg.StatusCode, body)
	}
	if !reflect.DeepEqual(got, []any{req{7}, TrapRequest{Authenticated: true, User: "bob", Role: "owner"}}) {
		t.Fatalf("hook saw %#v", got)
	}

	s, _ = quietSentry("", "")
	trap = s.Trap("/t").RespondWith(func(r any, ctx TrapRequest) *TrapResponse { got = append(got, ctx); return nil }).Build()
	if _, cfg := s.triggerTrapEvent(nil, trap); cfg.StatusCode != 401 || got[2] != (TrapRequest{}) {
		t.Fatalf("got %d, ctx %#v", cfg.StatusCode, got[2])
	}
}

func TestInvalidResponseHookResultSendsTheStaticResponse(t *testing.T) {
	for _, res := range []*TrapResponse{
		{Status: 99}, {Status: 600}, {Body: func(any) any { return "x" }},
		{Headers: map[string]string{"X": "a\r\nb"}}, {Headers: map[string]string{"": "a"}},
	} {
		s, logs := quietSentry("", "")
		trap := s.Trap("/t").IfUnauthenticated(ResponseConfig{Status: 403, Body: "static"}).
			RespondWith(func(any, TrapRequest) *TrapResponse { return res }).Build()
		body, cfg := s.triggerTrapEvent(nil, trap)
		if cfg.StatusCode != 403 || string(body) != "static" || !strings.Contains(logs.String(), "trap response hook failed") {
			t.Fatalf("%+v: got %d %q, logs %q", res, cfg.StatusCode, body, logs.String())
		}
	}
}

func TestHookBodyThatCannotBeEncodedSendsTheDefaultResponse(t *testing.T) {
	s, _ := quietSentry("", "")
	s.DefaultUnauthenticatedResponse(ResponseConfig{Body: "default"})
	trap := s.Trap("/t").RespondWith(func(any, TrapRequest) *TrapResponse {
		return &TrapResponse{Status: 404, Body: make(chan int)}
	}).Build()
	if body, cfg := s.triggerTrapEvent(nil, trap); string(body) != "default" || cfg.StatusCode != 401 {
		t.Fatalf("got %d %q", cfg.StatusCode, body)
	}
}

func TestInvalidHeadersPanicAtConfigurationTime(t *testing.T) {
	for _, h := range []map[string]string{{"X": "a\nb"}, {"X\r": "a"}, {"": "a"}, {"X:Y": "a"}} {
		s, _ := quietSentry("", "")
		for name, configure := range map[string]func(){
			"Respond":           func() { s.Trap("/t").Respond(ResponseConfig{Headers: h}) },
			"IfUnauthenticated": func() { s.Trap("/t").IfUnauthenticated(ResponseConfig{Headers: h}) },
			"DefaultResponse":   func() { s.DefaultResponse(ResponseConfig{Headers: h}) },
			"TemplateResponse":  func() { s.TemplateResponse("t", ResponseTemplate{Headers: h}) },
		} {
			func() {
				defer func() {
					if recover() == nil {
						t.Fatalf("%s(%q) did not panic", name, h)
					}
				}()
				configure()
			}()
		}
	}
}

func TestTemplateResponseCarriesHeaders(t *testing.T) {
	s, _ := quietSentry("", "")
	s.TemplateResponse("bearer", ResponseTemplate{StatusCode: 401, Body: map[string]any{"detail": "Not authenticated"},
		Headers: map[string]string{"WWW-Authenticate": "Bearer"}})
	trap := s.Trap("/t").IfUnauthenticated(ResponseConfig{Template: "bearer"}).Build()
	body, cfg := s.triggerTrapEvent(nil, trap)
	if string(body) != `{"detail":"Not authenticated"}` || cfg.MIMEType != "application/json" ||
		!reflect.DeepEqual(cfg.Headers, map[string]string{"WWW-Authenticate": "Bearer"}) {
		t.Fatalf("got %q %+v", body, cfg)
	}
}

func TestConfiguredHeadersAreCopied(t *testing.T) {
	s, _ := quietSentry("", "")
	h := map[string]string{"Vary": "Accept"}
	b := s.Trap("/t").IfUnauthenticated(ResponseConfig{Headers: h})
	h["Vary"] = "changed"
	if _, cfg := s.triggerTrapEvent(nil, b.Build()); cfg.Headers["Vary"] != "Accept" {
		t.Fatalf("headers = %v", cfg.Headers)
	}
}
