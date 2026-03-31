package trappsec

import (
	"encoding/json"
	"testing"
)

type captureHandler struct {
	events []TriggerContext
}

func (h *captureHandler) Emit(event TriggerContext) error {
	h.events = append(h.events, event)
	return nil
}

func TestTriggerWatchEventEmitsSignal(t *testing.T) {
	s := NewSentry("svc", "test")
	capture := &captureHandler{}
	s.handlers = []EventHandler{capture}
	s.Identity.IP = func(_ any) string { return "1.2.3.4" }
	s.Request.Path = func(_ any) string { return "/a" }
	s.Request.Method = func(_ any) string { return "GET" }
	s.Request.UserAgent = func(_ any) string { return "ua" }

	s.TriggerWatchEvent(struct{}{}, []FoundField{{Type: "query", Field: "x"}})

	if len(capture.events) != 1 {
		t.Fatalf("expected one event, got %d", len(capture.events))
	}
	ev := capture.events[0]
	if ev.Event != "trappsec.watch_hit" || ev.Type != "signal" {
		t.Fatalf("unexpected event payload: %+v", ev)
	}
	if ev.Path != "/a" || ev.Method != "GET" || ev.IP != "1.2.3.4" {
		t.Fatalf("unexpected request context: %+v", ev)
	}
}

func TestTriggerTrapEventUsesAuthenticatedResponse(t *testing.T) {
	s := NewSentry("svc", "test")
	capture := &captureHandler{}
	s.handlers = []EventHandler{capture}
	s.Identity.IP = func(_ any) string { return "1.2.3.4" }
	s.Identity.Auth = func(_ any) *AuthContext { return &AuthContext{User: "u1", Role: "admin"} }
	s.Request.Path = func(_ any) string { return "/trap" }
	s.Request.Method = func(_ any) string { return "POST" }
	s.Request.UserAgent = func(_ any) string { return "ua" }

	trap := TrapConfig{
		Path:    "/trap",
		Methods: []string{"GET"},
		Intent:  "Recon",
		ResponseAuthenticated: ResponseTemplate{
			StatusCode: 201,
			Body:       map[string]any{"ok": true},
			MIMEType:   "application/json",
		},
		ResponseUnauthenticated: ResponseTemplate{
			StatusCode: 401,
			Body:       map[string]any{"ok": false},
			MIMEType:   "application/json",
		},
	}

	body, cfg := s.TriggerTrapEvent(struct{}{}, trap)
	if cfg.StatusCode != 201 {
		t.Fatalf("expected 201, got %d", cfg.StatusCode)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("failed to parse json response: %v", err)
	}
	if payload["ok"] != true {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	if len(capture.events) != 1 || capture.events[0].Type != "alert" {
		t.Fatalf("expected one alert event, got %+v", capture.events)
	}
}

func TestTrapAndWatchBuildersBasicShape(t *testing.T) {
	s := NewSentry("svc", "test")
	s.Template("gone", 410, map[string]any{"error": "gone"}, "application/json")

	trapCfg := newTrapBuilder(s, "/trap").
		Methods(" put ", "").
		Intent("Recon").
		Respond(ResponseConfig{Status: 418, Body: map[string]any{"x": 1}, MIMEType: "application/json"}).
		IfUnauthenticated(ResponseConfig{Template: "gone"}).
		Build()

	if len(trapCfg.Methods) != 1 || trapCfg.Methods[0] != "PUT" {
		t.Fatalf("unexpected methods: %+v", trapCfg.Methods)
	}
	if trapCfg.ResponseAuthenticated.StatusCode != 418 {
		t.Fatalf("unexpected auth status: %d", trapCfg.ResponseAuthenticated.StatusCode)
	}
	if trapCfg.ResponseUnauthenticated.StatusCode != 410 {
		t.Fatalf("unexpected unauth status: %d", trapCfg.ResponseUnauthenticated.StatusCode)
	}

	watchCfg := newWatchBuilder(s, "/login").
		Query("role", "user", "x").
		Body("token", NoDefault, "y").
		Build()
	if watchCfg.Path != "/login" {
		t.Fatalf("unexpected path: %s", watchCfg.Path)
	}
	if _, ok := watchCfg.QueryFields["role"]; !ok {
		t.Fatalf("expected query field role")
	}
	if _, ok := watchCfg.BodyFields["token"]; !ok {
		t.Fatalf("expected body field token")
	}
}
