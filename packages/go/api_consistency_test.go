package trappsec

import (
	"io"
	"log"
	"reflect"
	"testing"
)

func TestWatchFieldOptions(t *testing.T) {
	s := NewSentry("svc", "test")
	s.logger = log.New(io.Discard, "", 0)
	w := s.Watch("/x").
		Body("a", Default(false), Intent("PrivEsc")).
		Body("b", Intent("Recon")).
		Body("c").
		Body("d", Default(nil)).
		Query("legacy", "false", "Recon"). // pre-0.3 positional form
		Query("legacy_nodefault", NoDefault, "").
		Build()

	want := map[string]WatchFieldRule{
		"a": {Default: false, Intent: "PrivEsc"},
		"b": {Default: NoDefault, Intent: "Recon"},
		"c": {Default: NoDefault},
		"d": {Default: nil},
	}
	if !reflect.DeepEqual(w.BodyFields, want) {
		t.Fatalf("body fields = %#v", w.BodyFields)
	}
	if got := w.QueryFields["legacy"]; got != (WatchFieldRule{Default: "false", Intent: "Recon"}) {
		t.Fatalf("legacy query = %#v", got)
	}
	if got := w.QueryFields["legacy_nodefault"]; !isNoDefault(got.Default) || got.Intent != "" {
		t.Fatalf("legacy NoDefault query = %#v", got)
	}
}

func TestTriggerOptions(t *testing.T) {
	s := NewSentry("svc", "test")
	capture := &captureHandler{}
	s.handlers = []EventHandler{capture}

	s.Trigger(nil, "opts", Intent("fraud"), Metadata(map[string]any{"amount": 5}))
	s.Trigger(nil, "positional", "fraud", map[string]any{"amount": 6})
	s.Trigger(nil, "bare")

	got := capture.events
	if len(got) != 3 {
		t.Fatalf("events = %d", len(got))
	}
	if got[0].Intent != "fraud" || !reflect.DeepEqual(got[0].Metadata, map[string]any{"amount": 5}) {
		t.Fatalf("options form: %+v", got[0])
	}
	if got[1].Intent != "fraud" || !reflect.DeepEqual(got[1].Metadata, map[string]any{"amount": 6}) {
		t.Fatalf("positional form: %+v", got[1])
	}
	if got[2].Intent != "" || got[2].Metadata != nil || got[2].Reason != "bare" {
		t.Fatalf("bare: %+v", got[2])
	}
}

func TestDefaultResponseSetters(t *testing.T) {
	s := NewSentry("svc", "test")
	trap := s.Trap("/t")
	if s.DefaultResponse(ResponseConfig{Body: map[string]any{"ok": true}}) != s {
		t.Fatal("DefaultResponse must chain")
	}
	s.DefaultUnauthenticatedResponse(ResponseConfig{Status: 403, Body: "no", MIMEType: "text/plain"})
	cfg := trap.Build()
	if cfg.ResponseAuthenticated.StatusCode != 200 || !reflect.DeepEqual(cfg.ResponseAuthenticated.Body, map[string]any{"ok": true}) ||
		cfg.ResponseAuthenticated.MIMEType != "application/json" {
		t.Fatalf("authenticated = %+v", cfg.ResponseAuthenticated)
	}
	if cfg.ResponseUnauthenticated != (ResponseTemplate{StatusCode: 403, Body: "no", MIMEType: "text/plain"}) {
		t.Fatalf("unauthenticated = %+v", cfg.ResponseUnauthenticated)
	}

	s.Template("gone", 410, map[string]any{"error": "gone"}) // MIME type is optional
	s.DefaultUnauthenticatedResponse(ResponseConfig{Template: "gone"})
	got := s.Trap("/u").Build().ResponseUnauthenticated
	if got.StatusCode != 410 || got.MIMEType != "application/json" {
		t.Fatalf("template default = %+v", got)
	}
}

func TestIsTrapIndexFollowsTrapChanges(t *testing.T) {
	s := NewSentry("svc", "test")
	type req struct{ method, path string }
	s.Request.Method = func(r any) string { return r.(req).method }
	s.Request.Path = func(r any) string { return r.(req).path }

	tr := s.Trap("/admin/backup")
	s.Trap("/users/:id/export").Methods("GET")
	cases := []struct {
		r    req
		want bool
	}{
		{req{"GET", "/admin/backup"}, true},
		{req{"POST", "/admin/backup/"}, true},
		{req{"DELETE", "/admin/backup"}, false},
		{req{"GET", "/users/7/export"}, true},
		{req{"POST", "/users/7/export"}, false},
		{req{"GET", "/users//export"}, false},
	}
	for _, c := range cases {
		if got := s.IsTrap(c.r); got != c.want {
			t.Fatalf("IsTrap(%v) = %v, want %v", c.r, got, c.want)
		}
	}

	// The index is cached; changing methods or adding a trap must refresh it.
	tr.Methods("DELETE")
	if s.IsTrap(req{"GET", "/admin/backup"}) || !s.IsTrap(req{"DELETE", "/admin/backup"}) {
		t.Fatal("IsTrap did not follow a Methods() change")
	}
	s.Trap("/late")
	if !s.IsTrap(req{"GET", "/late"}) {
		t.Fatal("IsTrap did not see a trap added later")
	}
}
