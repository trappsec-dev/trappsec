package trappsec

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestSlackHandlerDefaultsToAlertsOnly(t *testing.T) {
	var posts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&posts, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	h, err := NewSlackHandler(server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	if err := h.Emit(TriggerContext{Event: "trappsec.watch_hit", Type: "signal"}); err != nil {
		t.Fatalf("emit returned unexpected error: %v", err)
	}

	if got := atomic.LoadInt32(&posts); got != 0 {
		t.Fatalf("expected no webhook posts for signal event, got %d", got)
	}
}

func TestSlackHandlerFormatsBlocksPayload(t *testing.T) {
	var payload map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	h, err := NewSlackHandler(server.URL, &SlackOptions{AlertsOnly: boolPtr(false)})
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	err = h.Emit(TriggerContext{
		Event:  "trappsec.trap_hit",
		Type:   "alert",
		Path:   "/deployment/config",
		Method: "GET",
		Intent: "Recon",
		App:    AppInfo{Service: "svc", Environment: "dev", Hostname: "h1"},
	})
	if err != nil {
		t.Fatalf("emit returned unexpected error: %v", err)
	}

	blocks, ok := payload["blocks"].([]any)
	if !ok || len(blocks) == 0 {
		t.Fatalf("expected slack blocks payload, got %#v", payload)
	}
}
