package trappsec

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func boolPtr(v bool) *bool {
	return &v
}

func TestWebhookHandlerDefaultsToAlertsOnly(t *testing.T) {
	var posts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&posts, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	h, err := NewWebhookHandler(server.URL, nil)
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

func TestWebhookHandlerCanDisableAlertsOnly(t *testing.T) {
	var posts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&posts, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	h, err := NewWebhookHandler(server.URL, &WebhookOptions{AlertsOnly: boolPtr(false)})
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	if err := h.Emit(TriggerContext{Event: "trappsec.watch_hit", Type: "signal"}); err != nil {
		t.Fatalf("emit returned unexpected error: %v", err)
	}

	if got := atomic.LoadInt32(&posts); got != 1 {
		t.Fatalf("expected one webhook post for signal event, got %d", got)
	}
}
