package trappsec

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
		Event:     "trappsec.trap_hit",
		Type:      "alert",
		Timestamp: 1712011200,
		Path:      "/deployment/config",
		Method:    "GET",
		Intent:    "Recon",
		App:       AppInfo{Service: "svc", Environment: "dev", Hostname: "h1"},
	})
	if err != nil {
		t.Fatalf("emit returned unexpected error: %v", err)
	}

	attachments, ok := payload["attachments"].([]any)
	if !ok || len(attachments) == 0 {
		t.Fatalf("expected slack attachments payload, got %#v", payload)
	}
	first, ok := attachments[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first attachment object, got %#v", attachments[0])
	}
	if text, _ := payload["text"].(string); text != "" {
		t.Fatalf("expected empty top-level text summary, got %q", text)
	}
	blocks, ok := first["blocks"].([]any)
	if !ok || len(blocks) == 0 {
		t.Fatalf("expected slack blocks payload, got %#v", payload)
	}
	firstBlock, ok := blocks[0].(map[string]any)
	if !ok {
		t.Fatalf("expected first block object, got %#v", blocks[0])
	}
	textObj, ok := firstBlock["text"].(map[string]any)
	if !ok {
		t.Fatalf("expected first block text object, got %#v", firstBlock["text"])
	}
	text, _ := textObj["text"].(string)
	if !strings.Contains(text, "*Event:* Decoy Route Triggered") {
		t.Fatalf("expected event line, got %q", text)
	}
	if !strings.Contains(text, "*Timestamp:* <!date^1712011200^") {
		t.Fatalf("expected slack date token in timestamp, got %q", text)
	}
}
