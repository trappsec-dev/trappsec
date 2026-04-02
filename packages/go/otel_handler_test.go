package trappsec

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestOTELHandlerAnnotatesActiveSpan(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	defer func() { _ = tp.Shutdown(context.Background()) }()

	ctx, span := tp.Tracer("trappsec-test").Start(context.Background(), "request")

	h := &OTELHandler{}
	err := h.EmitWithContext(ctx, TriggerContext{
		Event: "trappsec.watch_hit",
		Type:  "alert",
		User:  "u-123",
		Role:  "admin",
		IP:    "1.2.3.4",
		Found: []FoundField{
			{Type: "body", Field: "is_admin", Value: true, Intent: "PrivEsc"},
		},
		Metadata: map[string]any{
			"attempt": 3,
		},
	})
	if err != nil {
		t.Fatalf("emit returned error: %v", err)
	}

	span.End()

	ended := recorder.Ended()
	if len(ended) != 1 {
		t.Fatalf("expected one ended span, got %d", len(ended))
	}

	attrMap := make(map[attribute.Key]attribute.Value)
	for _, kv := range ended[0].Attributes() {
		attrMap[kv.Key] = kv.Value
	}

	if got := attrMap["trappsec.detected"].AsBool(); !got {
		t.Fatalf("expected trappsec.detected=true, got false")
	}
	if got := attrMap["trappsec.event"].AsString(); got != "trappsec.watch_hit" {
		t.Fatalf("unexpected trappsec.event: %q", got)
	}
	if got := attrMap["trappsec.type"].AsString(); got != "alert" {
		t.Fatalf("unexpected trappsec.type: %q", got)
	}
	if got := attrMap["trappsec.user"].AsString(); got != "u-123" {
		t.Fatalf("unexpected trappsec.user: %q", got)
	}
	if got := attrMap["metadata.attempt"].AsInt64(); got != 3 {
		t.Fatalf("unexpected metadata.attempt: %d", got)
	}

	events := ended[0].Events()
	if len(events) != 1 || events[0].Name != "watch_hit" {
		t.Fatalf("expected a single watch_hit span event, got %+v", events)
	}
}

func TestOTELHandlerNoContextNoop(t *testing.T) {
	h := &OTELHandler{}
	if err := h.Emit(TriggerContext{Event: "trappsec.trap_hit", Type: "alert"}); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}
