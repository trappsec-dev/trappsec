// Package adapter is the API the framework adapters (nethttp, gin, echo) use
// to drive a Sentry. It is internal so that it is not part of the
// application-facing API.
package adapter

import (
	"net/http"

	core "github.com/trappsec-dev/trappsec/packages/go"
	"github.com/trappsec-dev/trappsec/packages/go/internal/hooks"
)

// InspectWatch applies a watch to the request: it detects and strips honey
// fields in the query and body and emits a watch_hit event.
func InspectWatch(s *core.Sentry, r *http.Request, reqObj any, watch core.WatchConfig, maxBody int64) {
	hooks.InspectWatch(s, r, reqObj, watch, maxBody)
}

// TriggerTrapEvent emits a trap_hit event and returns the response to send.
func TriggerTrapEvent(s *core.Sentry, req any, trap core.TrapConfig) ([]byte, core.ResponseTemplate) {
	payload, cfg := hooks.TriggerTrapEvent(s, req, trap)
	return payload, cfg.(core.ResponseTemplate)
}

// SetBodyResolver registers the adapter's resolver for framework-typed
// dynamic response bodies (e.g. func(*gin.Context) any).
func SetBodyResolver(s *core.Sentry, fn func(body any, req any) any) {
	hooks.SetBodyResolver(s, fn)
}
