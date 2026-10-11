package trappsec

import (
	"net/http"

	"github.com/trappsec-dev/trappsec/packages/go/internal/hooks"
)

func init() {
	hooks.InspectWatch = func(s any, r *http.Request, reqObj any, watch any, maxBody int64) {
		inspectWatch(s.(*Sentry), r, reqObj, watch.(WatchConfig), maxBody)
	}
	hooks.TriggerTrapEvent = func(s any, req any, trap any) ([]byte, any) {
		return s.(*Sentry).triggerTrapEvent(req, trap.(TrapConfig))
	}
	hooks.SetBodyResolver = func(s any, fn func(body any, req any) any) {
		s.(*Sentry).setBodyResolver(fn)
	}
}

// InspectWatch is used by framework adapters.
//
// Deprecated: not part of the application API; kept so that adapter modules
// older than 0.3 build against this version.
func InspectWatch(s *Sentry, r *http.Request, reqObj any, watch WatchConfig, maxBody int64) {
	inspectWatch(s, r, reqObj, watch, maxBody)
}

// TriggerTrapEvent is used by framework adapters.
//
// Deprecated: not part of the application API; kept so that adapter modules
// older than 0.3 build against this version.
func (s *Sentry) TriggerTrapEvent(req any, trap TrapConfig) ([]byte, ResponseTemplate) {
	return s.triggerTrapEvent(req, trap)
}

// SetBodyResolver is used by framework adapters.
//
// Deprecated: not part of the application API; kept so that adapter modules
// older than 0.3 build against this version.
func (s *Sentry) SetBodyResolver(fn func(body any, req any) any) {
	s.setBodyResolver(fn)
}
