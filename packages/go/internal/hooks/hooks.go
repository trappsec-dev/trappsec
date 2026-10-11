// Package hooks carries the adapter-only operations of package trappsec to
// package adapter without exporting them from trappsec. trappsec fills these
// in at init; the arguments and results are trappsec types.
package hooks

import "net/http"

var (
	InspectWatch     func(s any, r *http.Request, reqObj any, watch any, maxBody int64)
	TriggerTrapEvent func(s any, req any, trap any) (payload []byte, cfg any)
	SetBodyResolver  func(s any, fn func(body any, req any) any)
)
