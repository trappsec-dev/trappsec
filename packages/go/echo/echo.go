// Package trappsececho integrates trappsec with the Echo web framework.
//
// Usage:
//
//	e := echo.New()
//	ts := trappsececho.NewSentry(e, "my-service", "production")
package trappsececho

import (
	"encoding/json"
	"net/url"
	"strings"
	"sync"

	"github.com/labstack/echo/v4"
	core "github.com/trappsec-dev/trappsec/packages/go"
)

// Re-export core types as aliases so callers need only one import.
type (
	Sentry        = core.Sentry
	AuthContext    = core.AuthContext
	ResponseConfig = core.ResponseConfig
	TrapConfig     = core.TrapConfig
	WatchConfig    = core.WatchConfig
	WatchFieldRule = core.WatchFieldRule
	FoundField     = core.FoundField
	TriggerContext = core.TriggerContext
	AppInfo        = core.AppInfo
	WebhookOptions = core.WebhookOptions
	EventHandler   = core.EventHandler
)

// NoDefault is re-exported from core so callers need only one import.
var NoDefault = core.NoDefault

// NewSentry creates a Sentry and wires trappsec middleware onto the given Echo instance.
func NewSentry(app *echo.Echo, service, environment string) *Sentry {
	s := core.NewSentry(service, environment)
	Use(s, app)
	return s
}

type echoIntegration struct {
	ts       *core.Sentry
	once     sync.Once
	trapIdx  map[string]core.TrapConfig
	watchIdx map[string]core.WatchConfig
}

// Use wires up the trappsec middleware on the given Echo instance.
//
// Two middleware registrations are used deliberately:
//   - app.Pre  — trap interception runs before Echo's router so that paths not
//     registered in Echo's own router are still caught.
//   - app.Use  — watch inspection runs after routing so that c.Path() carries
//     the route pattern (e.g. /users/:id) rather than the raw URL.
func Use(s *core.Sentry, app *echo.Echo) {
	in := &echoIntegration{ts: s}

	if s.Identity.IP == nil {
		s.Identity.IP = func(req any) string {
			if c, ok := req.(echo.Context); ok {
				return c.RealIP()
			}
			return "0.0.0.0"
		}
	}

	s.Request.Path = func(req any) string {
		if c, ok := req.(echo.Context); ok {
			return c.Request().URL.Path
		}
		return ""
	}
	s.Request.UserAgent = func(req any) string {
		if c, ok := req.(echo.Context); ok {
			return c.Request().UserAgent()
		}
		return ""
	}
	s.Request.Method = func(req any) string {
		if c, ok := req.(echo.Context); ok {
			return c.Request().Method
		}
		return ""
	}

	s.SetBodyResolver(func(body any, req any) any {
		if fn, ok := body.(func(echo.Context) any); ok {
			if c, ok := req.(echo.Context); ok {
				return fn(c)
			}
		}
		return body
	})

	// Pre-routing: trap paths are not registered in Echo's router, so they must
	// be intercepted before routing occurs.
	app.Pre(in.trapMiddleware())

	// Post-routing: watches need the resolved route pattern from c.Path().
	app.Use(in.watchMiddleware())
}

func (in *echoIntegration) buildIndexes() {
	in.once.Do(func() {
		in.trapIdx = make(map[string]core.TrapConfig)
		for _, t := range in.ts.Traps() {
			in.trapIdx[t.Path] = t
		}
		in.watchIdx = make(map[string]core.WatchConfig)
		for _, w := range in.ts.Watches() {
			in.watchIdx[w.Path] = w
		}
	})
}

// trapMiddleware runs via app.Pre() — before Echo's router.
// It matches against the raw URL path since no route pattern is available yet.
func (in *echoIntegration) trapMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			in.buildIndexes()
			path := c.Request().URL.Path
			method := c.Request().Method

			if trap, ok := in.trapIdx[path]; ok && core.MethodAllowed(method, trap.Methods) {
				body, cfg := in.ts.TriggerTrapEvent(c, trap)
				return c.Blob(cfg.StatusCode, cfg.MIMEType, body)
			}

			return next(c)
		}
	}
}

// watchMiddleware runs via app.Use() — after Echo's router has matched the route.
// c.Path() returns the route pattern (e.g. /users/:id) at this point.
func (in *echoIntegration) watchMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			in.buildIndexes()
			path := c.Path()

			if watch, ok := in.watchIdx[path]; ok {
				found := make([]core.FoundField, 0)

				if len(watch.QueryFields) > 0 {
					qData := core.QueryToMap(c.Request().URL.Query())
					sanitized, f := in.ts.DetectHoneyFields(qData, watch.QueryFields, c)
					if len(f) > 0 {
						for i := range f {
							f[i].Type = "query"
						}
						found = append(found, f...)
						c.Request().URL.RawQuery = core.MapToQuery(sanitized)
					}
				}

				if len(watch.BodyFields) > 0 {
					r := c.Request()
					bodyBytes := core.ReadBody(r)
					contentType := r.Header.Get("Content-Type")
					if len(bodyBytes) > 0 {
						if strings.Contains(contentType, "application/json") {
							var data map[string]any
							if err := json.Unmarshal(bodyBytes, &data); err == nil {
								sanitized, f := in.ts.DetectHoneyFields(data, watch.BodyFields, c)
								if len(f) > 0 {
									for i := range f {
										f[i].Type = "body"
									}
									found = append(found, f...)
									newBody, _ := json.Marshal(sanitized)
									core.ResetBody(r, newBody)
								}
							}
						} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
							vals, err := url.ParseQuery(string(bodyBytes))
							if err == nil {
								form := core.QueryToMap(vals)
								sanitized, f := in.ts.DetectHoneyFields(form, watch.BodyFields, c)
								if len(f) > 0 {
									for i := range f {
										f[i].Type = "body"
									}
									found = append(found, f...)
									core.ResetBody(r, []byte(core.MapToQuery(sanitized)))
								}
							}
						}
					}
				}

				if len(found) > 0 {
					in.ts.TriggerWatchEvent(c, found)
				}
			}

			return next(c)
		}
	}
}
