// Package trappsecgin integrates trappsec with the Gin web framework.
//
// Usage:
//
//	r := gin.New()
//	ts := trappsecgin.NewSentry(r, "my-service", "production")
package trappsecgin

import (
	"encoding/json"
	"net/url"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	core "github.com/trappsec-dev/trappsec/packages/go"
)

// Re-export core types as aliases so callers need only one import.
type (
	Sentry         = core.Sentry
	AuthContext     = core.AuthContext
	ResponseConfig  = core.ResponseConfig
	TrapConfig      = core.TrapConfig
	WatchConfig     = core.WatchConfig
	WatchFieldRule  = core.WatchFieldRule
	FoundField      = core.FoundField
	TriggerContext  = core.TriggerContext
	AppInfo         = core.AppInfo
	WebhookOptions  = core.WebhookOptions
	EventHandler    = core.EventHandler
)

// NoDefault is re-exported from core so callers need only one import.
var NoDefault = core.NoDefault

// NewSentry creates a Sentry and wires trappsec middleware onto the given Gin engine.
func NewSentry(app *gin.Engine, service, environment string) *Sentry {
	s := core.NewSentry(service, environment)
	Use(s, app)
	return s
}

type ginIntegration struct {
	ts       *core.Sentry
	once     sync.Once
	trapIdx  map[string]core.TrapConfig
	watchIdx map[string]core.WatchConfig
}

// Use wires up the trappsec middleware on the given Gin engine.
func Use(s *core.Sentry, app *gin.Engine) {
	in := &ginIntegration{ts: s}

	if s.Identity.IP == nil {
		s.Identity.IP = func(req any) string {
			if c, ok := req.(*gin.Context); ok {
				return c.ClientIP()
			}
			return "0.0.0.0"
		}
	}

	s.Request.Path = func(req any) string {
		if c, ok := req.(*gin.Context); ok {
			return c.Request.URL.Path
		}
		return ""
	}
	s.Request.UserAgent = func(req any) string {
		if c, ok := req.(*gin.Context); ok {
			return c.Request.UserAgent()
		}
		return ""
	}
	s.Request.Method = func(req any) string {
		if c, ok := req.(*gin.Context); ok {
			return c.Request.Method
		}
		return ""
	}

	s.SetBodyResolver(func(body any, req any) any {
		if fn, ok := body.(func(*gin.Context) any); ok {
			if c, ok := req.(*gin.Context); ok {
				return fn(c)
			}
		}
		return body
	})

	app.Use(in.middleware())
}

func (in *ginIntegration) buildIndexes() {
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

func (in *ginIntegration) middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		in.buildIndexes()
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}
		method := c.Request.Method

		if trap, ok := in.trapIdx[path]; ok && core.MethodAllowed(method, trap.Methods) {
			body, cfg := in.ts.TriggerTrapEvent(c, trap)
			c.Data(cfg.StatusCode, cfg.MIMEType, body)
			c.Abort()
			return
		}

		if watch, ok := in.watchIdx[path]; ok {
			found := make([]core.FoundField, 0)

			if len(watch.QueryFields) > 0 {
				qData := core.QueryToMap(c.Request.URL.Query())
				sanitized, f := in.ts.DetectHoneyFields(qData, watch.QueryFields, c)
				if len(f) > 0 {
					for i := range f {
						f[i].Type = "query"
					}
					found = append(found, f...)
					c.Request.URL.RawQuery = core.MapToQuery(sanitized)
				}
			}

			if len(watch.BodyFields) > 0 {
				bodyBytes := core.ReadBody(c.Request)
				contentType := c.GetHeader("Content-Type")
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
								core.ResetBody(c.Request, newBody)
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
								core.ResetBody(c.Request, []byte(core.MapToQuery(sanitized)))
							}
						}
					}
				}
			}

			if len(found) > 0 {
				in.ts.TriggerWatchEvent(c, found)
			}
		}

		c.Next()
	}
}
