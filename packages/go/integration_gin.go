package trappsec

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
)

type ginIntegration struct {
	ts *Sentry
}

func newGinIntegration(ts *Sentry, app *gin.Engine) *ginIntegration {
	in := &ginIntegration{ts: ts}

	if ts.Identity.IP == nil {
		ts.Identity.IP = func(req any) string {
			if c, ok := req.(*gin.Context); ok {
				return c.ClientIP()
			}
			return "0.0.0.0"
		}
	}

	ts.Request.Path = func(req any) string {
		if c, ok := req.(*gin.Context); ok {
			return c.Request.URL.Path
		}
		return ""
	}
	ts.Request.UserAgent = func(req any) string {
		if c, ok := req.(*gin.Context); ok {
			return c.Request.UserAgent()
		}
		return ""
	}
	ts.Request.Method = func(req any) string {
		if c, ok := req.(*gin.Context); ok {
			return c.Request.Method
		}
		return ""
	}

	app.Use(in.middleware())
	return in
}

func (in *ginIntegration) middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.FullPath()
		if path == "" {
			path = c.Request.URL.Path
		}
		method := c.Request.Method

		for _, trap := range in.ts.trapsForPath(path) {
			if methodAllowed(method, trap.Methods) {
				body, cfg := in.ts.triggerTrapEvent(c, trap)
				c.Data(cfg.StatusCode, cfg.MIMEType, body)
				c.Abort()
				return
			}
		}

		for _, watch := range in.ts.watchesForPath(path) {
			found := make([]FoundField, 0)

			if len(watch.QueryFields) > 0 {
				qData := queryToMap(c.Request.URL.Query())
				sanitized, f := in.ts.detectHoneyFields(qData, watch.QueryFields, c)
				if len(f) > 0 {
					for i := range f {
						f[i].Type = "query"
					}
					found = append(found, f...)
					c.Request.URL.RawQuery = mapToQuery(sanitized)
				}
			}

			if len(watch.BodyFields) > 0 {
				bodyBytes, _ := c.GetRawData()
				contentType := c.GetHeader("Content-Type")
				if len(bodyBytes) > 0 {
					if strings.Contains(contentType, "application/json") {
						var data map[string]any
						if err := json.Unmarshal(bodyBytes, &data); err == nil {
							sanitized, f := in.ts.detectHoneyFields(data, watch.BodyFields, c)
							if len(f) > 0 {
								for i := range f {
									f[i].Type = "body"
								}
								found = append(found, f...)
								newBody, _ := json.Marshal(sanitized)
								resetBody(c.Request, newBody)
							}
						}
					} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
						vals, err := url.ParseQuery(string(bodyBytes))
						if err == nil {
							form := queryToMap(vals)
							sanitized, f := in.ts.detectHoneyFields(form, watch.BodyFields, c)
							if len(f) > 0 {
								for i := range f {
									f[i].Type = "body"
								}
								found = append(found, f...)
								resetBody(c.Request, []byte(mapToQuery(sanitized)))
							}
						}
					}
				}
			}

			if len(found) > 0 {
				in.ts.triggerWatchEvent(c, found)
			}
		}

		c.Next()
	}
}

// WrapHTTPHandler can be used with routers built on net/http.
func (s *Sentry) WrapHTTPHandler(next http.Handler) http.Handler {
	in := &netHTTPServerIntegration{ts: s}
	return in.wrap(next)
}
