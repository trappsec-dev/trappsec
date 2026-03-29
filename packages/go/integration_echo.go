package trappsec

import (
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"sync"

	"github.com/labstack/echo/v4"
)

type echoIntegration struct {
	ts       *Sentry
	once     sync.Once
	trapIdx  map[string]TrapConfig
	watchIdx map[string]WatchConfig
}

func newEchoIntegration(ts *Sentry, app *echo.Echo) *echoIntegration {
	in := &echoIntegration{ts: ts}

	if ts.Identity.IP == nil {
		ts.Identity.IP = func(req any) string {
			if c, ok := req.(echo.Context); ok {
				return c.RealIP()
			}
			return "0.0.0.0"
		}
	}

	ts.Request.Path = func(req any) string {
		if c, ok := req.(echo.Context); ok {
			return c.Request().URL.Path
		}
		return ""
	}
	ts.Request.UserAgent = func(req any) string {
		if c, ok := req.(echo.Context); ok {
			return c.Request().UserAgent()
		}
		return ""
	}
	ts.Request.Method = func(req any) string {
		if c, ok := req.(echo.Context); ok {
			return c.Request().Method
		}
		return ""
	}

	app.Use(in.middleware())
	return in
}

func (in *echoIntegration) buildIndexes() {
	in.once.Do(func() {
		in.trapIdx = make(map[string]TrapConfig)
		for _, t := range in.ts.Traps() {
			in.trapIdx[t.Path] = t
		}
		in.watchIdx = make(map[string]WatchConfig)
		for _, w := range in.ts.Watches() {
			in.watchIdx[w.Path] = w
		}
	})
}

func (in *echoIntegration) middleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			in.buildIndexes()
			path := c.Path()
			if path == "" {
				path = c.Request().URL.Path
			}
			method := c.Request().Method

			if trap, ok := in.trapIdx[path]; ok && methodAllowed(method, trap.Methods) {
				body, cfg := in.ts.triggerTrapEvent(c, trap)
				if cfg.MIMEType == "" {
					cfg.MIMEType = "application/json"
				}
				return c.Blob(cfg.StatusCode, cfg.MIMEType, body)
			}

			if watch, ok := in.watchIdx[path]; ok {
				found := make([]FoundField, 0)

				if len(watch.QueryFields) > 0 {
					qData := queryToMap(c.QueryParams())
					sanitized, f := in.ts.detectHoneyFields(qData, watch.QueryFields, c)
					if len(f) > 0 {
						for i := range f {
							f[i].Type = "query"
						}
						found = append(found, f...)
						c.Request().URL.RawQuery = mapToQuery(sanitized)
					}
				}

				if len(watch.BodyFields) > 0 {
					contentType := c.Request().Header.Get("Content-Type")
					bodyBytes := readEchoBody(c)
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
									resetBody(c.Request(), newBody)
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
									resetBody(c.Request(), []byte(mapToQuery(sanitized)))
								}
							}
						}
					}
				}

				if len(found) > 0 {
					in.ts.triggerWatchEvent(c, found)
				}
			}

			return next(c)
		}
	}
}

func readEchoBody(c echo.Context) []byte {
	if c.Request().Body == nil {
		return nil
	}
	data, _ := io.ReadAll(c.Request().Body)
	resetBody(c.Request(), data)
	return data
}
