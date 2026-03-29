package trappsec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type netHTTPServerIntegration struct {
	ts       *Sentry
	once     sync.Once
	trapIdx  map[string][]TrapConfig
	watchIdx map[string][]WatchConfig
}

func newNetHTTPServerIntegration(ts *Sentry, server *http.Server) *netHTTPServerIntegration {
	in := &netHTTPServerIntegration{ts: ts}

	if ts.Identity.IP == nil {
		ts.Identity.IP = func(req any) string {
			r, ok := req.(*http.Request)
			if !ok || r == nil {
				return "0.0.0.0"
			}
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			if err == nil {
				return host
			}
			return r.RemoteAddr
		}
	}

	ts.Request.Path = func(req any) string {
		r, _ := req.(*http.Request)
		if r == nil {
			return ""
		}
		return r.URL.Path
	}
	ts.Request.UserAgent = func(req any) string {
		r, _ := req.(*http.Request)
		if r == nil {
			return ""
		}
		return r.UserAgent()
	}
	ts.Request.Method = func(req any) string {
		r, _ := req.(*http.Request)
		if r == nil {
			return ""
		}
		return r.Method
	}

	next := server.Handler
	if next == nil {
		next = http.DefaultServeMux
	}
	server.Handler = in.wrap(next)
	return in
}

func (in *netHTTPServerIntegration) buildIndexes() {
	in.once.Do(func() {
		in.trapIdx = make(map[string][]TrapConfig)
		for _, t := range in.ts.Traps() {
			in.trapIdx[t.Path] = append(in.trapIdx[t.Path], t)
		}
		in.watchIdx = make(map[string][]WatchConfig)
		for _, w := range in.ts.Watches() {
			in.watchIdx[w.Path] = append(in.watchIdx[w.Path], w)
		}
	})
}

func (in *netHTTPServerIntegration) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in.buildIndexes()
		// r.Pattern is set by http.ServeMux (Go 1.22+) when used via WrapHTTPHandler.
		// When wrapping at the server level, routing hasn't occurred yet so r.Pattern
		// is empty; fall back to the raw URL path in that case.
		path := r.Pattern
		if path == "" {
			path = r.URL.Path
		}
		method := strings.ToUpper(r.Method)

		for _, trap := range in.trapIdx[path] {
			if methodAllowed(method, trap.Methods) {
				body, cfg := in.ts.triggerTrapEvent(r, trap)
				if cfg.MIMEType != "" {
					w.Header().Set("Content-Type", cfg.MIMEType)
				}
				w.WriteHeader(cfg.StatusCode)
				_, _ = w.Write(body)
				return
			}
		}

		for _, watch := range in.watchIdx[path] {
			found := make([]FoundField, 0)

			if len(watch.QueryFields) > 0 {
				qData := queryToMap(r.URL.Query())
				sanitized, f := in.ts.detectHoneyFields(qData, watch.QueryFields, r)
				if len(f) > 0 {
					for i := range f {
						f[i].Type = "query"
					}
					found = append(found, f...)
					r.URL.RawQuery = mapToQuery(sanitized)
				}
			}

			if len(watch.BodyFields) > 0 {
				contentType := r.Header.Get("Content-Type")
				bodyBytes := readBody(r)
				if len(bodyBytes) > 0 {
					if strings.Contains(contentType, "application/json") {
						var data map[string]any
						if err := json.Unmarshal(bodyBytes, &data); err == nil {
							sanitized, f := in.ts.detectHoneyFields(data, watch.BodyFields, r)
							if len(f) > 0 {
								for i := range f {
									f[i].Type = "body"
								}
								found = append(found, f...)
								newBody, _ := json.Marshal(sanitized)
								resetBody(r, newBody)
							}
						}
					} else if strings.Contains(contentType, "application/x-www-form-urlencoded") {
						vals, err := url.ParseQuery(string(bodyBytes))
						if err == nil {
							form := queryToMap(vals)
							sanitized, f := in.ts.detectHoneyFields(form, watch.BodyFields, r)
							if len(f) > 0 {
								for i := range f {
									f[i].Type = "body"
								}
								found = append(found, f...)
								newBody := mapToQuery(sanitized)
								resetBody(r, []byte(newBody))
							}
						}
					}
				}
			}

			if len(found) > 0 {
				in.ts.triggerWatchEvent(r, found)
			}
		}

		next.ServeHTTP(w, r)
	})
}

func methodAllowed(method string, allowed []string) bool {
	for _, m := range allowed {
		if strings.EqualFold(method, m) {
			return true
		}
	}
	return false
}

func queryToMap(vals url.Values) map[string]any {
	out := map[string]any{}
	for k, v := range vals {
		if len(v) == 1 {
			out[k] = v[0]
		} else {
			arr := make([]any, 0, len(v))
			for _, item := range v {
				arr = append(arr, item)
			}
			out[k] = arr
		}
	}
	return out
}

func mapToQuery(data map[string]any) string {
	vals := url.Values{}
	for k, v := range data {
		switch vv := v.(type) {
		case []any:
			for _, i := range vv {
				vals.Add(k, toString(i))
			}
		case []string:
			for _, i := range vv {
				vals.Add(k, i)
			}
		default:
			vals.Set(k, toString(vv))
		}
	}
	return vals.Encode()
}

func readBody(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	data, _ := io.ReadAll(r.Body)
	resetBody(r, data)
	return data
}

func resetBody(r *http.Request, data []byte) {
	r.Body = io.NopCloser(bytes.NewReader(data))
	r.ContentLength = int64(len(data))
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case int:
		return fmt.Sprintf("%d", t)
	case int64:
		return fmt.Sprintf("%d", t)
	case float64:
		return fmt.Sprintf("%v", t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}
