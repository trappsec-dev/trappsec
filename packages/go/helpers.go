package trappsec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// MethodAllowed reports whether method is in the allowed list (case-insensitive).
func MethodAllowed(method string, allowed []string) bool {
	for _, m := range allowed {
		if strings.EqualFold(method, m) {
			return true
		}
	}
	return false
}

// QueryToMap converts url.Values to a map[string]any suitable for DetectHoneyFields.
func QueryToMap(vals url.Values) map[string]any {
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

// MapToQuery encodes a map[string]any back to a URL query string.
func MapToQuery(data map[string]any) string {
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

// ReadBody reads r.Body fully and restores it so downstream handlers can re-read it.
func ReadBody(r *http.Request) []byte {
	if r.Body == nil {
		return nil
	}
	data, _ := io.ReadAll(r.Body)
	ResetBody(r, data)
	return data
}

// ResetBody replaces r.Body with a fresh reader containing data.
func ResetBody(r *http.Request, data []byte) {
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
