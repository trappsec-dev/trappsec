package trappsec

// Direct tests of the shared adapter helpers. The nethttp, gin and echo
// modules exercise them through real routers; these pin the behaviour in the
// core package itself.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func inspectEnv(t *testing.T) (*Sentry, *captureHandler, WatchConfig) {
	t.Helper()
	s := NewSentry("svc", "test")
	capture := &captureHandler{}
	s.handlers = []EventHandler{capture}
	watch := WatchConfig{
		Path:        "/w",
		QueryFields: map[string]WatchFieldRule{"debug": {Default: NoDefault, Intent: "q"}},
		BodyFields: map[string]WatchFieldRule{
			"is_admin": {Default: NoDefault, Intent: "b"},
			"role":     {Default: "user", Intent: "r"},
		},
	}
	return s, capture, watch
}

func readAll(t *testing.T, r *http.Request) string {
	t.Helper()
	b, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

func TestInspectWatchQueryStripKeepsOtherValues(t *testing.T) {
	s, capture, watch := inspectEnv(t)
	r := httptest.NewRequest("GET", "/w?debug=1&a=1&a=2", nil)
	inspectWatch(s, r, r, watch, 0)
	if got := r.URL.Query(); got.Has("debug") || strings.Join(got["a"], ",") != "1,2" {
		t.Fatalf("query after strip = %v", got)
	}
	if len(capture.events) != 1 || capture.events[0].Found[0].Type != "query" {
		t.Fatalf("events = %+v", capture.events)
	}
}

func TestInspectWatchJSONStripUpdatesLength(t *testing.T) {
	s, capture, watch := inspectEnv(t)
	body := `{"is_admin":true,"role":"user","name":"a"}`
	r := httptest.NewRequest("POST", "/w", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json; charset=utf-8")
	inspectWatch(s, r, r, watch, 0)
	got := readAll(t, r)
	if got != `{"name":"a"}` {
		t.Fatalf("body = %s", got)
	}
	if r.ContentLength != int64(len(got)) || r.Header.Get("Content-Length") != "12" {
		t.Fatalf("length not updated: %d / %q", r.ContentLength, r.Header.Get("Content-Length"))
	}
	if len(capture.events) != 1 || len(capture.events[0].Found) != 1 || capture.events[0].Found[0].Field != "is_admin" {
		t.Fatalf("events = %+v", capture.events)
	}
}

func TestInspectWatchJSONWithoutContentTypeIsInspected(t *testing.T) {
	for _, ct := range []string{"", "text/plain", "application/vnd.api+json"} {
		s, capture, watch := inspectEnv(t)
		r := httptest.NewRequest("POST", "/w", strings.NewReader(` {"is_admin":1}`))
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		inspectWatch(s, r, r, watch, 0)
		if got := readAll(t, r); got != `{}` || len(capture.events) != 1 {
			t.Fatalf("ct=%q: body=%s events=%d", ct, got, len(capture.events))
		}
	}
}

func TestInspectWatchUntouchedBodyIsByteIdentical(t *testing.T) {
	s, capture, watch := inspectEnv(t)
	body := "{ \"name\" : \"a\",\n \"n\": 1.50 }"
	r := httptest.NewRequest("POST", "/w", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	inspectWatch(s, r, r, watch, 0)
	if got := readAll(t, r); got != body || len(capture.events) != 0 {
		t.Fatalf("body changed: %q (events %d)", got, len(capture.events))
	}
}

func TestInspectWatchTrailingDataCannotBypass(t *testing.T) {
	cases := []struct{ body, want string }{
		{`{"is_admin":true} trailing`, `{} trailing`},
		{`{"is_admin":true}{"is_admin":1}`, "{}\n{}"},
		{"{\"is_admin\":true}\n[{\"role\":\"admin\"}] x", "{}\n[{}] x"},
	}
	for _, c := range cases {
		s, capture, watch := inspectEnv(t)
		r := httptest.NewRequest("POST", "/w", strings.NewReader(c.body))
		r.Header.Set("Content-Type", "application/json")
		inspectWatch(s, r, r, watch, 0)
		if got := readAll(t, r); got != c.want {
			t.Fatalf("%q: body = %q, want %q", c.body, got, c.want)
		}
		if len(capture.events) != 1 {
			t.Fatalf("%q: events = %d", c.body, len(capture.events))
		}
	}
}

func TestInspectWatchUnparseableJSONLeftAlone(t *testing.T) {
	s, capture, watch := inspectEnv(t)
	body := `{"is_admin":tru`
	r := httptest.NewRequest("POST", "/w", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	inspectWatch(s, r, r, watch, 0)
	if got := readAll(t, r); got != body || len(capture.events) != 0 {
		t.Fatalf("body=%q events=%d", got, len(capture.events))
	}
}

func TestInspectWatchFormStripPreservesMultiValues(t *testing.T) {
	s, capture, watch := inspectEnv(t)
	r := httptest.NewRequest("POST", "/w", strings.NewReader("role=admin&tag=a&tag=b"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	inspectWatch(s, r, r, watch, 0)
	vals, _ := url.ParseQuery(readAll(t, r))
	if vals.Has("role") || strings.Join(vals["tag"], ",") != "a,b" {
		t.Fatalf("form after strip = %v", vals)
	}
	if len(capture.events) != 1 || capture.events[0].Found[0].Value != "admin" {
		t.Fatalf("events = %+v", capture.events)
	}
}

func TestInspectWatchMultipartStripKeepsFileParts(t *testing.T) {
	s, capture, watch := inspectEnv(t)
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	_ = w.WriteField("is_admin", "true")
	_ = w.WriteField("name", "a")
	fw, _ := w.CreateFormFile("upload", "f.txt")
	_, _ = fw.Write([]byte("file-bytes"))
	_ = w.Close()

	r := httptest.NewRequest("POST", "/w", &buf)
	r.Header.Set("Content-Type", w.FormDataContentType())
	inspectWatch(s, r, r, watch, 0)

	if err := r.ParseMultipartForm(1 << 20); err != nil {
		t.Fatalf("rewritten body is not valid multipart: %v", err)
	}
	if _, ok := r.MultipartForm.Value["is_admin"]; ok || r.MultipartForm.Value["name"][0] != "a" {
		t.Fatalf("fields after strip = %v", r.MultipartForm.Value)
	}
	fh := r.MultipartForm.File["upload"]
	if len(fh) != 1 || fh[0].Filename != "f.txt" {
		t.Fatalf("file part lost: %v", r.MultipartForm.File)
	}
	f, _ := fh[0].Open()
	if b, _ := io.ReadAll(f); string(b) != "file-bytes" {
		t.Fatalf("file contents = %q", b)
	}
	if len(capture.events) != 1 {
		t.Fatalf("events = %d", len(capture.events))
	}
}

func TestInspectWatchOversizeBodyPassesThrough(t *testing.T) {
	body := `{"is_admin":true,"pad":"` + strings.Repeat("a", 500) + `"}`
	for _, chunked := range []bool{false, true} {
		s, capture, watch := inspectEnv(t)
		r := httptest.NewRequest("POST", "/w", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if chunked {
			r.ContentLength = -1
		}
		inspectWatch(s, r, r, watch, 100)
		if got := readAll(t, r); got != body || len(capture.events) != 0 {
			t.Fatalf("chunked=%v: body intact=%v events=%d", chunked, got == body, len(capture.events))
		}
	}
}

func TestInspectWatchRecoversFromPanickingDefault(t *testing.T) {
	s, _, watch := inspectEnv(t)
	watch.BodyFields["role"] = WatchFieldRule{Default: func(any) any { panic("boom") }, Intent: "r"}
	r := httptest.NewRequest("POST", "/w", strings.NewReader(`{"role":"user","name":"a"}`))
	r.Header.Set("Content-Type", "application/json")
	inspectWatch(s, r, r, watch, 0)
	if got := readAll(t, r); got != `{"name":"a"}` {
		t.Fatalf("field must be stripped even when the default panics: %s", got)
	}
}

func TestReadBodyLimitRestoresStream(t *testing.T) {
	r := httptest.NewRequest("POST", "/", strings.NewReader("0123456789"))
	if data, ok := readBodyLimit(r, 4); data != nil || ok {
		t.Fatalf("over limit: data=%q ok=%v", data, ok)
	}
	if got := readAll(t, r); got != "0123456789" {
		t.Fatalf("stream not restored: %q", got)
	}

	boom := errors.New("boom")
	r = httptest.NewRequest("POST", "/", io.MultiReader(strings.NewReader("ab"), errReader{boom}))
	if _, ok := readBodyLimit(r, 100); ok {
		t.Fatal("read error must report !ok")
	}
	b, err := io.ReadAll(r.Body)
	if string(b) != "ab" || !errors.Is(err, boom) {
		t.Fatalf("downstream must see the same bytes then the error: %q, %v", b, err)
	}
}

func TestQueryMapRoundTripAndMethodAllowed(t *testing.T) {
	vals := url.Values{"a": {"1"}, "b": {"x", "y"}}
	m := queryToMap(vals)
	if m["a"] != "1" {
		t.Fatalf("single value should be a scalar: %#v", m["a"])
	}
	back, _ := url.ParseQuery(mapToQuery(m))
	if !equalValues(back, vals) {
		t.Fatalf("round trip = %v", back)
	}
	if !methodAllowed("post", []string{"GET", "POST"}) || methodAllowed("DELETE", []string{"GET"}) {
		t.Fatal("methodAllowed is case-insensitive membership")
	}
}

func equalValues(a, b url.Values) bool {
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	return bytes.Equal(ja, jb)
}

func TestInspectWatchDuplicateKeysDetectedAndStripped(t *testing.T) {
	watch := WatchConfig{
		Path:        "/w",
		QueryFields: map[string]WatchFieldRule{"role": {Default: "user", Intent: "q"}},
		BodyFields:  map[string]WatchFieldRule{"role": {Default: "user", Intent: "b"}},
	}
	var mp bytes.Buffer
	w := multipart.NewWriter(&mp)
	_ = w.WriteField("role", "user")
	_ = w.WriteField("role", "admin")
	_ = w.WriteField("name", "a")
	_ = w.Close()

	cases := []struct {
		name, target, ct, body string
	}{
		{"query", "/w?role=user&role=admin&x=1", "", ""},
		{"form", "/w", "application/x-www-form-urlencoded", "role=user&role=admin&name=a"},
		{"multipart", "/w", w.FormDataContentType(), mp.String()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := NewSentry("svc", "test")
			capture := &captureHandler{}
			s.handlers = []EventHandler{capture}
			r := httptest.NewRequest("POST", c.target, strings.NewReader(c.body))
			if c.ct != "" {
				r.Header.Set("Content-Type", c.ct)
			}
			inspectWatch(s, r, r, watch, 0)
			if r.URL.Query().Has("role") {
				t.Fatalf("query still has role: %s", r.URL.RawQuery)
			}
			if c.ct != "" {
				if err := r.ParseMultipartForm(1 << 20); err != nil && err != http.ErrNotMultipart {
					t.Fatalf("parse: %v", err)
				}
				if r.PostForm.Has("role") || r.PostForm.Get("name") != "a" {
					t.Fatalf("form after strip = %v", r.PostForm)
				}
			}
			if len(capture.events) != 1 || len(capture.events[0].Found) != 1 {
				t.Fatalf("events = %+v", capture.events)
			}
			if got, _ := json.Marshal(capture.events[0].Found[0].Value); string(got) != `["user","admin"]` {
				t.Fatalf("recorded value = %s", got)
			}
		})
	}
}
