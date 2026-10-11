package trappsec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
)

// DefaultMaxBodyBytes is the default limit on request bodies that watch
// inspection will buffer. Larger bodies are passed through uninspected.
const DefaultMaxBodyBytes int64 = 1 << 20

// queryToMap converts url.Values to a map[string]any suitable for detectHoneyFields.
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

// readBodyLimit reads at most limit bytes of r.Body. When the whole body was
// read within the limit it returns (data, true). On a read error or when the
// body exceeds limit it returns (nil, false); in every case r.Body is restored
// so downstream consumers observe the original stream intact (bytes already
// read, then the remainder or the original error).
func readBodyLimit(r *http.Request, limit int64) ([]byte, bool) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, true
	}
	orig := r.Body
	data, err := io.ReadAll(io.LimitReader(orig, limit+1))
	if err != nil {
		r.Body = &readCloser{io.MultiReader(bytes.NewReader(data), errReader{err}), orig}
		return nil, false
	}
	if int64(len(data)) > limit {
		r.Body = &readCloser{io.MultiReader(bytes.NewReader(data), orig), orig}
		return nil, false
	}
	r.Body = &readCloser{bytes.NewReader(data), orig}
	return data, true
}

type readCloser struct {
	io.Reader
	c io.Closer
}

func (r *readCloser) Close() error { return r.c.Close() }

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }

// resetBody replaces r.Body with a fresh reader containing data and updates
// ContentLength / Content-Length / Transfer-Encoding accordingly.
func resetBody(r *http.Request, data []byte) {
	r.Body = io.NopCloser(bytes.NewReader(data))
	r.ContentLength = int64(len(data))
	r.TransferEncoding = nil
	if r.Header != nil {
		r.Header.Del("Transfer-Encoding")
		r.Header.Set("Content-Length", fmt.Sprint(len(data)))
	}
}

// inspectWatch applies a watch to the request: it detects and strips honey
// fields from the query string and body (JSON, +json, form, multipart, or a
// body that merely looks like JSON) and emits a watch event when violations are
// found. Bodies larger than maxBody (<=0 means DefaultMaxBodyBytes) are passed
// through uninspected and intact. Panics are recovered and logged: the request
// always continues to the application.
func inspectWatch(s *Sentry, r *http.Request, reqObj any, watch WatchConfig, maxBody int64) {
	defer func() {
		if p := recover(); p != nil {
			s.Logger().Printf("trappsec: watch inspection failed: %v", p)
		}
	}()
	if maxBody <= 0 {
		maxBody = DefaultMaxBodyBytes
	}
	var found []FoundField

	if len(watch.QueryFields) > 0 {
		vals := r.URL.Query()
		if len(vals) > 0 {
			sanitized, f, touched := s.detectHoneyFields(queryToMap(vals), watch.QueryFields, reqObj, "query")
			found = append(found, f...)
			if touched {
				pruneValues(vals, sanitized)
				r.URL.RawQuery = vals.Encode()
				r.Form, r.PostForm = nil, nil
			}
		}
	}

	if len(watch.BodyFields) > 0 {
		found = append(found, inspectBody(s, r, reqObj, watch.BodyFields, maxBody)...)
	}

	if len(found) > 0 {
		s.triggerWatchEvent(reqObj, found)
	}
}

func pruneValues(vals url.Values, sanitized map[string]any) {
	for k := range vals {
		if _, ok := sanitized[k]; !ok {
			delete(vals, k)
		}
	}
}

const (
	kindOther = iota
	kindJSON
	kindForm
	kindMultipart
)

func classifyContentType(ct string) int {
	mt := strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
	switch {
	case mt == "application/x-www-form-urlencoded":
		return kindForm
	case mt == "multipart/form-data":
		return kindMultipart
	case mt == "application/json", mt == "text/json", strings.HasSuffix(mt, "+json"):
		return kindJSON
	}
	return kindOther
}

func looksLikeJSON(b []byte) bool {
	b = bytes.TrimLeft(b, " \t\r\n")
	return len(b) > 0 && (b[0] == '{' || b[0] == '[')
}

func inspectBody(s *Sentry, r *http.Request, reqObj any, rules map[string]WatchFieldRule, maxBody int64) []FoundField {
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return nil
	}
	if r.ContentLength > maxBody {
		return nil // known to be too large: leave the stream untouched
	}
	ct := r.Header.Get("Content-Type")
	kind := classifyContentType(ct)
	data, ok := readBodyLimit(r, maxBody)
	if !ok || len(data) == 0 {
		return nil
	}
	if kind == kindOther {
		if !looksLikeJSON(data) {
			return nil
		}
		kind = kindJSON
	}
	switch kind {
	case kindJSON:
		return inspectJSON(s, r, reqObj, rules, data)
	case kindForm:
		vals, _ := url.ParseQuery(string(data))
		if len(vals) == 0 {
			return nil
		}
		sanitized, f, touched := s.detectHoneyFields(queryToMap(vals), rules, reqObj, "body")
		if touched {
			pruneValues(vals, sanitized)
			resetBody(r, []byte(vals.Encode()))
			r.Form, r.PostForm = nil, nil
		}
		return f
	case kindMultipart:
		return inspectMultipart(s, r, reqObj, rules, data, ct)
	}
	return nil
}

func marshalJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func inspectJSON(s *Sentry, r *http.Request, reqObj any, rules map[string]WatchFieldRule, data []byte) []FoundField {
	// Inspect every top-level value, not just the first: json.Decoder (used by
	// Gin's and Echo's binders) reads the first value and ignores what
	// follows, so `{"honey":1} x` or `{"honey":1}{}` must not skip inspection.
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber() // keep large integers exact
	var values []any
	var tail []byte
	for {
		start := dec.InputOffset()
		var v any
		if err := dec.Decode(&v); err != nil {
			if err != io.EOF {
				tail = data[start:] // unparseable remainder, kept verbatim
			}
			break
		}
		values = append(values, v)
	}
	if len(values) == 0 {
		return nil
	}
	var found []FoundField
	touchedAny := false
	for _, v := range values {
		_, f, touched := s.detectHoneyFieldsAny(v, rules, reqObj, "body")
		found = append(found, f...)
		touchedAny = touchedAny || touched
	}
	if touchedAny {
		var out bytes.Buffer
		for i, v := range values {
			nb, err := marshalJSON(v)
			if err != nil {
				return found
			}
			if i > 0 {
				out.WriteByte('\n')
			}
			out.Write(nb)
		}
		out.Write(tail)
		resetBody(r, out.Bytes())
		r.Form, r.PostForm = nil, nil
	}
	return found
}

type mpPart struct {
	header  textproto.MIMEHeader
	body    []byte
	name    string
	isField bool
}

func inspectMultipart(s *Sentry, r *http.Request, reqObj any, rules map[string]WatchFieldRule, data []byte, ct string) []FoundField {
	_, params, err := mime.ParseMediaType(ct)
	if err != nil || params["boundary"] == "" {
		return nil
	}
	boundary := params["boundary"]
	mr := multipart.NewReader(bytes.NewReader(data), boundary)
	var parts []mpPart
	vals := url.Values{}
	for {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil // malformed: leave untouched
		}
		b, err := io.ReadAll(p)
		if err != nil {
			return nil
		}
		mp := mpPart{header: p.Header, body: b, name: p.FormName()}
		if mp.name != "" {
			_, dp, _ := mime.ParseMediaType(p.Header.Get("Content-Disposition"))
			_, hasFilename := dp["filename"]
			_, hasFilenameExt := dp["filename*"]
			mp.isField = !hasFilename && !hasFilenameExt
		}
		if mp.isField {
			vals.Add(mp.name, string(b))
		}
		parts = append(parts, mp)
	}
	if len(vals) == 0 {
		return nil
	}
	sanitized, f, touched := s.detectHoneyFields(queryToMap(vals), rules, reqObj, "body")
	if !touched {
		return f
	}
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	newBoundary := boundary
	if err := w.SetBoundary(boundary); err != nil {
		newBoundary = w.Boundary()
	}
	for _, p := range parts {
		if p.isField {
			if _, keep := sanitized[p.name]; !keep {
				continue
			}
		}
		pw, err := w.CreatePart(p.header)
		if err != nil {
			return f // cannot rebuild safely: leave body as read
		}
		_, _ = pw.Write(p.body)
	}
	if err := w.Close(); err != nil {
		return f
	}
	resetBody(r, buf.Bytes())
	if newBoundary != boundary {
		r.Header.Set("Content-Type", w.FormDataContentType())
	}
	r.MultipartForm, r.PostForm, r.Form = nil, nil, nil
	return f
}
