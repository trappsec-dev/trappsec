package trappsec

// Shared cross-language cases from tests/conformance (R17, R18).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func loadConformance(t *testing.T, name string, v any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "conformance", name))
	if os.IsNotExist(err) && os.Getenv("CI") == "" {
		t.Skipf("%s not found (outside the trappsec repository)", name)
	}
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber() // same decoding the adapters use for request bodies
	if err := dec.Decode(v); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

// normalizeJSON round-trips v through JSON so values built from different Go
// types (json.Number, []FoundField, ...) compare structurally.
func normalizeJSON(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

func TestConformanceValuesMatch(t *testing.T) {
	var fx struct {
		Cases []struct {
			Actual   any  `json:"actual"`
			Expected any  `json:"expected"`
			Match    bool `json:"match"`
		} `json:"cases"`
	}
	loadConformance(t, "values_match.json", &fx)
	for i, c := range fx.Cases {
		name := fmt.Sprintf("%d:%v~%v", i, c.Actual, c.Expected)
		t.Run(name, func(t *testing.T) {
			if got := valuesMatch(c.Actual, c.Expected); got != c.Match {
				t.Fatalf("valuesMatch(%#v, %#v) = %v, want %v", c.Actual, c.Expected, got, c.Match)
			}
		})
	}
}

func TestConformanceDetectHoneyFields(t *testing.T) {
	var fx struct {
		Cases []struct {
			Name    string                    `json:"name"`
			Source  string                    `json:"source"`
			Rules   map[string]map[string]any `json:"rules"`
			Data    any                       `json:"data"`
			Found   []map[string]any          `json:"found"`
			Result  any                       `json:"result"`
			Touched bool                      `json:"touched"`
		} `json:"cases"`
	}
	loadConformance(t, "detect_honey_fields.json", &fx)
	for _, c := range fx.Cases {
		t.Run(c.Name, func(t *testing.T) {
			source := c.Source
			if source == "" {
				source = "body"
			}
			rules := map[string]WatchFieldRule{}
			for field, r := range c.Rules {
				rule := WatchFieldRule{Default: NoDefault, Intent: r["intent"].(string)}
				if d, ok := r["default"]; ok {
					rule.Default = d
				}
				rules[field] = rule
			}

			s := NewSentry("svc", "test")
			data, found, touched := s.DetectHoneyFieldsAny(c.Data, rules, nil, source)
			if found == nil {
				found = []FoundField{}
			}

			want := make([]map[string]any, 0, len(c.Found))
			for _, f := range c.Found {
				want = append(want, map[string]any{"type": source, "field": f["field"], "value": f["value"], "intent": f["intent"]})
			}
			sort.Slice(found, func(i, j int) bool { return found[i].Field < found[j].Field })
			sort.Slice(want, func(i, j int) bool { return want[i]["field"].(string) < want[j]["field"].(string) })

			if got, exp := normalizeJSON(t, found), normalizeJSON(t, want); !reflect.DeepEqual(got, exp) {
				t.Errorf("found = %v, want %v", got, exp)
			}
			if got, exp := normalizeJSON(t, data), normalizeJSON(t, c.Result); !reflect.DeepEqual(got, exp) {
				t.Errorf("data = %v, want %v", got, exp)
			}
			if touched != c.Touched {
				t.Errorf("touched = %v, want %v", touched, c.Touched)
			}
		})
	}
}

func TestConformanceEventKeys(t *testing.T) {
	var fx struct {
		Common     []string            `json:"common"`
		App        []string            `json:"app"`
		Events     map[string][]string `json:"events"`
		FoundField []string            `json:"found_field"`
	}
	loadConformance(t, "event_keys.json", &fx)

	s := NewSentry("svc", "test")
	capture := &captureHandler{}
	s.handlers = []EventHandler{capture}
	s.TriggerTrapEvent(nil, TrapConfig{Path: "/t"})
	s.TriggerWatchEvent(nil, []FoundField{{Type: "body", Field: "f"}})
	s.Trigger(nil, "", "", nil)

	keysOf := func(v any) []string {
		var m map[string]any
		_ = json.Unmarshal(normalizeRaw(t, v), &m)
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	sorted := func(a ...[]string) []string {
		var out []string
		for _, x := range a {
			out = append(out, x...)
		}
		sort.Strings(out)
		return out
	}
	if len(capture.events) != 3 {
		t.Fatalf("events = %d", len(capture.events))
	}
	for _, ev := range capture.events {
		if got, want := keysOf(ev), sorted(fx.Common, fx.Events[ev.Event]); !reflect.DeepEqual(got, want) {
			t.Errorf("%s keys = %v, want %v", ev.Event, got, want)
		}
		if got, want := keysOf(ev.App), sorted(fx.App); !reflect.DeepEqual(got, want) {
			t.Errorf("app keys = %v, want %v", got, want)
		}
		if ev.Event == "trappsec.watch_hit" {
			if got, want := keysOf(ev.Found[0]), sorted(fx.FoundField); !reflect.DeepEqual(got, want) {
				t.Errorf("found_field keys = %v, want %v", got, want)
			}
		}
	}
}

func normalizeRaw(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func expandRepeat(v any) any {
	switch t := v.(type) {
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = expandRepeat(x)
		}
		return out
	case map[string]any:
		if s, ok := t["$repeat"].(string); ok {
			n, _ := t["count"].(json.Number).Int64()
			prefix, _ := t["prefix"].(string)
			suffix, _ := t["suffix"].(string)
			return prefix + strings.Repeat(s, int(n)) + suffix
		}
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = expandRepeat(x)
		}
		return out
	}
	return v
}

func TestConformanceSafeValue(t *testing.T) {
	var fx struct {
		Cases []struct {
			Name   string `json:"name"`
			Input  any    `json:"input"`
			Output any    `json:"output"`
		} `json:"cases"`
		Events map[string]any `json:"events"`
	}
	loadConformance(t, "safe_value.json", &fx)
	for _, c := range fx.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got := SafeValue(expandRepeat(c.Input))
			if g, w := normalizeJSON(t, got), normalizeJSON(t, expandRepeat(c.Output)); !reflect.DeepEqual(g, w) {
				t.Errorf("SafeValue = %#v, want %#v", g, w)
			}
		})
	}

	ev := expandRepeat(fx.Events).(map[string]any)
	s := NewSentry("svc", "test")
	capture := &captureHandler{}
	s.handlers = []EventHandler{capture}
	s.Request.Path = func(any) string { return ev["path"].(string) }
	s.Request.UserAgent = func(any) string { return ev["user_agent"].(string) }
	s.Trigger(nil, "reason", "", nil)
	var m map[string]any
	_ = json.Unmarshal(normalizeRaw(t, capture.events[0]), &m)
	if m["path"] != ev["path_out"] || m["user_agent"] != ev["user_agent_out"] {
		t.Errorf("event path/user_agent: got %d/%d chars, want %d/%d",
			len(m["path"].(string)), len(m["user_agent"].(string)), len(ev["path_out"].(string)), len(ev["user_agent_out"].(string)))
	}
}
