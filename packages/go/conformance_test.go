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
