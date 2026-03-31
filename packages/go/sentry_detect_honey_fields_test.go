package trappsec

import "testing"

func TestDetectHoneyFieldsTouchedWithDefaultStripsWithoutViolation(t *testing.T) {
	s := NewSentry("svc", "test")
	data := map[string]any{"role": "user", "safe": "x"}
	rules := map[string]WatchFieldRule{
		"role": {Default: "user", Intent: "Privilege Escalation"},
	}

	sanitized, found, touched := s.DetectHoneyFields(data, rules, nil)

	if !touched {
		t.Fatalf("expected touched=true")
	}
	if len(found) != 0 {
		t.Fatalf("expected no violations, got %d", len(found))
	}
	if _, ok := sanitized["role"]; ok {
		t.Fatalf("expected role to be stripped")
	}
	if sanitized["safe"] != "x" {
		t.Fatalf("expected safe to remain")
	}
}

func TestDetectHoneyFieldsTouchedWithMismatchStripsAndReports(t *testing.T) {
	s := NewSentry("svc", "test")
	data := map[string]any{"role": "admin", "safe": "x"}
	rules := map[string]WatchFieldRule{
		"role": {Default: "user", Intent: "Privilege Escalation"},
	}

	sanitized, found, touched := s.DetectHoneyFields(data, rules, nil)

	if !touched {
		t.Fatalf("expected touched=true")
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(found))
	}
	if found[0].Field != "role" {
		t.Fatalf("unexpected field %q", found[0].Field)
	}
	if _, ok := sanitized["role"]; ok {
		t.Fatalf("expected role to be stripped")
	}
}

func TestDetectHoneyFieldsUntouchedNoWatchedKeys(t *testing.T) {
	s := NewSentry("svc", "test")
	data := map[string]any{"safe": "x"}
	rules := map[string]WatchFieldRule{
		"role": {Default: "user", Intent: "Privilege Escalation"},
	}

	sanitized, found, touched := s.DetectHoneyFields(data, rules, nil)

	if touched {
		t.Fatalf("expected touched=false")
	}
	if len(found) != 0 {
		t.Fatalf("expected no violations, got %d", len(found))
	}
	if sanitized["safe"] != "x" {
		t.Fatalf("expected safe to remain")
	}
}

func TestDetectHoneyFieldsNoDefaultAlwaysTriggersAndStrips(t *testing.T) {
	s := NewSentry("svc", "test")
	data := map[string]any{"token": "abc"}
	rules := map[string]WatchFieldRule{
		"token": {Default: NoDefault, Intent: "Credential Stuffing"},
	}

	sanitized, found, touched := s.DetectHoneyFields(data, rules, nil)

	if !touched {
		t.Fatalf("expected touched=true")
	}
	if len(found) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(found))
	}
	if len(sanitized) != 0 {
		t.Fatalf("expected sanitized map to be empty")
	}
}
