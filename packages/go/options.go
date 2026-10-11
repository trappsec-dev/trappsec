package trappsec

import "fmt"

type optionKind int

const (
	optDefault optionKind = iota + 1
	optIntent
	optMetadata
)

// Option is an optional argument to WatchBuilder.Query, WatchBuilder.Body and
// Sentry.Trigger, so that only what you mean has to be written, as with
// Python's keyword arguments and Node's options object:
//
//	watch.Body("is_admin", trappsec.Default(false), trappsec.Intent("PrivEsc"))
//	watch.Query("debug")                       // alert on any presence
//	ts.Trigger(c, "Velocity limit exceeded", trappsec.Intent("fraud"), trappsec.Metadata(m))
type Option struct {
	kind  optionKind
	value any
}

// Default sets the expected value of a watched field. A request that sends a
// different value is a violation; without Default any presence is.
func Default(value any) Option { return Option{kind: optDefault, value: value} }

// Intent labels a watched field or a Trigger event.
func Intent(intent string) Option { return Option{kind: optIntent, value: intent} }

// Metadata attaches free-form data to a Trigger event.
func Metadata(metadata any) Option { return Option{kind: optMetadata, value: metadata} }

// splitOptions applies the Option values in args and returns the remaining
// positional arguments (the pre-0.3 form: Body(name, default, intent) and
// Trigger(req, reason, intent, metadata)).
func splitOptions(args []any, apply func(Option) bool) (positional []any, err error) {
	for _, a := range args {
		if o, ok := a.(Option); ok {
			if !apply(o) {
				err = fmt.Errorf("option %s is not accepted here", o.kind)
			}
			continue
		}
		positional = append(positional, a)
	}
	return positional, err
}

func (k optionKind) String() string {
	switch k {
	case optDefault:
		return "Default"
	case optIntent:
		return "Intent"
	case optMetadata:
		return "Metadata"
	}
	return "unknown"
}

func (s *Sentry) fieldRule(method, name string, args []any) WatchFieldRule {
	rule := WatchFieldRule{Default: NoDefault}
	positional, err := splitOptions(args, func(o Option) bool {
		switch o.kind {
		case optDefault:
			rule.Default = o.value
		case optIntent:
			rule.Intent, _ = o.value.(string)
		default:
			return false
		}
		return true
	})
	if err != nil {
		s.logger.Printf("trappsec: %s(%q): %v", method, name, err)
	}
	if len(positional) > 0 {
		rule.Default = positional[0]
	}
	if len(positional) > 1 {
		if intent, ok := positional[1].(string); ok {
			rule.Intent = intent
		} else {
			s.logger.Printf("trappsec: %s(%q): intent must be a string, got %T", method, name, positional[1])
		}
	}
	if len(positional) > 2 {
		s.logger.Printf("trappsec: %s(%q): ignoring %d extra arguments", method, name, len(positional)-2)
	}
	return rule
}
