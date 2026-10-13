package trappsechandler

import "strings"

type segKind int

// Ordered by specificity: a literal segment beats a parameter, which beats a
// catch-all.
const (
	segCatchAll segKind = iota
	segParam
	segLit
)

type seg struct {
	kind segKind
	lit  string
}

// pattern is a route path split into segments. Segments written :id, {id},
// {id:regex}, <id>, <int:id> or *rest match one segment; a last segment
// written *rest, {rest...}, {rest:path} or <path:rest> matches one or more.
// These are the trap and watch path syntaxes of every trappsec package, and
// the route syntaxes of chi, gorilla/mux and httprouter.
type pattern struct{ segs []seg }

func parsePattern(p string) pattern {
	parts := splitPath(p)
	segs := make([]seg, len(parts))
	for i, s := range parts {
		switch {
		case strings.HasPrefix(s, ":"), strings.HasPrefix(s, "*"),
			strings.HasPrefix(s, "{") && strings.HasSuffix(s, "}"),
			strings.HasPrefix(s, "<") && strings.HasSuffix(s, ">"):
			segs[i].kind = segParam
			if i == len(parts)-1 && (strings.HasPrefix(s, "*") || strings.HasSuffix(s, "...}") ||
				strings.HasSuffix(s, ":path}") || strings.HasPrefix(s, "<path:")) {
				segs[i].kind = segCatchAll
			}
		default:
			segs[i] = seg{kind: segLit, lit: s}
		}
	}
	return pattern{segs: segs}
}

// splitPath cleans a path (query and fragment dropped, trailing slashes
// trimmed) and splits it into segments; "/" has none.
func splitPath(p string) []string {
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimRight(strings.TrimPrefix(p, "/"), "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// matches reports whether the request path segments fit the pattern.
func (p pattern) matches(path []string) bool {
	for i, s := range p.segs {
		if s.kind == segCatchAll {
			if i >= len(path) {
				return false
			}
			for _, part := range path[i:] {
				if part == "" {
					return false
				}
			}
			return true
		}
		if i >= len(path) {
			return false
		}
		switch s.kind {
		case segParam:
			if path[i] == "" {
				return false
			}
		case segLit:
			if path[i] != s.lit {
				return false
			}
		}
	}
	return len(path) == len(p.segs)
}

// compare orders two patterns that match the same path by specificity: the
// first segment where they differ decides, a literal beating a parameter
// beating a catch-all beating no segment at all (a prefix route). It returns
// a positive number when p is more specific than q, negative when less, and
// 0 when they are equally specific.
func (p pattern) compare(q pattern) int {
	for i := 0; i < len(p.segs) || i < len(q.segs); i++ {
		a, b := -1, -1
		if i < len(p.segs) {
			a = int(p.segs[i].kind)
		}
		if i < len(q.segs) {
			b = int(q.segs[i].kind)
		}
		if a != b {
			return a - b
		}
		if a == int(segCatchAll) {
			return 0
		}
	}
	return 0
}

// shape is the pattern with parameter names dropped, so that /users/{id} and
// /users/:uid compare equal.
func (p pattern) shape() string {
	var b strings.Builder
	for _, s := range p.segs {
		b.WriteByte('/')
		switch s.kind {
		case segLit:
			b.WriteString(s.lit)
		case segParam:
			b.WriteString("{}")
		case segCatchAll:
			b.WriteString("*")
		}
	}
	if b.Len() == 0 {
		return "/"
	}
	return b.String()
}
