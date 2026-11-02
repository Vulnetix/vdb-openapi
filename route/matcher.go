package route

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// MatcherVersion is the version of the serialised matcher set. A consumer
// in another language (the Guardian Worker) refuses a set whose major it
// does not know.
const MatcherVersion = "1"

// Template is one route to match concrete request paths against.
type Template struct {
	// Method is upper case, or ANY.
	Method string `json:"method"`
	// Path is a normalised template (see Path), already joined with any
	// server base path.
	Path string `json:"path"`
	// Key is what a match returns; usually the operation or route key.
	Key string `json:"key"`
}

// Matcher maps a concrete method and path to the template that serves it.
//
// The rule is the same in every implementation and is pinned by
// testdata/route/matcher-cases.json:
//
//  1. The request path is split on "/" after dropping the query, the
//     fragment and one trailing slash. Each segment is percent-decoded
//     before comparison; a segment that does not decode is compared raw.
//  2. A template matches when it has the same number of segments, every
//     literal segment is equal (case-sensitive) and every {param} segment
//     is a non-empty segment.
//  3. Among matches, the one with a literal at the first position where
//     they differ wins (`/users/me` beats `/users/{param}`).
//  4. A template with method ANY matches every method, but loses to one
//     with the exact method at the same specificity.
type Matcher struct {
	templates []compiled
}

type compiled struct {
	t        Template
	segments []string
}

// Set is the serialised form.
type Set struct {
	Version   string     `json:"version"`
	Templates []Template `json:"templates"`
}

// Compile builds a matcher. Duplicate method and path pairs keep the first
// key in sorted order, so the result does not depend on input order.
func Compile(ts []Template) *Matcher {
	cp := append([]Template(nil), ts...)
	sort.SliceStable(cp, func(i, j int) bool {
		if cp[i].Path != cp[j].Path {
			return cp[i].Path < cp[j].Path
		}
		if cp[i].Method != cp[j].Method {
			return cp[i].Method < cp[j].Method
		}
		return cp[i].Key < cp[j].Key
	})
	m := &Matcher{}
	seen := map[string]bool{}
	for _, t := range cp {
		t.Method = Method(t.Method)
		id := t.Method + " " + t.Path
		if seen[id] || !strings.HasPrefix(t.Path, "/") {
			continue
		}
		seen[id] = true
		m.templates = append(m.templates, compiled{t: t, segments: split(t.Path)})
	}
	return m
}

// Set returns the serialisable form of the matcher.
func (m *Matcher) Set() Set {
	out := Set{Version: MatcherVersion, Templates: make([]Template, 0, len(m.templates))}
	for _, c := range m.templates {
		out.Templates = append(out.Templates, c.t)
	}
	return out
}

// MarshalJSON writes the serialised set.
func (m *Matcher) MarshalJSON() ([]byte, error) { return json.Marshal(m.Set()) }

// Match returns the template that serves method and rawPath.
func (m *Matcher) Match(method, rawPath string) (Template, bool) {
	method = Method(method)
	segs := requestSegments(rawPath)
	if segs == nil {
		return Template{}, false
	}
	var best *compiled
	for i := range m.templates {
		c := &m.templates[i]
		if c.t.Method != method && c.t.Method != "ANY" {
			continue
		}
		if !matches(c.segments, segs) {
			continue
		}
		if best == nil || better(c, best, method) {
			best = c
		}
	}
	if best == nil {
		return Template{}, false
	}
	return best.t, true
}

func matches(tpl, req []string) bool {
	if len(tpl) != len(req) {
		return false
	}
	for i, s := range tpl {
		if s == Param {
			if req[i] == "" {
				return false
			}
			continue
		}
		if s != req[i] {
			return false
		}
	}
	return true
}

// better reports whether a is more specific than b for this method.
func better(a, b *compiled, method string) bool {
	for i := range a.segments {
		al, bl := a.segments[i] != Param, b.segments[i] != Param
		if al != bl {
			return al
		}
	}
	return a.t.Method == method && b.t.Method != method
}

func split(p string) []string {
	if p == "/" {
		return []string{""}
	}
	return strings.Split(strings.TrimPrefix(p, "/"), "/")
}

func requestSegments(raw string) []string {
	p := strings.TrimSpace(raw)
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if !strings.HasPrefix(p, "/") {
		return nil
	}
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	segs := split(p)
	for i, s := range segs {
		if d, err := url.PathUnescape(s); err == nil {
			segs[i] = d
		}
	}
	return segs
}
