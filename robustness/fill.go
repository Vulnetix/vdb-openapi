package robustness

import (
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Vulnetix/vdb-openapi/oas"
)

// Filled is a concrete request path for an operation's template.
// FromExamples is false when a placeholder stood in for a parameter: a 404
// on such a path says nothing about whether the route exists.
type Filled struct {
	Path         string `json:"path"`
	FromExamples bool   `json:"fromExamples"`
}

var tplParam = regexp.MustCompile(`\{([^}]+)\}`)

// ConcretePath fills the operation's path parameters with the document's
// examples, enum values or a safe placeholder for the type. It reports false
// for a parameter whose type gives no safe value (an object, say).
func ConcretePath(basePath string, o oas.Operation) (Filled, bool) {
	params := map[string]oas.Parameter{}
	for _, p := range o.Parameters {
		if p.In == oas.InPath {
			params[p.Name] = p
		}
	}
	fromExamples := true
	ok := true
	path := tplParam.ReplaceAllStringFunc(o.PathTemplate, func(m string) string {
		name := m[1 : len(m)-1]
		p := params[name]
		v, real, safe := valueFor(p.Example, p.Schema)
		if !safe {
			ok = false
			return m
		}
		if !real {
			fromExamples = false
		}
		return url.PathEscape(v)
	})
	if !ok {
		return Filled{}, false
	}
	base := strings.TrimSuffix(basePath, "/")
	return Filled{Path: base + path, FromExamples: fromExamples}, true
}

// valueFor returns a value for a schema: the example if any (real), else a
// placeholder by type. safe is false when no scalar value fits.
func valueFor(example string, s oas.SchemaSummary) (v string, real, safe bool) {
	if example != "" {
		return example, true, true
	}
	if len(s.Enum) > 0 {
		return s.Enum[0], true, true
	}
	switch s.Type {
	case "integer", "number":
		n := 1.0
		if s.Minimum != nil && *s.Minimum > n {
			n = *s.Minimum
		}
		return strconv.FormatFloat(n, 'f', -1, 64), false, true
	case "boolean":
		return "true", false, true
	case "string", "":
		switch s.Format {
		case "uuid":
			return "00000000-0000-4000-8000-000000000000", false, true
		case "date":
			return "2026-01-01", false, true
		case "date-time":
			return "2026-01-01T00:00:00Z", false, true
		case "email":
			return "probe@example.com", false, true
		}
		v := "vulnetix"
		if s.MinLength != nil && *s.MinLength > len(v) {
			v += strings.Repeat("x", *s.MinLength-len(v))
		}
		if s.MaxLength != nil && *s.MaxLength < len(v) {
			v = v[:*s.MaxLength]
		}
		return v, false, true
	}
	return "", false, false
}
