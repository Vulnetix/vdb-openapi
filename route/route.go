// Package route holds the one normalisation every Vulnetix component uses
// to name an HTTP route, so a route the CLI reads from code, an operation
// from an OpenAPI document, a runtime sensor's "METHOD path" and a Guardian
// log line all meet on the same key.
//
// Two repositories that spell the same route differently never meet:
// `/users/:id`, `/users/{userId}`, `/users/<int:id>` and `/users/*` all come
// out as `GET /users/{param}`.
package route

import (
	"regexp"
	"strings"
)

// Param is the placeholder every path parameter becomes.
const Param = "{param}"

// pathParam matches parameters in every dialect in common use: Express and
// Rails `:id`, OpenAPI and chi `{id}`, Flask `<int:id>` and a bare `*`.
var pathParam = regexp.MustCompile(`(:[A-Za-z_][\w]*)|(\{[^}]*\})|(<[^>]*>)|(\*)`)

// noise lists health and observability paths. Every service has one, so
// publishing them as cross-repo contracts links everything to everything.
// They are still real operations: a spec reader keeps them; only graph
// edge emitters drop them through IsNoise.
var noise = map[string]bool{
	"/health": true, "/healthz": true, "/healthcheck": true, "/health-check": true,
	"/ready": true, "/readyz": true, "/live": true, "/livez": true,
	"/metrics": true, "/ping": true, "/status": true, "/": true, "": true,
}

// anyMethods are the router verbs that register a path for every method.
var anyMethods = map[string]bool{
	"HANDLE": true, "HANDLEFUNC": true, "ALL": true, "ROUTE": true, "REQUEST": true, "ANY": true,
}

// Path normalises a path template: query and fragment dropped, trailing
// slash dropped, every parameter replaced by {param}. It returns "" for a
// path that does not start with "/".
func Path(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || !strings.HasPrefix(p, "/") {
		return ""
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	if len(p) > 1 {
		p = strings.TrimSuffix(p, "/")
	}
	return pathParam.ReplaceAllString(p, Param)
}

// Method upper-cases a method and folds the register-for-everything verbs
// into ANY.
func Method(m string) string {
	m = strings.ToUpper(strings.TrimSpace(m))
	if anyMethods[m] {
		return "ANY"
	}
	return m
}

// Key is "METHOD /normalised/path", or "" when the path is not a path.
func Key(method, p string) string {
	n := Path(p)
	if n == "" {
		return ""
	}
	return Method(method) + " " + n
}

// Join prefixes a normalised path with a server base path ("/v1").
func Join(basePath, p string) string {
	b := strings.TrimSuffix(strings.TrimSpace(basePath), "/")
	if b == "" {
		return p
	}
	if !strings.HasPrefix(b, "/") {
		b = "/" + b
	}
	if p == "/" {
		return b
	}
	return b + p
}

// IsNoise reports a health or observability path. Graph emitters drop
// these; spec readers keep them.
func IsNoise(p string) bool {
	q := strings.TrimSpace(p)
	if i := strings.IndexAny(q, "?#"); i >= 0 {
		q = q[:i]
	}
	if len(q) > 1 {
		q = strings.TrimSuffix(q, "/")
	}
	return noise[strings.ToLower(q)]
}

// Identifying reports whether a normalised path names something: a path
// made only of parameters (`/{param}/{param}`) matches everything, so it
// identifies nothing and must not become a cross-repo edge.
func Identifying(normalised string) bool {
	s := strings.ReplaceAll(normalised, Param, "")
	s = strings.ReplaceAll(s, "/", "")
	return s != ""
}
