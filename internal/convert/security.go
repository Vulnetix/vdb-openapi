package convert

import (
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/Vulnetix/vdb-openapi/internal/tree"
	"github.com/Vulnetix/vdb-openapi/oas"
)

var oauth2Flows = map[string]string{
	// Swagger 2.0 names → OpenAPI 3 names.
	"implicit": "implicit", "password": "password",
	"application": "clientCredentials", "accessCode": "authorizationCode",
}

func (c *conv) securitySchemes(m map[string]any) {
	var defs map[string]any
	var base string
	if c.v == v20 {
		defs, base = obj(m["securityDefinitions"]), "/securityDefinitions"
	} else {
		defs, base = obj(obj(m["components"])["securitySchemes"]), "/components/securitySchemes"
	}
	for _, name := range sortedKeys(defs) {
		sm, _, _, _, ok := c.deref(c.root, defs[name], base+"/"+tree.Escape(name))
		if !ok {
			continue
		}
		s := oas.SecurityScheme{Type: text(sm["type"])}
		switch s.Type {
		case "basic":
			s.Type, s.Scheme = "http", "basic"
		case "http":
			s.Scheme = strings.ToLower(text(sm["scheme"]))
			s.BearerFormat = text(sm["bearerFormat"])
		case "apiKey":
			s.In = oas.ParameterIn(text(sm["in"]))
			s.Name = text(sm["name"])
		case "oauth2":
			s.Flows = c.flows(sm)
		case "openIdConnect":
			s.OpenIDConnectURL = text(sm["openIdConnectUrl"])
		}
		c.out.SecuritySchemes[name] = s
	}
}

func (c *conv) flows(sm map[string]any) []oas.OAuthFlow {
	scopes := func(v any) []string {
		out := sortedKeys(obj(v))
		if out == nil {
			out = []string{}
		}
		return out
	}
	var out []oas.OAuthFlow
	if c.v == v20 {
		kind := oauth2Flows[text(sm["flow"])]
		if kind == "" {
			kind = text(sm["flow"])
		}
		out = append(out, oas.OAuthFlow{
			Kind:             kind,
			AuthorizationURL: text(sm["authorizationUrl"]),
			TokenURL:         text(sm["tokenUrl"]),
			Scopes:           scopes(sm["scopes"]),
		})
		return out
	}
	fl := obj(sm["flows"])
	for _, kind := range sortedKeys(fl) {
		f := obj(fl[kind])
		out = append(out, oas.OAuthFlow{
			Kind:             kind,
			AuthorizationURL: text(f["authorizationUrl"]),
			TokenURL:         text(f["tokenUrl"]),
			Scopes:           scopes(f["scopes"]),
		})
	}
	return out
}

// security works out the effective requirement: the operation's own
// security if it has the key at all, otherwise the document's, otherwise
// unspecified. An empty list is an explicit "no authentication"; an empty
// entry inside a list makes authentication optional.
func (c *conv) security(op map[string]any) oas.Security {
	raw, from := op["security"], "operation"
	if _, ok := op["security"]; !ok {
		root := obj(c.root.Root)
		if _, ok := root["security"]; !ok {
			return oas.Security{State: oas.SecurityUnspecified, Alternatives: [][]oas.SchemeUse{}}
		}
		raw, from = root["security"], "document"
	}
	list := arr(raw)
	sec := oas.Security{From: from, Alternatives: [][]oas.SchemeUse{}}
	if len(list) == 0 {
		sec.State = oas.SecurityNone
		return sec
	}
	optional := false
	for _, e := range list {
		em := obj(e)
		if len(em) == 0 {
			optional = true
			continue
		}
		var alt []oas.SchemeUse
		for _, name := range sortedKeys(em) {
			var scopes []string
			for _, s := range arr(em[name]) {
				if t := text(s); t != "" {
					scopes = append(scopes, t)
				}
			}
			sort.Strings(scopes)
			if scopes == nil {
				scopes = []string{}
			}
			alt = append(alt, oas.SchemeUse{Scheme: name, Scopes: scopes})
		}
		sec.Alternatives = append(sec.Alternatives, alt)
	}
	sort.Slice(sec.Alternatives, func(i, j int) bool {
		return altKey(sec.Alternatives[i]) < altKey(sec.Alternatives[j])
	})
	switch {
	case optional:
		sec.State = oas.SecurityOptional
	default:
		sec.State = oas.SecurityRequired
	}
	return sec
}

func altKey(a []oas.SchemeUse) string {
	parts := make([]string, len(a))
	for i, u := range a {
		parts[i] = u.Scheme + ":" + strings.Join(u.Scopes, ",")
	}
	return strings.Join(parts, "&")
}

var serverVar = regexp.MustCompile(`\{([^}]+)\}`)

func (c *conv) servers(d *tree.Doc, v any, ptr string) []oas.Server {
	out := []oas.Server{}
	for _, s := range arr(v) {
		sm := obj(s)
		u := strings.TrimSpace(text(sm["url"]))
		if u == "" {
			continue
		}
		srv := oas.Server{URL: u}
		vars := obj(sm["variables"])
		if len(vars) > 0 {
			srv.Variables = map[string]oas.ServerVariable{}
			for _, name := range sortedKeys(vars) {
				vm := obj(vars[name])
				sv := oas.ServerVariable{Default: text(vm["default"])}
				for _, e := range arr(vm["enum"]) {
					sv.Enum = append(sv.Enum, text(e))
				}
				srv.Variables[name] = sv
			}
		}
		srv.Resolved = serverVar.ReplaceAllStringFunc(u, func(m string) string {
			name := m[1 : len(m)-1]
			if sv, ok := srv.Variables[name]; ok {
				return sv.Default
			}
			return m
		})
		fillServer(&srv)
		out = append(out, srv)
	}
	return out
}

// swaggerServers builds servers from 2.0 host, basePath and schemes. One
// server per scheme, in the order given.
func (c *conv) swaggerServers(m map[string]any) []oas.Server {
	host := strings.TrimSpace(text(m["host"]))
	base := strings.TrimSpace(text(m["basePath"]))
	out := []oas.Server{}
	if host == "" && base == "" {
		return out
	}
	if host == "" {
		srv := oas.Server{URL: base, Resolved: base}
		fillServer(&srv)
		return append(out, srv)
	}
	var schemes []string
	for _, s := range arr(m["schemes"]) {
		if t := strings.ToLower(text(s)); t == "http" || t == "https" {
			schemes = append(schemes, t)
		}
	}
	if len(schemes) == 0 {
		c.issue("/schemes", "schemes-assumed", "info", "schemes not declared; https assumed")
		schemes = []string{"https"}
	}
	for _, sch := range schemes {
		u := sch + "://" + host + base
		srv := oas.Server{URL: u, Resolved: u}
		fillServer(&srv)
		out = append(out, srv)
	}
	return out
}

func fillServer(s *oas.Server) {
	r := s.Resolved
	if strings.HasPrefix(r, "//") {
		r = "https:" + r
	}
	if strings.Contains(r, "://") {
		if u, err := url.Parse(r); err == nil {
			s.Scheme = strings.ToLower(u.Scheme)
			s.Host = strings.ToLower(u.Host)
			s.BasePath = u.Path
		}
	} else {
		s.BasePath = r
		if i := strings.IndexAny(s.BasePath, "?#"); i >= 0 {
			s.BasePath = s.BasePath[:i]
		}
	}
	s.BasePath = strings.TrimSuffix(s.BasePath, "/")
}
