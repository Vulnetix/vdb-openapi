package convert

import (
	"sort"
	"strings"

	"github.com/Vulnetix/vdb-openapi/internal/tree"
	"github.com/Vulnetix/vdb-openapi/oas"
)

var inOrder = map[oas.ParameterIn]int{oas.InPath: 0, oas.InQuery: 1, oas.InHeader: 2, oas.InCookie: 3}

type rawParam struct {
	d   *tree.Doc
	m   map[string]any
	ptr string
}

// operationInputs merges path-level and operation-level parameters (the
// operation's win on name and location), then splits Swagger 2.0 body and
// formData parameters out into a request body.
func (c *conv) operationInputs(d *tree.Doc, op map[string]any, ptr string, shared []any, sharedPtr string, o *oas.Operation) {
	byKey := map[string]rawParam{}
	var order []string
	collect := func(list []any, base string, doc *tree.Doc) {
		for i, p := range list {
			pptr := base + "/" + itoa(i)
			m, pd, rptr, _, ok := c.deref(doc, p, pptr)
			if !ok {
				continue
			}
			k := text(m["in"]) + "\x00" + text(m["name"])
			if _, seen := byKey[k]; !seen {
				order = append(order, k)
			}
			byKey[k] = rawParam{d: pd, m: m, ptr: rptr}
		}
	}
	collect(shared, sharedPtr, d)
	collect(arr(op["parameters"]), ptr+"/parameters", d)

	var body *rawParam
	var form []rawParam
	for _, k := range order {
		rp := byKey[k]
		switch text(rp.m["in"]) {
		case "body":
			b := rp
			body = &b
		case "formData":
			form = append(form, rp)
		default:
			if p, ok := c.parameter(rp); ok {
				o.Parameters = append(o.Parameters, p)
			}
		}
	}
	sort.SliceStable(o.Parameters, func(i, j int) bool {
		a, b := o.Parameters[i], o.Parameters[j]
		if a.In != b.In {
			return inOrder[a.In] < inOrder[b.In]
		}
		return a.Name < b.Name
	})

	if c.v == v20 {
		o.RequestBody = c.swaggerBody(op, ptr, body, form)
		return
	}
	if rb, ok := op["requestBody"]; ok {
		m, bd, bptr, _, ok := c.deref(d, rb, ptr+"/requestBody")
		if ok {
			o.RequestBody = &oas.RequestBody{
				Required: boolean(m["required"]),
				Content:  c.content(bd, m["content"], bptr+"/content"),
			}
		}
	}
}

func (c *conv) parameter(rp rawParam) (oas.Parameter, bool) {
	m := rp.m
	in := oas.ParameterIn(text(m["in"]))
	if _, ok := inOrder[in]; !ok {
		c.issue(at(rp.d, rp.ptr+"/in"), "parameter-in", "warning", "unknown parameter location "+string(in))
		return oas.Parameter{}, false
	}
	p := oas.Parameter{
		Name:          text(m["name"]),
		In:            in,
		Required:      boolean(m["required"]) || in == oas.InPath,
		Deprecated:    boolean(m["deprecated"]),
		AllowReserved: boolean(m["allowReserved"]),
	}
	var schemaMap map[string]any
	if c.v == v20 {
		// A 2.0 parameter carries its schema keywords inline.
		p.Schema = c.schema(rp.d, m, rp.ptr, 0, map[string]bool{})
		schemaMap = m
		c.collectionFormat(m, &p, rp)
	} else {
		sv, sptr := m["schema"], rp.ptr+"/schema"
		if sv == nil {
			if content := obj(m["content"]); len(content) > 0 {
				first := sortedKeys(content)[0]
				sv = obj(content[first])["schema"]
				sptr = rp.ptr + "/content/" + tree.Escape(first) + "/schema"
			}
		}
		p.Schema = c.schema(rp.d, sv, sptr, 0, map[string]bool{})
		schemaMap, _, _, _, _ = c.deref(rp.d, sv, sptr)
		p.Style = text(m["style"])
		if e, ok := m["explode"].(bool); ok {
			p.Explode = e
		} else {
			p.Explode = defaultStyle(in) == "form" && (p.Style == "" || p.Style == "form")
		}
		if p.Style == "" {
			p.Style = defaultStyle(in)
		}
	}
	p.Example = c.example(m, schemaMap)
	return p, true
}

func defaultStyle(in oas.ParameterIn) string {
	if in == oas.InQuery || in == oas.InCookie {
		return "form"
	}
	return "simple"
}

// collectionFormat maps Swagger 2.0 array serialisation onto OpenAPI 3
// style and explode. Scalars get the 3.x defaults so a scalar parameter
// reads the same in every version.
func (c *conv) collectionFormat(m map[string]any, p *oas.Parameter, rp rawParam) {
	p.Style = defaultStyle(p.In)
	p.Explode = p.Style == "form"
	if p.Schema.Type != "array" {
		return
	}
	switch cf := text(m["collectionFormat"]); cf {
	case "", "csv":
		p.Explode = false
	case "multi":
		p.Style, p.Explode = "form", true
	case "ssv":
		p.Style, p.Explode = "spaceDelimited", false
	case "pipes":
		p.Style, p.Explode = "pipeDelimited", false
	default:
		p.Explode = false
		c.loss(at(rp.d, rp.ptr+"/collectionFormat"), "collectionFormat", "collection format "+cf+" has no OpenAPI 3 style")
	}
}

// example picks the first example the document gives for a parameter.
func (c *conv) example(param, schema map[string]any) string {
	pick := func(v any) (string, bool) {
		if v == nil {
			return "", false
		}
		return clip(text(v), 200), true
	}
	if s, ok := pick(param["example"]); ok {
		return s
	}
	if s, ok := pick(param["x-example"]); ok {
		return s
	}
	if ex := obj(param["examples"]); len(ex) > 0 {
		if s, ok := pick(obj(ex[sortedKeys(ex)[0]])["value"]); ok {
			return s
		}
	}
	if schema == nil {
		return ""
	}
	if s, ok := pick(schema["example"]); ok {
		return s
	}
	if exs := arr(schema["examples"]); len(exs) > 0 {
		if s, ok := pick(exs[0]); ok {
			return s
		}
	}
	if s, ok := pick(schema["default"]); ok {
		return s
	}
	if en := arr(schema["enum"]); len(en) > 0 {
		if s, ok := pick(en[0]); ok {
			return s
		}
	}
	return ""
}

func (c *conv) content(d *tree.Doc, v any, ptr string) []oas.MediaType {
	cm := obj(v)
	out := []oas.MediaType{}
	for _, ct := range sortedKeys(cm) {
		mptr := ptr + "/" + tree.Escape(ct)
		mt := obj(cm[ct])
		entry := oas.MediaType{Type: strings.ToLower(ct)}
		if sv, ok := mt["schema"]; ok {
			s := c.schema(d, sv, mptr+"/schema", 0, map[string]bool{})
			entry.Schema = &s
		}
		if enc := obj(mt["encoding"]); len(enc) > 0 {
			entry.Encoding = map[string]string{}
			for _, field := range sortedKeys(enc) {
				if t := text(obj(enc[field])["contentType"]); t != "" {
					entry.Encoding[field] = t
				}
			}
			if len(entry.Encoding) == 0 {
				entry.Encoding = nil
			}
		}
		out = append(out, entry)
	}
	return out
}

func (c *conv) mediaTypes(op map[string]any, key string, ptr string) []string {
	list := arr(op[key])
	if _, ok := op[key]; !ok {
		list = arr(obj(c.root.Root)[key])
	}
	var out []string
	for _, t := range list {
		if s := strings.ToLower(text(t)); s != "" {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		c.issue(ptr, key+"-assumed", "info", key+" not declared; application/json assumed")
		out = []string{"application/json"}
	}
	sort.Strings(out)
	return out
}

func (c *conv) swaggerBody(op map[string]any, ptr string, body *rawParam, form []rawParam) *oas.RequestBody {
	switch {
	case body != nil:
		s := c.schema(body.d, body.m["schema"], body.ptr+"/schema", 0, map[string]bool{})
		rb := &oas.RequestBody{Required: boolean(body.m["required"]), Content: []oas.MediaType{}}
		for _, t := range c.mediaTypes(op, "consumes", ptr) {
			sc := s
			rb.Content = append(rb.Content, oas.MediaType{Type: t, Schema: &sc})
		}
		return rb
	case len(form) > 0:
		s := oas.SchemaSummary{Type: "object", Properties: map[string]oas.SchemaSummary{}}
		hasFile := false
		for _, f := range form {
			name := text(f.m["name"])
			fs := c.schema(f.d, f.m, f.ptr, 1, map[string]bool{})
			if text(f.m["type"]) == "file" {
				hasFile = true
			}
			s.Properties[name] = fs
			if boolean(f.m["required"]) {
				s.Required = append(s.Required, name)
			}
		}
		sort.Strings(s.Required)
		var types []string
		for _, t := range arr(op["consumes"]) {
			lt := strings.ToLower(text(t))
			if lt == "multipart/form-data" || lt == "application/x-www-form-urlencoded" {
				types = append(types, lt)
			}
		}
		if len(types) == 0 {
			if hasFile {
				types = []string{"multipart/form-data"}
			} else {
				types = []string{"application/x-www-form-urlencoded"}
			}
		}
		sort.Strings(types)
		rb := &oas.RequestBody{Content: []oas.MediaType{}}
		for _, f := range form {
			if boolean(f.m["required"]) {
				rb.Required = true
			}
		}
		for _, t := range types {
			sc := s
			rb.Content = append(rb.Content, oas.MediaType{Type: t, Schema: &sc})
		}
		return rb
	}
	return nil
}

func (c *conv) responses(d *tree.Doc, op map[string]any, ptr string, o *oas.Operation) {
	rs := obj(op["responses"])
	for _, code := range sortedKeys(rs) {
		if strings.HasPrefix(code, "x-") {
			continue
		}
		rptr := ptr + "/responses/" + tree.Escape(code)
		m, rd, mptr, _, ok := c.deref(d, rs[code], rptr)
		if !ok {
			continue
		}
		r := oas.Response{Code: code, Content: []oas.MediaType{}, Headers: sortedKeys(obj(m["headers"]))}
		if c.v == v20 {
			if sv, ok := m["schema"]; ok {
				s := c.schema(rd, sv, mptr+"/schema", 0, map[string]bool{})
				for _, t := range c.mediaTypes(op, "produces", ptr) {
					sc := s
					r.Content = append(r.Content, oas.MediaType{Type: t, Schema: &sc})
				}
			}
		} else {
			r.Content = c.content(rd, m["content"], mptr+"/content")
		}
		o.Responses = append(o.Responses, r)
	}
}
