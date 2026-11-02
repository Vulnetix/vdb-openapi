// Package convert turns a parsed Swagger 2.0, OpenAPI 3.0 or OpenAPI 3.1
// tree into the oas contract. Each version's differences are settled here
// and nowhere else; what comes out is the same shape whichever went in.
package convert

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Vulnetix/vdb-openapi/internal/tree"
	"github.com/Vulnetix/vdb-openapi/oas"
	"github.com/Vulnetix/vdb-openapi/route"
)

// ErrNotSpec is returned for a document that is neither Swagger nor
// OpenAPI.
var ErrNotSpec = errors.New("not a Swagger or OpenAPI document")

type version int

const (
	v20 version = 20
	v30 version = 30
	v31 version = 31
)

// methods in the order operations are listed within one path.
var methods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// maxSchemaDepth bounds how far nested properties are summarised.
const maxSchemaDepth = 8

type conv struct {
	refs    *tree.Refs
	root    *tree.Doc
	v       version
	out     *oas.Document
	lossSet map[string]bool
	issSet  map[string]bool
}

// Detect returns the format and declared version of a parsed root, or
// ErrNotSpec.
func Detect(root any) (oas.Format, string, error) {
	m, ok := root.(map[string]any)
	if !ok {
		return "", "", ErrNotSpec
	}
	if s, ok := m["swagger"]; ok {
		return oas.FormatSwagger, text(s), nil
	}
	if s, ok := m["openapi"]; ok {
		return oas.FormatOpenAPI, text(s), nil
	}
	return "", "", ErrNotSpec
}

// Document converts a parsed root document. refs resolves $ref values;
// root.Location is the document's own path for relative references.
func Document(root *tree.Doc, refs *tree.Refs, src oas.Source) (*oas.Document, error) {
	format, specVersion, err := Detect(root.Root)
	if err != nil {
		return nil, err
	}
	c := &conv{
		refs: refs, root: root,
		out: &oas.Document{
			Contract:        oas.ContractVersion,
			Source:          src,
			Servers:         []oas.Server{},
			Operations:      []oas.Operation{},
			Webhooks:        []oas.Operation{},
			SecuritySchemes: map[string]oas.SecurityScheme{},
			Tags:            []string{},
			Losses:          []oas.Loss{},
			Issues:          []oas.Issue{},
		},
		lossSet: map[string]bool{}, issSet: map[string]bool{},
	}
	c.out.Source.Format = format
	c.out.Source.SpecVersion = specVersion
	c.v = c.pickVersion(format, specVersion)

	m := obj(root.Root)
	c.info(m)
	c.tags(m)
	c.securitySchemes(m)
	if c.v == v20 {
		c.out.Servers = c.swaggerServers(m)
	} else {
		c.out.Servers = c.servers(root, m["servers"], "/servers")
	}
	c.paths(m)
	if c.v == v31 {
		c.webhooks(m)
	}
	c.finish()
	return c.out, nil
}

func (c *conv) pickVersion(f oas.Format, sv string) version {
	switch {
	case f == oas.FormatSwagger:
		if sv != "2.0" {
			c.loss("/swagger", "swagger", fmt.Sprintf("version %q read as 2.0", sv))
		}
		return v20
	case strings.HasPrefix(sv, "3.0"):
		return v30
	case strings.HasPrefix(sv, "3.1"):
		return v31
	case strings.HasPrefix(sv, "3."):
		c.loss("/openapi", "openapi", fmt.Sprintf("version %q read as 3.1, the nearest known", sv))
		return v31
	default:
		c.loss("/openapi", "openapi", fmt.Sprintf("version %q is not known; read as 3.1", sv))
		return v31
	}
}

func (c *conv) info(m map[string]any) {
	i := obj(m["info"])
	c.out.Info = oas.Info{Title: text(i["title"]), Version: text(i["version"])}
	if c.v == v31 {
		c.out.Info.Summary = text(i["summary"])
	}
}

func (c *conv) tags(m map[string]any) {
	for _, t := range arr(m["tags"]) {
		if n := text(obj(t)["name"]); n != "" {
			c.out.Tags = append(c.out.Tags, n)
		}
	}
}

// at renders a pointer for Losses and Issues: plain within the root
// document, "file#/pointer" inside a referenced one.
func at(d *tree.Doc, ptr string) string {
	if d == nil || d.Location == "" {
		return ptr
	}
	return d.Location + "#" + ptr
}

func (c *conv) loss(ptr, construct, reason string) {
	k := ptr + "\x00" + construct
	if c.lossSet[k] {
		return
	}
	c.lossSet[k] = true
	c.out.Losses = append(c.out.Losses, oas.Loss{Pointer: ptr, Construct: construct, Reason: reason})
}

func (c *conv) issue(ptr, code, severity, msg string) {
	k := ptr + "\x00" + code
	if c.issSet[k] {
		return
	}
	c.issSet[k] = true
	c.out.Issues = append(c.out.Issues, oas.Issue{Pointer: ptr, Code: code, Message: msg, Severity: severity})
}

// deref follows a $ref on v, if it has one. It returns the target map, the
// document it is in, its pointer there and the component name (the last
// pointer token) when a ref was followed.
func (c *conv) deref(d *tree.Doc, v any, ptr string) (map[string]any, *tree.Doc, string, string, bool) {
	m := obj(v)
	ref, ok := m["$ref"].(string)
	if !ok {
		return m, d, ptr, "", m != nil
	}
	target, td, tptr, err := c.refs.Resolve(d, ref)
	if err != nil {
		if errors.Is(err, tree.ErrExternalRef) {
			c.loss(at(d, ptr), "$ref", err.Error())
		} else {
			c.issue(at(d, ptr), "unresolved-ref", "error", err.Error())
		}
		return nil, d, ptr, "", false
	}
	name := tptr
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	tm := obj(target)
	return tm, td, tptr, name, tm != nil
}

func (c *conv) paths(m map[string]any) {
	ps := obj(m["paths"])
	keys := sortedKeys(ps)
	for _, p := range keys {
		ptr := "/paths/" + tree.Escape(p)
		item, d, iptr, _, ok := c.deref(c.root, ps[p], ptr)
		if !ok {
			continue
		}
		c.pathItem(d, item, iptr, p, "")
	}
	sort.SliceStable(c.out.Operations, func(i, j int) bool {
		a, b := c.out.Operations[i], c.out.Operations[j]
		if a.PathTemplate != b.PathTemplate {
			return a.PathTemplate < b.PathTemplate
		}
		return methodIndex(a.Method) < methodIndex(b.Method)
	})
}

func (c *conv) webhooks(m map[string]any) {
	wh := obj(m["webhooks"])
	for _, name := range sortedKeys(wh) {
		ptr := "/webhooks/" + tree.Escape(name)
		item, d, iptr, _, ok := c.deref(c.root, wh[name], ptr)
		if !ok {
			continue
		}
		c.pathItem(d, item, iptr, "", name)
	}
}

func methodIndex(m string) int {
	for i, x := range methods {
		if strings.EqualFold(x, m) {
			return i
		}
	}
	return len(methods)
}

func (c *conv) pathItem(d *tree.Doc, item map[string]any, ptr, path, webhook string) {
	shared := arr(item["parameters"])
	var pathServers []oas.Server
	if c.v != v20 {
		if _, ok := item["servers"]; ok {
			pathServers = c.servers(d, item["servers"], ptr+"/servers")
		}
	}
	for _, method := range methods {
		raw, ok := item[method]
		if !ok {
			continue
		}
		op := obj(raw)
		if op == nil {
			continue
		}
		optr := ptr + "/" + method
		c.addOperation(d, op, optr, method, path, webhook, shared, ptr+"/parameters", pathServers)
	}
	if _, ok := item["query"]; ok {
		c.loss(at(d, ptr+"/query"), "query", "the QUERY method is not part of the contract yet")
	}
	if _, ok := item["additionalOperations"]; ok {
		c.loss(at(d, ptr+"/additionalOperations"), "additionalOperations", "custom methods are not part of the contract yet")
	}
}

func (c *conv) addOperation(d *tree.Doc, op map[string]any, ptr, method, path, webhook string, shared []any, sharedPtr string, pathServers []oas.Server) {
	o := oas.Operation{
		Method:       strings.ToUpper(method),
		PathTemplate: path,
		Webhook:      webhook,
		OperationID:  text(op["operationId"]),
		Summary:      text(op["summary"]),
		Tags:         []string{},
		Deprecated:   boolean(op["deprecated"]),
		Parameters:   []oas.Parameter{},
		Responses:    []oas.Response{},
		Callbacks:    []string{},
		PIIHints:     []oas.PIIHint{},
	}
	if path != "" {
		o.Key = route.Key(o.Method, path)
	}
	for _, t := range arr(op["tags"]) {
		if s := text(t); s != "" {
			o.Tags = append(o.Tags, s)
		}
	}

	c.operationInputs(d, op, ptr, shared, sharedPtr, &o)
	c.responses(d, op, ptr, &o)
	o.Security = c.security(op)

	switch {
	case c.v == v20:
		o.Servers = c.out.Servers
	default:
		if _, ok := op["servers"]; ok {
			o.Servers = c.servers(d, op["servers"], ptr+"/servers")
		} else if pathServers != nil {
			o.Servers = pathServers
		} else {
			o.Servers = c.out.Servers
		}
	}
	if o.Servers == nil {
		o.Servers = []oas.Server{}
	}

	if c.v != v20 {
		cbs := obj(op["callbacks"])
		o.Callbacks = append(o.Callbacks, sortedKeys(cbs)...)
	}
	o.Extensions = extensions(op)
	o.PIIHints = piiHints(&o)

	if webhook != "" {
		c.out.Webhooks = append(c.out.Webhooks, o)
	} else {
		c.out.Operations = append(c.out.Operations, o)
	}
}

// finish sorts the lists that came from map iteration so output is
// byte-stable.
func (c *conv) finish() {
	sort.Slice(c.out.Losses, func(i, j int) bool {
		a, b := c.out.Losses[i], c.out.Losses[j]
		if a.Pointer != b.Pointer {
			return a.Pointer < b.Pointer
		}
		return a.Construct < b.Construct
	})
	sort.Slice(c.out.Issues, func(i, j int) bool {
		a, b := c.out.Issues[i], c.out.Issues[j]
		if a.Pointer != b.Pointer {
			return a.Pointer < b.Pointer
		}
		return a.Code < b.Code
	})
}
