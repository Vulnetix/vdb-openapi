package load_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/Vulnetix/vdb-openapi/load"
	"github.com/Vulnetix/vdb-openapi/oas"
)

func mustLoad(t *testing.T, src string, opt load.Options) *oas.Document {
	t.Helper()
	doc, err := load.Load([]byte(src), opt)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func hasLoss(doc *oas.Document, construct string) bool {
	for _, l := range doc.Losses {
		if l.Construct == construct {
			return true
		}
	}
	return false
}

func TestNotSpec(t *testing.T) {
	_, err := load.Load([]byte("name: not an api\n"), load.Options{})
	if !errors.Is(err, load.ErrNotSpec) {
		t.Fatalf("err = %v, want ErrNotSpec", err)
	}
}

func TestLossesFor31Keywords(t *testing.T) {
	doc := mustLoad(t, `
openapi: 3.1.0
info: {title: t, version: "1"}
paths:
  /x:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              if: {properties: {a: {const: 1}}}
              then: {required: [b]}
              properties:
                tuple: {type: array, prefixItems: [{type: string}]}
      responses: {"200": {description: ok}}
`, load.Options{})
	for _, kw := range []string{"if", "then", "prefixItems"} {
		if !hasLoss(doc, kw) {
			t.Errorf("no Loss for %s: %+v", kw, doc.Losses)
		}
	}
}

func TestUnknownVersionReadAsNearest(t *testing.T) {
	doc := mustLoad(t, `{"openapi":"3.2.0","info":{"title":"t","version":"1"},"paths":{"/a":{"get":{"responses":{"200":{"description":"ok"}}}}}}`, load.Options{})
	if !hasLoss(doc, "openapi") {
		t.Fatalf("no version Loss: %+v", doc.Losses)
	}
	if len(doc.Operations) != 1 || doc.Operations[0].Key != "GET /a" {
		t.Fatalf("operations = %+v", doc.Operations)
	}
}

func TestExternalRefWithoutFSIsALoss(t *testing.T) {
	doc := mustLoad(t, `
openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /a:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema: {$ref: "schemas.yaml#/Thing"}
`, load.Options{})
	if !hasLoss(doc, "$ref") {
		t.Fatalf("external ref not recorded as a Loss: %+v", doc.Losses)
	}
}

func TestExternalRefThroughFS(t *testing.T) {
	fsys := fstest.MapFS{
		"api/openapi.yaml": {Data: []byte(`
openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /things/{id}:
    get:
      parameters:
        - $ref: "common/params.yaml#/Id"
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema: {$ref: "common/schemas.yaml#/Thing"}
`)},
		"api/common/params.yaml":  {Data: []byte("Id: {name: id, in: path, required: true, schema: {type: string, format: uuid}}\n")},
		"api/common/schemas.yaml": {Data: []byte("Thing: {type: object, properties: {owner: {$ref: '#/Owner'}}}\nOwner: {type: object, properties: {email: {type: string, format: email}}}\n")},
	}
	doc, err := load.LoadFile(fsys, "api/openapi.yaml", load.Options{})
	if err != nil {
		t.Fatal(err)
	}
	op := doc.Operations[0]
	if len(op.Parameters) != 1 || op.Parameters[0].Schema.Format != "uuid" {
		t.Fatalf("parameter not resolved: %+v", op.Parameters)
	}
	s := op.Responses[0].Content[0].Schema
	if s.Name != "Thing" || s.Properties["owner"].Name != "Owner" {
		t.Fatalf("nested external ref not resolved: %+v", s)
	}
	if len(op.PIIHints) != 1 || op.PIIHints[0].Where != "response:200:owner.email" {
		t.Fatalf("pii = %+v", op.PIIHints)
	}
	if len(doc.Losses) != 0 || len(doc.Issues) != 0 {
		t.Fatalf("losses %+v issues %+v", doc.Losses, doc.Issues)
	}
}

func TestFSRefCannotEscape(t *testing.T) {
	fsys := fstest.MapFS{
		"api/openapi.yaml": {Data: []byte(`
openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /a:
    get:
      responses:
        "200": {$ref: "../../etc/passwd#/x"}
`)},
	}
	doc, err := load.LoadFile(fsys, "api/openapi.yaml", load.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Issues) == 0 {
		t.Fatal("a ref outside the file system was not reported")
	}
}

type fakeResolver map[string]string

func (f fakeResolver) Fetch(u string) ([]byte, error) {
	if s, ok := f[u]; ok {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("not found: %s", u)
}

func TestRemoteRefOnlyThroughResolver(t *testing.T) {
	src := `
openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /a:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema: {$ref: "https://schemas.example.com/thing.json#/Thing"}
`
	without := mustLoad(t, src, load.Options{})
	if !hasLoss(without, "$ref") {
		t.Fatal("remote ref followed with no resolver")
	}
	with := mustLoad(t, src, load.Options{Resolver: fakeResolver{
		"https://schemas.example.com/thing.json": `{"Thing":{"type":"object","properties":{"n":{"type":"integer"}}}}`,
	}})
	s := with.Operations[0].Responses[0].Content[0].Schema
	if s.Name != "Thing" || s.Properties["n"].Type != "integer" {
		t.Fatalf("remote ref not resolved: %+v", s)
	}
}

func TestRecursiveSchemaStops(t *testing.T) {
	doc := mustLoad(t, `
openapi: 3.0.3
info: {title: t, version: "1"}
components:
  schemas:
    Node:
      type: object
      properties:
        children: {type: array, items: {$ref: "#/components/schemas/Node"}}
paths:
  /tree:
    get:
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema: {$ref: "#/components/schemas/Node"}
`, load.Options{})
	s := doc.Operations[0].Responses[0].Content[0].Schema
	child := s.Properties["children"].Items
	if child == nil || !child.Recursive || child.Name != "Node" {
		t.Fatalf("recursion not marked: %+v", child)
	}
}

func TestSecurityStates(t *testing.T) {
	doc := mustLoad(t, `
openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /none:
    get: {responses: {"200": {description: ok}}}
`, load.Options{})
	if got := doc.Operations[0].Security.State; got != oas.SecurityUnspecified {
		t.Fatalf("no security anywhere read as %q, want unspecified", got)
	}
}

func TestServerVariables(t *testing.T) {
	doc := mustLoad(t, `
openapi: 3.0.3
info: {title: t, version: "1"}
servers:
  - url: "https://{region}.api.example.com:{port}/base/"
    variables:
      region: {default: eu, enum: [eu, us]}
      port: {default: "8443"}
paths: {}
`, load.Options{})
	s := doc.Servers[0]
	if s.Resolved != "https://eu.api.example.com:8443/base/" || s.Host != "eu.api.example.com:8443" || s.BasePath != "/base" {
		t.Fatalf("server = %+v", s)
	}
}

func TestSwaggerCollectionFormat(t *testing.T) {
	doc := mustLoad(t, `
swagger: "2.0"
info: {title: t, version: "1"}
paths:
  /a:
    get:
      parameters:
        - {name: ids, in: query, type: array, items: {type: string}, collectionFormat: multi}
        - {name: tags, in: query, type: array, items: {type: string}}
        - {name: odd, in: query, type: array, items: {type: string}, collectionFormat: tsv}
      responses: {"200": {description: ok}}
`, load.Options{})
	ps := map[string]oas.Parameter{}
	for _, p := range doc.Operations[0].Parameters {
		ps[p.Name] = p
	}
	if !ps["ids"].Explode || ps["tags"].Explode {
		t.Fatalf("explode: ids=%v tags=%v", ps["ids"].Explode, ps["tags"].Explode)
	}
	if !hasLoss(doc, "collectionFormat") {
		t.Fatal("tsv not recorded as a Loss")
	}
	// A spec with no consumes or produces gets application/json and an info issue.
	if len(doc.Issues) != 0 {
		// No body or response schema here, so neither is assumed.
		t.Fatalf("issues = %+v", doc.Issues)
	}
}

func TestLimits(t *testing.T) {
	bomb := `a: &a ["x","x","x","x","x","x","x","x","x","x"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f,*f]
openapi: 3.0.3
`
	if _, err := load.Load([]byte(bomb), load.Options{}); !errors.Is(err, load.ErrTooMany) {
		t.Errorf("alias bomb: err = %v, want ErrTooMany", err)
	}
	deep := strings.Repeat("[", 300) + strings.Repeat("]", 300)
	if _, err := load.Load([]byte(deep), load.Options{}); !errors.Is(err, load.ErrTooDeep) {
		t.Errorf("deep nesting: err = %v, want ErrTooDeep", err)
	}
	if _, err := load.Load(make([]byte, 2048), load.Options{Limits: load.Limits{MaxBytes: 1024}}); !errors.Is(err, load.ErrTooLarge) {
		t.Errorf("oversize: err = %v, want ErrTooLarge", err)
	}
}

func TestSniff(t *testing.T) {
	f, v, ok := load.Sniff([]byte(`{"swagger":"2.0"}`), load.Options{})
	if !ok || f != oas.FormatSwagger || v != "2.0" {
		t.Fatalf("Sniff = %v %v %v", f, v, ok)
	}
	if _, _, ok := load.Sniff([]byte("kind: Deployment\n"), load.Options{}); ok {
		t.Fatal("a Kubernetes manifest sniffed as a spec")
	}
}

func FuzzLoad(f *testing.F) {
	f.Add([]byte(`{"openapi":"3.1.0","paths":{"/a":{"get":{}}}}`))
	f.Add([]byte("swagger: '2.0'\npaths:\n  /a/{b}:\n    post:\n      parameters: [{in: body, name: x, schema: {$ref: '#/definitions/X'}}]\n"))
	f.Add([]byte("openapi: 3.0.0\ncomponents: {schemas: {A: {$ref: '#/components/schemas/A'}}}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = load.Load(data, load.Options{Limits: load.Limits{MaxBytes: 1 << 16, MaxNodes: 50_000}})
	})
}
