package lint_test

import (
	"os"
	"testing"

	"github.com/Vulnetix/vdb-openapi/lint"
	"github.com/Vulnetix/vdb-openapi/load"
)

func TestPetstoreIsClean(t *testing.T) {
	data, err := os.ReadFile("../testdata/coherence/petstore.oas30.yaml")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := load.Load(data, load.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if s := lint.Check(doc); len(s.Findings) != 0 {
		t.Fatalf("findings = %+v", s.Findings)
	}
}

func TestProblems(t *testing.T) {
	doc, err := load.Load([]byte(`
openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /a/{id}:
    get:
      operationId: same
      security: [{ghost: []}]
      responses: {"200": {description: ok}}
  /b:
    get:
      operationId: same
`), load.Options{})
	if err != nil {
		t.Fatal(err)
	}
	s := lint.Check(doc)
	want := map[string]bool{
		"no-servers": false, "path-parameter-undeclared": false, "unknown-security-scheme": false,
		"duplicate-operation-id": false, "no-responses": false,
	}
	for _, f := range s.Findings {
		if _, ok := want[f.Rule]; ok {
			want[f.Rule] = true
		}
	}
	for rule, seen := range want {
		if !seen {
			t.Errorf("rule %s did not fire: %+v", rule, s.Findings)
		}
	}
}
