package diff_test

import (
	"os"
	"strings"
	"testing"

	"github.com/Vulnetix/vdb-openapi/diff"
	"github.com/Vulnetix/vdb-openapi/load"
	"github.com/Vulnetix/vdb-openapi/oas"
)

func petstore(t *testing.T, edit func(string) string) *oas.Document {
	t.Helper()
	data, err := os.ReadFile("../testdata/coherence/petstore.oas30.yaml")
	if err != nil {
		t.Fatal(err)
	}
	src := string(data)
	if edit != nil {
		src = edit(src)
	}
	doc, err := load.Load([]byte(src), load.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func find(r diff.Result, kind diff.Kind, key string) *diff.Change {
	for i, c := range r.Changes {
		if c.Kind == kind && c.Key == key {
			return &r.Changes[i]
		}
	}
	return nil
}

func TestSameDocumentHasNoChanges(t *testing.T) {
	a, b := petstore(t, nil), petstore(t, nil)
	if r := diff.Compare(a, b); len(r.Changes) != 0 {
		t.Fatalf("changes = %+v", r.Changes)
	}
}

func TestSecurityRemovedIsARegression(t *testing.T) {
	old := petstore(t, nil)
	cur := petstore(t, func(s string) string {
		return strings.Replace(s, "      security:\n        - oauth: [write:pets]\n", "      security: []\n", 1)
	})
	r := diff.Compare(old, cur)
	c := find(r, diff.SecurityRemoved, "POST /pets")
	if c == nil || !c.SecurityRegression {
		t.Fatalf("security removal not reported: %+v", r.Changes)
	}
	if r.SecurityRegressions != 1 {
		t.Fatalf("regressions = %d", r.SecurityRegressions)
	}
}

func TestRemovalAndRequiredParameterAreBreaking(t *testing.T) {
	old := petstore(t, nil)
	cur := petstore(t, func(s string) string {
		s = strings.Replace(s, "    delete:\n      operationId: deletePet\n      deprecated: true\n      security:\n        - basicAuth: []\n        - {}\n      responses:\n        \"204\":\n          description: Deleted\n", "", 1)
		return strings.Replace(s, "        - name: status\n          in: query\n", "        - name: status\n          in: query\n          required: true\n", 1)
	})
	r := diff.Compare(old, cur)
	if c := find(r, diff.OperationRemoved, "DELETE /pets/{param}"); c == nil || !c.Breaking {
		t.Fatalf("removal not breaking: %+v", r.Changes)
	}
	if c := find(r, diff.ParameterRequired, "GET /pets"); c == nil || !c.Breaking {
		t.Fatalf("required parameter not breaking: %+v", r.Changes)
	}
}

func TestWeakerAlternativeIsARegression(t *testing.T) {
	old := petstore(t, nil)
	cur := petstore(t, func(s string) string {
		return strings.Replace(s, "        - oauth: [write:pets]\n", "        - oauth: [write:pets]\n        - apiKey: []\n", 1)
	})
	r := diff.Compare(old, cur)
	if c := find(r, diff.SecurityWeakened, "POST /pets"); c == nil || !c.SecurityRegression {
		t.Fatalf("weaker alternative not reported: %+v", r.Changes)
	}
}
