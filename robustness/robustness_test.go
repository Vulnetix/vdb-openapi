package robustness_test

import (
	"os"
	"testing"

	"github.com/Vulnetix/vdb-openapi/load"
	"github.com/Vulnetix/vdb-openapi/oas"
	"github.com/Vulnetix/vdb-openapi/robustness"
)

func doc(t *testing.T, src string) *oas.Document {
	t.Helper()
	d, err := load.Load([]byte(src), load.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func weight(id string) float64 {
	for _, v := range robustness.Vectors() {
		if v.ID == id {
			return v.Weight
		}
	}
	return 0
}

const hardened = `
openapi: 3.0.3
info: {title: t, version: "1"}
servers: [{url: https://api.example.com}]
components:
  securitySchemes:
    bearer: {type: http, scheme: bearer}
security: [{bearer: []}]
paths:
  /items:
    get:
      parameters:
        - name: limit
          in: query
          schema: {type: integer, format: int32, minimum: 1, maximum: 100}
        - name: q
          in: query
          schema: {type: string, maxLength: 64, pattern: "^[a-z0-9 ]+$"}
      responses:
        "200":
          description: ok
          content:
            application/json:
              schema:
                type: object
                additionalProperties: false
                properties:
                  n: {type: integer}
        "400": {description: bad}
        "429": {description: slow}
`

func TestFullyDefendedScores100(t *testing.T) {
	r := robustness.Score(doc(t, hardened))
	if r.Score != 100 {
		t.Fatalf("score = %v, recommendations = %+v", r.Score, r.Recommendations)
	}
	if len(r.Recommendations) != 0 {
		t.Fatalf("recommendations = %+v", r.Recommendations)
	}
}

// Removing one defence lowers the defended weight by exactly that vector's
// weight, and the recommendation says so.
func TestEachDefenceCountsItsWeight(t *testing.T) {
	full := robustness.Score(doc(t, hardened))
	weak := robustness.Score(doc(t, replace(hardened, "maximum: 100}", "}")))
	lost := full.DefendedWeight - weak.DefendedWeight
	if lost != weight("pagination-max")+weight("number-bounded") {
		t.Fatalf("lost %v, want pagination-max + number-bounded", lost)
	}
	if weak.ApplicableWeight != full.ApplicableWeight {
		t.Fatalf("applicable weight changed: %v vs %v", weak.ApplicableWeight, full.ApplicableWeight)
	}
	if len(weak.Recommendations) != 2 || weak.Recommendations[0].Vector != "pagination-max" {
		t.Fatalf("recommendations = %+v", weak.Recommendations)
	}
	if weak.Recommendations[0].Gain < weak.Recommendations[1].Gain {
		t.Fatal("recommendations not sorted by gain")
	}
}

func TestPatternThatBlocksOnlyLiteralQuote(t *testing.T) {
	r := robustness.Score(doc(t, replace(hardened, `pattern: "^[a-z0-9 ]+$"`, `pattern: "^[^'<>;|]*$"`)))
	got := map[string]bool{}
	for _, rec := range r.Recommendations {
		got[rec.Vector] = true
	}
	if !got["pattern-rejects-encoded"] {
		t.Fatalf("encoded forms not caught: %+v", r.Recommendations)
	}
}

func TestReDoSPatternFlagged(t *testing.T) {
	r := robustness.Score(doc(t, replace(hardened, `pattern: "^[a-z0-9 ]+$"`, `pattern: "^(a+)+$"`)))
	for _, rec := range r.Recommendations {
		if rec.Vector == "pattern-redos-safe" {
			return
		}
	}
	t.Fatalf("ReDoS pattern not flagged: %+v", r.Recommendations)
}

func TestUnspecifiedSecurityAndMassAssignment(t *testing.T) {
	r := robustness.Score(doc(t, `
openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /users:
    post:
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name: {type: string}
      responses: {"201": {description: ok}}
`))
	want := map[string]bool{"security-declared": false, "object-closed": false, "string-max-length": false, "rate-limit-declared": false}
	for _, rec := range r.Recommendations {
		if _, ok := want[rec.Vector]; ok {
			want[rec.Vector] = true
		}
	}
	for v, seen := range want {
		if !seen {
			t.Errorf("%s not recommended", v)
		}
	}
}

func TestPetstoreScores(t *testing.T) {
	data, err := os.ReadFile("../testdata/coherence/petstore.oas30.yaml")
	if err != nil {
		t.Fatal(err)
	}
	r := robustness.Score(doc(t, string(data)))
	if r.Score <= 0 || r.Score >= 100 {
		t.Fatalf("score = %v", r.Score)
	}
	// basic auth on DELETE is weak security.
	for _, rec := range r.Recommendations {
		if rec.Vector == "security-strong" && rec.Key == "DELETE /pets/{param}" {
			return
		}
	}
	t.Fatalf("basic auth not flagged: %+v", r.Recommendations)
}

func TestConcretePath(t *testing.T) {
	d := doc(t, `
openapi: 3.0.3
info: {title: t, version: "1"}
paths:
  /pets/{id}/photos/{n}:
    get:
      parameters:
        - {name: id, in: path, required: true, schema: {type: string, format: uuid}}
        - {name: n, in: path, required: true, example: 3, schema: {type: integer}}
      responses: {"200": {description: ok}}
`)
	f, ok := robustness.ConcretePath("/v1", d.Operations[0])
	if !ok || f.Path != "/v1/pets/00000000-0000-4000-8000-000000000000/photos/3" || f.FromExamples {
		t.Fatalf("filled = %+v ok=%v", f, ok)
	}
}

func replace(s, old, new string) string {
	out := ""
	for {
		i := index(s, old)
		if i < 0 {
			return out + s
		}
		out += s[:i] + new
		s = s[i+len(old):]
	}
}

func index(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
