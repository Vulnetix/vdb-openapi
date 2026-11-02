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
        "400":
          description: bad
          content:
            application/json:
              schema: {type: object}
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

func vectorIDs(r robustness.Result) map[string]bool {
	got := map[string]bool{}
	for _, rec := range r.Recommendations {
		got[rec.Vector] = true
	}
	return got
}

func contains(list []string, id string) bool {
	for _, v := range list {
		if v == id {
			return true
		}
	}
	return false
}

// A spec with no upload, no PII and no open map has those checks marked not
// applicable. They are in neither total, so the score is unchanged by them.
func TestNotApplicableChecksAreExcludedNotZero(t *testing.T) {
	r := robustness.Score(doc(t, hardened))
	for _, id := range []string{"upload-max-length", "upload-type-allowlist", "pii-not-in-url", "map-properties-bounded", "path-param-constrained"} {
		if !contains(r.NotApplicable, id) {
			t.Errorf("%s should be not applicable, got %v", id, r.NotApplicable)
		}
	}
	// Every catalogue check is either applicable (has a stat) or not applicable.
	applicable := map[string]bool{}
	for _, v := range r.Vectors {
		applicable[v.Vector] = true
	}
	for _, v := range robustness.Vectors() {
		if applicable[v.ID] == contains(r.NotApplicable, v.ID) {
			t.Errorf("%s is both or neither applicable and not applicable", v.ID)
		}
	}
	if r.Score != 100 {
		t.Fatalf("a spec with everything applicable defended must score 100, got %v", r.Score)
	}
}

// Adding an upload makes the upload checks applicable. Defending them keeps
// the score at 100; leaving them open is a real deduction.
func TestUploadChecksApplyOnlyWhenAnUploadExists(t *testing.T) {
	withUpload := hardened + `
  /files:
    post:
      requestBody:
        content:
          multipart/form-data:
            schema:
              type: object
              additionalProperties: false
              required: [file]
              properties:
                file: {type: string, format: binary}
      responses:
        "201": {description: ok}
        "400": {description: bad, content: {application/json: {schema: {type: object}}}}
        "429": {description: slow}
`
	r := robustness.Score(doc(t, withUpload))
	if contains(r.NotApplicable, "upload-max-length") {
		t.Fatal("an upload exists, so the size check must apply")
	}
	if !vectorIDs(r)["upload-max-length"] || !vectorIDs(r)["upload-type-allowlist"] {
		t.Fatalf("undefended upload not recommended: %+v", r.Recommendations)
	}
	if r.Score >= 100 {
		t.Fatalf("an unbounded upload must lower the score, got %v", r.Score)
	}
}

func TestPathAndHeaderParametersMustBeConstrained(t *testing.T) {
	r := robustness.Score(doc(t, hardened+`
  /files/{name}:
    get:
      parameters:
        - {name: name, in: path, required: true, schema: {type: string, maxLength: 64}}
        - {name: X-Trace, in: header, schema: {type: string, maxLength: 64}}
      responses:
        "200": {description: ok}
        "400": {description: bad, content: {application/json: {schema: {type: object}}}}
        "429": {description: slow}
`))
	got := vectorIDs(r)
	for _, id := range []string{"path-param-constrained", "header-param-constrained", "string-non-empty"} {
		if !got[id] {
			t.Errorf("%s not recommended: %+v", id, r.Recommendations)
		}
	}
	// A pattern defends all three.
	fixed := robustness.Score(doc(t, hardened+`
  /files/{name}:
    get:
      parameters:
        - {name: name, in: path, required: true, schema: {type: string, maxLength: 64, pattern: "^[a-z0-9_-]+$"}}
        - {name: X-Trace, in: header, schema: {type: string, maxLength: 64, pattern: "^[A-Za-z0-9._~-]+$"}}
      responses:
        "200": {description: ok}
        "400": {description: bad, content: {application/json: {schema: {type: object}}}}
        "429": {description: slow}
`))
	for _, id := range []string{"path-param-constrained", "header-param-constrained", "string-non-empty"} {
		if vectorIDs(fixed)[id] {
			t.Errorf("%s still recommended with a pattern: %+v", id, fixed.Recommendations)
		}
	}
}

func TestStateChangingOperationMustRequireAuth(t *testing.T) {
	src := `
openapi: 3.0.3
info: {title: t, version: "1"}
servers: [{url: https://api.example.com}]
components:
  securitySchemes:
    bearer: {type: http, scheme: bearer}
paths:
  /things:
    get:
      security: []
      responses: {"200": {description: ok}}
    post:
      security: []
      responses: {"201": {description: ok}}
`
	r := robustness.Score(doc(t, src))
	for _, rec := range r.Recommendations {
		if rec.Vector == "mutating-requires-auth" && rec.Key == "POST /things" {
			for _, rec2 := range r.Recommendations {
				if rec2.Vector == "mutating-requires-auth" && rec2.Key == "GET /things" {
					t.Fatal("a read must not be graded by the state-changing check")
				}
			}
			return
		}
	}
	t.Fatalf("public POST not flagged: %+v", r.Recommendations)
}

func TestErrorSchemaAndWildcardMediaType(t *testing.T) {
	r := robustness.Score(doc(t, `
openapi: 3.0.3
info: {title: t, version: "1"}
servers: [{url: https://api.example.com}]
components:
  securitySchemes:
    bearer: {type: http, scheme: bearer}
security: [{bearer: []}]
paths:
  /x:
    put:
      requestBody:
        content:
          "*/*":
            schema: {type: object, additionalProperties: false, required: [a], properties: {a: {type: string, maxLength: 5, minLength: 1}}}
      responses:
        "200": {description: ok}
        "400": {description: bad}
        "429": {description: slow}
`))
	got := vectorIDs(r)
	if !got["error-schema-declared"] || !got["body-media-type-specific"] {
		t.Fatalf("expected error-schema-declared and body-media-type-specific: %+v", r.Recommendations)
	}
}

func TestPersonalDataInTheURLIsFlaggedAndBodyIsNot(t *testing.T) {
	src := func(where string) string {
		return `
openapi: 3.0.3
info: {title: t, version: "1"}
servers: [{url: https://api.example.com}]
components:
  securitySchemes:
    bearer: {type: http, scheme: bearer}
security: [{bearer: []}]
paths:
  /lookup:
    get:
      parameters:
        - {name: email, in: ` + where + `, schema: {type: string, maxLength: 64, pattern: "^[a-z@.]+$"}}
      responses:
        "200": {description: ok}
        "400": {description: bad, content: {application/json: {schema: {type: object}}}}
        "429": {description: slow}
`
	}
	if !vectorIDs(robustness.Score(doc(t, src("query"))))["pii-not-in-url"] {
		t.Fatal("email in the query string must be flagged")
	}
	if vectorIDs(robustness.Score(doc(t, src("header"))))["pii-not-in-url"] {
		t.Fatal("email in a header is not the URL exposure")
	}
}

func TestOpenMapNeedsAPropertyBound(t *testing.T) {
	base := `
openapi: 3.0.3
info: {title: t, version: "1"}
servers: [{url: https://api.example.com}]
components:
  securitySchemes:
    bearer: {type: http, scheme: bearer}
security: [{bearer: []}]
paths:
  /m:
    put:
      requestBody:
        content:
          application/json:
            schema: {type: object, additionalProperties: true, required: [a], properties: {a: {type: string, maxLength: 5, minLength: 1}}%s}
      responses:
        "200": {description: ok}
        "400": {description: bad, content: {application/json: {schema: {type: object}}}}
        "429": {description: slow}
`
	open := robustness.Score(doc(t, replace(base, "%s", "")))
	if !vectorIDs(open)["map-properties-bounded"] {
		t.Fatalf("open map without maxProperties not flagged: %+v", open.Recommendations)
	}
	bounded := robustness.Score(doc(t, replace(base, "%s", ", maxProperties: 50")))
	if vectorIDs(bounded)["map-properties-bounded"] {
		t.Fatalf("bounded map still flagged: %+v", bounded.Recommendations)
	}
}

func TestEveryVectorHasItsOwnWords(t *testing.T) {
	for _, v := range robustness.Vectors() {
		if v.Group == "" || v.Why == "" || v.Applies == "" {
			t.Errorf("%s is missing group, why or applies", v.ID)
		}
	}
}
