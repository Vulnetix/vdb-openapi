// Package robustness grades how much of a known set of input vectors a
// spec's own validation defends.
//
// Every occurrence of an applicable vector (a string field, a page-size
// parameter, an operation) counts the vector's weight. The score is the
// defended weight over the applicable weight, times 100. A spec that
// defends every applicable vector scores 100, so each fix adds exactly its
// weight, and recommendations are ranked by what they add.
//
// The score measures what the spec declares, not what the server enforces.
// A page that shows it says so.
package robustness

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Vulnetix/vdb-openapi/oas"
)

//go:embed vectors.json
var vectorsJSON []byte

//go:embed corpus.json
var corpusJSON []byte

// Vector is one entry of the catalogue.
type Vector struct {
	ID        string  `json:"id"`
	Title     string  `json:"title"`
	AppliesTo string  `json:"appliesTo"`
	Weight    float64 `json:"weight"`
	OWASP     string  `json:"owasp"`
	CWE       int     `json:"cwe"`
	Keyword   string  `json:"keyword"`
	Suggest   any     `json:"suggest"`
}

type catalogue struct {
	Version string   `json:"version"`
	Vectors []Vector `json:"vectors"`
}

type payload struct {
	Class string `json:"class"`
	Value string `json:"value"`
}

type corpusFile struct {
	Version string    `json:"version"`
	Literal []payload `json:"literal"`
	Encoded []payload `json:"encoded"`
}

var (
	cat    catalogue
	byID   = map[string]Vector{}
	corpus corpusFile
)

func init() {
	if err := json.Unmarshal(vectorsJSON, &cat); err != nil {
		panic("robustness: vectors.json: " + err.Error())
	}
	for _, v := range cat.Vectors {
		byID[v.ID] = v
	}
	if err := json.Unmarshal(corpusJSON, &corpus); err != nil {
		panic("robustness: corpus.json: " + err.Error())
	}
}

// CatalogueVersion names the vector catalogue a score was computed with.
func CatalogueVersion() string { return cat.Version }

// Vectors returns the catalogue.
func Vectors() []Vector { return append([]Vector(nil), cat.Vectors...) }

// Fix is the spec change that defends one occurrence: set Keyword at Where.
type Fix struct {
	Keyword string `json:"keyword"`
	Value   any    `json:"value"`
}

// Recommendation is one undefended occurrence and what fixing it adds.
type Recommendation struct {
	Vector string  `json:"vector"`
	Title  string  `json:"title"`
	Key    string  `json:"key,omitempty"`
	Where  string  `json:"where"`
	Gain   float64 `json:"gain"`
	Weight float64 `json:"weight"`
	OWASP  string  `json:"owasp"`
	CWE    int     `json:"cwe"`
	Fix    Fix     `json:"fix"`
}

// VectorStat counts one vector across the document.
type VectorStat struct {
	Vector   string  `json:"vector"`
	Applies  int     `json:"applies"`
	Defended int     `json:"defended"`
	Weight   float64 `json:"weight"`
}

// OperationScore is the score of one operation on its own.
type OperationScore struct {
	Key              string  `json:"key"`
	Score            float64 `json:"score"`
	DefendedWeight   float64 `json:"defendedWeight"`
	ApplicableWeight float64 `json:"applicableWeight"`
}

// Result is a document's grade.
type Result struct {
	CatalogueVersion string           `json:"catalogueVersion"`
	Score            float64          `json:"score"`
	DefendedWeight   float64          `json:"defendedWeight"`
	ApplicableWeight float64          `json:"applicableWeight"`
	Operations       []OperationScore `json:"operations"`
	Vectors          []VectorStat     `json:"vectors"`
	Recommendations  []Recommendation `json:"recommendations"`
	// NotEvaluated lists patterns this package could not compile (for
	// example ECMAScript lookarounds). Their pattern vectors are left out of
	// the score rather than guessed.
	NotEvaluated []string `json:"notEvaluated"`
}

type occurrence struct {
	vector   string
	key      string
	where    string
	defended bool
}

type grader struct {
	occ          []occurrence
	notEvaluated []string
	schemes      map[string]oas.SecurityScheme
}

func (g *grader) add(vector, key, where string, defended bool) {
	g.occ = append(g.occ, occurrence{vector, key, where, defended})
}

// Score grades a document.
func Score(d *oas.Document) Result {
	g := &grader{schemes: d.SecuritySchemes}
	for _, s := range d.Servers {
		g.server(s)
	}
	for _, o := range d.Operations {
		g.operation(o)
	}
	return g.result()
}

func (g *grader) result() Result {
	r := Result{CatalogueVersion: cat.Version, Operations: []OperationScore{}, Vectors: []VectorStat{}, Recommendations: []Recommendation{}, NotEvaluated: g.notEvaluated}
	if r.NotEvaluated == nil {
		r.NotEvaluated = []string{}
	}
	stats := map[string]*VectorStat{}
	ops := map[string]*OperationScore{}
	for _, o := range g.occ {
		v := byID[o.vector]
		r.ApplicableWeight += v.Weight
		st := stats[o.vector]
		if st == nil {
			st = &VectorStat{Vector: o.vector, Weight: v.Weight}
			stats[o.vector] = st
		}
		st.Applies++
		if o.key != "" {
			os := ops[o.key]
			if os == nil {
				os = &OperationScore{Key: o.key}
				ops[o.key] = os
			}
			os.ApplicableWeight += v.Weight
			if o.defended {
				os.DefendedWeight += v.Weight
			}
		}
		if o.defended {
			r.DefendedWeight += v.Weight
			st.Defended++
		}
	}
	r.Score = pct(r.DefendedWeight, r.ApplicableWeight)
	for _, o := range g.occ {
		if o.defended {
			continue
		}
		v := byID[o.vector]
		r.Recommendations = append(r.Recommendations, Recommendation{
			Vector: o.vector, Title: v.Title, Key: o.key, Where: o.where,
			Gain: round(100 * v.Weight / r.ApplicableWeight), Weight: v.Weight,
			OWASP: v.OWASP, CWE: v.CWE, Fix: Fix{Keyword: v.Keyword, Value: v.Suggest},
		})
	}
	sort.SliceStable(r.Recommendations, func(i, j int) bool {
		a, b := r.Recommendations[i], r.Recommendations[j]
		if a.Gain != b.Gain {
			return a.Gain > b.Gain
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		if a.Where != b.Where {
			return a.Where < b.Where
		}
		return a.Vector < b.Vector
	})
	for _, id := range sortedKeys(stats) {
		r.Vectors = append(r.Vectors, *stats[id])
	}
	for _, k := range sortedKeys(ops) {
		os := ops[k]
		os.Score = pct(os.DefendedWeight, os.ApplicableWeight)
		r.Operations = append(r.Operations, *os)
	}
	return r
}

func pct(d, a float64) float64 {
	if a == 0 {
		return 100
	}
	return round(100 * d / a)
}

func round(f float64) float64 {
	return float64(int64(f*10+0.5)) / 10
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (g *grader) server(s oas.Server) {
	where := "server:" + s.URL
	if s.Scheme != "" {
		g.add("server-https", "", where, s.Scheme == "https")
	}
	for _, name := range sortedKeys(s.Variables) {
		g.add("server-variables-enumerated", "", where+"#"+name, len(s.Variables[name].Enum) > 0)
	}
}

func (g *grader) operation(o oas.Operation) {
	k := o.Key
	g.add("security-declared", k, "operation", o.Security.State != oas.SecurityUnspecified)
	if o.Security.State == oas.SecurityRequired || o.Security.State == oas.SecurityOptional {
		g.add("security-strong", k, "operation", !g.weakSecurity(o))
	}
	if uses, scoped := g.oauth(o); uses {
		g.add("oauth-scoped", k, "operation", scoped)
	}
	has4xx, has429 := false, false
	for _, r := range o.Responses {
		if strings.HasPrefix(r.Code, "4") || r.Code == "default" {
			has4xx = true
		}
		if r.Code == "429" {
			has429 = true
		}
	}
	g.add("client-errors-declared", k, "operation", has4xx)
	g.add("rate-limit-declared", k, "operation", has429)

	for _, p := range o.Parameters {
		where := string(p.In) + ":" + p.Name
		if p.In == oas.InPath && isIdentifier(p.Name) {
			g.add("id-not-sequential", k, where, !(p.Schema.Type == "integer" && p.Schema.Format != "uuid"))
		}
		if p.In == oas.InQuery && p.Schema.Type == "array" {
			g.add("array-param-bounded", k, where, p.Schema.MaxItems != nil)
		}
		g.field(k, where, p.Name, p.Schema, false, 0)
	}

	if o.RequestBody != nil {
		withSchema := 0
		for _, mt := range o.RequestBody.Content {
			if mt.Schema != nil && (mt.Schema.Type != "" || len(mt.Schema.Types) > 0 || len(mt.Schema.Properties) > 0) {
				withSchema++
			}
			if strings.HasPrefix(mt.Type, "text/") {
				g.add("text-charset", k, "body:"+mt.Type, strings.Contains(mt.Type, "charset="))
			}
		}
		if len(o.RequestBody.Content) > 1 {
			g.add("single-body-encoding", k, "body", withSchema == len(o.RequestBody.Content))
		}
		// One schema per body is graded; the others are the same input in a
		// different encoding, and single-body-encoding covers the gap.
		for _, mt := range o.RequestBody.Content {
			if mt.Schema == nil {
				continue
			}
			g.body(k, mt, *mt.Schema)
			break
		}
	}

	for _, r := range o.Responses {
		if !strings.HasPrefix(r.Code, "2") {
			continue
		}
		for _, mt := range r.Content {
			if mt.Schema != nil {
				g.responseObject(k, "response:"+r.Code, *mt.Schema, 0)
			}
			break
		}
	}
}

func (g *grader) body(k string, mt oas.MediaType, s oas.SchemaSummary) {
	if isUpload(s) {
		g.upload(k, "body", mt, "", s)
		return
	}
	g.field(k, "body", "", s, true, 0)
	if s.Type == "object" {
		for _, name := range sortedKeys(s.Properties) {
			if isUpload(s.Properties[name]) {
				g.upload(k, "body:"+name, mt, name, s.Properties[name])
			}
		}
	}
}

func (g *grader) upload(k, where string, mt oas.MediaType, field string, s oas.SchemaSummary) {
	g.add("upload-max-length", k, where, s.MaxLength != nil)
	allow := false
	if field != "" && mt.Encoding != nil && mt.Encoding[field] != "" && !strings.Contains(mt.Encoding[field], "*") {
		allow = true
	}
	if s.ContentMediaType != "" && s.ContentMediaType != "application/octet-stream" {
		allow = true
	}
	g.add("upload-type-allowlist", k, where, allow)
}

func isUpload(s oas.SchemaSummary) bool {
	return s.Type == "string" && s.Format == "binary"
}

const maxDepth = 6

// field grades one input value. request marks a request body, where object
// vectors apply.
func (g *grader) field(k, where, name string, s oas.SchemaSummary, request bool, depth int) {
	if depth > maxDepth || s.Recursive || s.ReadOnly {
		return
	}
	switch {
	case s.Type == "string" && !isUpload(s):
		g.str(k, where, s)
	case s.Type == "integer" || s.Type == "number":
		g.num(k, where, name, s)
	case s.Type == "array":
		g.add("array-max-items", k, where, s.MaxItems != nil)
		g.add("array-items-typed", k, where, s.Items != nil && (s.Items.Type != "" || len(s.Items.Types) > 0 || len(s.Items.Properties) > 0 || len(s.Items.Variants) > 0))
		if s.Items != nil {
			g.field(k, where+"[]", name, *s.Items, request, depth+1)
		}
	case s.Type == "object" || (s.Type == "" && len(s.Properties) > 0):
		if request {
			g.add("object-closed", k, where, s.AdditionalProperties != nil && !*s.AdditionalProperties)
			g.add("object-required", k, where, len(s.Required) > 0)
		}
		for _, p := range sortedKeys(s.Properties) {
			child := s.Properties[p]
			if isUpload(child) {
				continue
			}
			g.field(k, joinWhere(where, p), p, child, request, depth+1)
		}
	}
	for i, v := range s.Variants {
		g.field(k, where+"|"+itoa(i), name, v, request, depth+1)
	}
}

func joinWhere(where, p string) string {
	if strings.HasSuffix(where, ":") || where == "body" {
		if where == "body" {
			return "body:" + p
		}
		return where + p
	}
	return where + "." + p
}

var strictFormats = map[string]bool{
	"uuid": true, "date": true, "date-time": true, "time": true, "ipv4": true, "ipv6": true,
	"byte": true, "int32": true, "int64": true, "duration": true,
}

func (g *grader) str(k, where string, s oas.SchemaSummary) {
	enum := s.EnumCount > 0
	g.add("string-max-length", k, where, s.MaxLength != nil || enum)
	g.add("string-constrained", k, where, enum || s.Pattern != "" || strictFormats[s.Format])
	if s.Pattern == "" || enum {
		return
	}
	g.add("pattern-anchored", k, where, strings.HasPrefix(s.Pattern, "^") && strings.HasSuffix(s.Pattern, "$"))
	g.add("pattern-redos-safe", k, where, !redosProne(s.Pattern))
	re, err := regexp.Compile(s.Pattern)
	if err != nil {
		g.notEvaluated = append(g.notEvaluated, k+" "+where+": "+s.Pattern)
		return
	}
	g.add("pattern-rejects-known-bad", k, where, rejectsAll(re, s, corpus.Literal))
	g.add("pattern-rejects-encoded", k, where, rejectsAll(re, s, corpus.Encoded))
}

// rejectsAll reports whether the schema refuses every payload. A payload
// is accepted when it matches the pattern and fits the length bounds;
// JSON Schema patterns are unanchored, as here.
func rejectsAll(re *regexp.Regexp, s oas.SchemaSummary, ps []payload) bool {
	for _, p := range ps {
		if accepts(re, s, p.Value) {
			return false
		}
	}
	return true
}

func accepts(re *regexp.Regexp, s oas.SchemaSummary, v string) bool {
	n := utf8.RuneCountInString(v)
	if s.MaxLength != nil && n > *s.MaxLength {
		return false
	}
	if s.MinLength != nil && n < *s.MinLength {
		return false
	}
	return re.MatchString(v)
}

// redosProne is a heuristic for patterns that backtrack catastrophically on
// a backtracking engine (most servers' regex libraries are): a quantified
// group that itself contains a quantifier, or an alternation of overlapping
// branches under a quantifier.
var (
	nestedQuant  = regexp.MustCompile(`\([^()]*[+*][^()]*\)[+*{]`)
	quantGroup   = regexp.MustCompile(`\(([^()|]+)\|([^()]+)\)[+*]`)
	repeatedDots = regexp.MustCompile(`(\.\*.*){3,}`)
)

func redosProne(p string) bool {
	if nestedQuant.MatchString(p) || repeatedDots.MatchString(p) {
		return true
	}
	// Go's RE2 has no backreferences, so overlap is checked here: a
	// quantified alternation whose branches start with the same text.
	for _, m := range quantGroup.FindAllStringSubmatch(p, -1) {
		a, b := m[1], m[2]
		if a != "" && b != "" && (strings.HasPrefix(b, a) || strings.HasPrefix(a, b) || a[0] == b[0]) {
			return true
		}
	}
	return false
}

var countName = regexp.MustCompile(`(?i)(^|_)(id|count|size|limit|offset|page|quantity|qty|amount|total|age|length|index)$|(Id|Count|Size|Limit|Offset|Page|Quantity)$`)
var pageName = regexp.MustCompile(`(?i)^(limit|size|page_?size|per_?page|count|top|max|max_?results|first|last)$`)

func (g *grader) num(k, where, name string, s oas.SchemaSummary) {
	enum := s.EnumCount > 0
	g.add("number-bounded", k, where, enum || (s.Minimum != nil && s.Maximum != nil))
	if s.Type == "integer" {
		g.add("integer-format", k, where, s.Format == "int32" || s.Format == "int64" || enum)
	}
	if name != "" && countName.MatchString(name) {
		g.add("count-non-negative", k, where, enum || (s.Minimum != nil && *s.Minimum >= 0))
	}
	if name != "" && pageName.MatchString(name) && strings.HasPrefix(where, "query:") {
		g.add("pagination-max", k, where, s.Maximum != nil || enum)
	}
}

func isIdentifier(name string) bool {
	n := strings.ToLower(name)
	return n == "id" || strings.HasSuffix(n, "_id") || strings.HasSuffix(name, "Id") || strings.HasSuffix(name, "ID")
}

// weakSecurity reports an operation that some alternative lets a caller
// satisfy with basic auth or an API key sent in the query string.
func (g *grader) weakSecurity(o oas.Operation) bool {
	for _, alt := range o.Security.Alternatives {
		weak := true
		for _, u := range alt {
			s := g.schemes[u.Scheme]
			isWeak := (s.Type == "http" && s.Scheme == "basic") || (s.Type == "apiKey" && s.In == oas.InQuery)
			if !isWeak {
				weak = false
			}
		}
		if weak && len(alt) > 0 {
			return true
		}
	}
	return false
}

// oauth reports whether the operation uses an OAuth or OpenID Connect
// scheme, and whether every such use names at least one scope.
func (g *grader) oauth(o oas.Operation) (uses, scoped bool) {
	scoped = true
	for _, alt := range o.Security.Alternatives {
		for _, u := range alt {
			t := g.schemes[u.Scheme].Type
			if t == "oauth2" || t == "openIdConnect" {
				uses = true
				if len(u.Scopes) == 0 {
					scoped = false
				}
			}
		}
	}
	return uses, scoped
}

func (g *grader) responseObject(k, where string, s oas.SchemaSummary, depth int) {
	if depth > 2 || s.Recursive {
		return
	}
	switch {
	case s.Type == "array" && s.Items != nil:
		g.responseObject(k, where+"[]", *s.Items, depth+1)
	case s.Type == "object" || (s.Type == "" && len(s.Properties) > 0):
		g.add("response-closed", k, where, s.AdditionalProperties != nil && !*s.AdditionalProperties)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
