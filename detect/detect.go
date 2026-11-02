// Package detect finds API descriptions: files in a repository that are
// specs, code that generates one at runtime, and the paths a running
// service serves one on.
package detect

import (
	_ "embed"
	"encoding/json"
	"path"
	"regexp"
	"strings"
)

//go:embed probepaths.json
var probePathsJSON []byte

// ProbePathsJSON is the raw embedded list, for consumers that pin a byte
// copy and check its hash.
func ProbePathsJSON() []byte { return append([]byte(nil), probePathsJSON...) }

// ProbePath is one well-known location.
type ProbePath struct {
	Path       string   `json:"path"`
	Serves     string   `json:"serves"`
	Frameworks []string `json:"frameworks"`
}

type probeFile struct {
	Version string      `json:"version"`
	Paths   []ProbePath `json:"paths"`
	UIPaths []ProbePath `json:"uiPaths"`
}

var probes = func() probeFile {
	var f probeFile
	if err := json.Unmarshal(probePathsJSON, &f); err != nil {
		panic("detect: probepaths.json: " + err.Error())
	}
	return f
}()

// ProbePaths lists the paths that serve a machine-readable description.
func ProbePaths() []ProbePath { return append([]ProbePath(nil), probes.Paths...) }

// UIPaths lists documentation UIs and query endpoints. They are not specs,
// but one answering on a public host is an exposed debug surface.
func UIPaths() []ProbePath { return append([]ProbePath(nil), probes.UIPaths...) }

var specName = regexp.MustCompile(`(?i)^(openapi|swagger|api[-_.]?spec|api[-_.]?docs?|oas)([-_.][\w.-]*)?\.(json|ya?ml)$|\.(openapi|oas|swagger)\.(json|ya?ml)$`)

// skipDirs are never walked for specs: vendored and generated trees hold
// other projects' descriptions.
var skipDirs = map[string]bool{
	"node_modules": true, "vendor": true, ".git": true, "dist": true, "build": true,
	"target": true, ".venv": true, "venv": true, "__pycache__": true, ".terraform": true,
}

// SkipDir reports a directory a spec walk should not enter.
func SkipDir(name string) bool { return skipDirs[name] }

// LikelySpecName reports a file name that is usually a spec. A file with
// another name can still be one; callers that can afford it also sniff
// every .json and .yaml under a size cap.
func LikelySpecName(p string) bool {
	return specName.MatchString(path.Base(p))
}

// MaybeSpecFile reports an extension worth sniffing.
func MaybeSpecFile(p string) bool {
	switch strings.ToLower(path.Ext(p)) {
	case ".json", ".yaml", ".yml":
		return true
	}
	return false
}

// Generator is code that produces a spec at runtime rather than a file in
// the repository.
type Generator struct {
	Framework string `json:"framework"`
	Language  string `json:"language"`
	// ServesAt is where the running service usually exposes the spec.
	ServesAt []string `json:"servesAt"`
}

type generatorRule struct {
	g       Generator
	markers []string
}

// generatorRules match dependency names or imports. They are evidence a
// service can describe itself, which is why liveness and discovery probe
// its ServesAt paths.
var generatorRules = []generatorRule{
	{Generator{"fastapi", "python", []string{"/openapi.json"}}, []string{"fastapi"}},
	{Generator{"drf-spectacular", "python", []string{"/api/schema/"}}, []string{"drf-spectacular", "drf_spectacular"}},
	{Generator{"flask-smorest", "python", []string{"/openapi.json"}}, []string{"flask-smorest", "flask_smorest"}},
	{Generator{"litestar", "python", []string{"/schema/openapi.json"}}, []string{"litestar"}},
	{Generator{"springdoc", "java", []string{"/v3/api-docs"}}, []string{"springdoc-openapi", "org.springdoc"}},
	{Generator{"springfox", "java", []string{"/v2/api-docs"}}, []string{"springfox"}},
	{Generator{"quarkus", "java", []string{"/q/openapi"}}, []string{"quarkus-smallrye-openapi"}},
	{Generator{"swashbuckle", "csharp", []string{"/swagger/v1/swagger.json"}}, []string{"Swashbuckle.AspNetCore"}},
	{Generator{"aspnetcore", "csharp", []string{"/openapi/v1.json"}}, []string{"Microsoft.AspNetCore.OpenApi"}},
	{Generator{"nestjs", "typescript", []string{"/api-docs-json", "/openapi.json"}}, []string{"@nestjs/swagger"}},
	{Generator{"tsoa", "typescript", nil}, []string{"tsoa"}},
	{Generator{"swagger-jsdoc", "javascript", []string{"/api-docs"}}, []string{"swagger-jsdoc"}},
	{Generator{"fastify-swagger", "javascript", []string{"/documentation/json"}}, []string{"@fastify/swagger", "fastify-swagger"}},
	{Generator{"swag", "go", []string{"/swagger/doc.json"}}, []string{"github.com/swaggo/swag"}},
	{Generator{"huma", "go", []string{"/openapi.json"}}, []string{"github.com/danielgtaylor/huma"}},
	{Generator{"goa", "go", []string{"/openapi.json"}}, []string{"goa.design/goa"}},
	{Generator{"grpc-gateway", "go", nil}, []string{"protoc-gen-openapiv2"}},
}

// Generators returns the generators a dependency or import name points at.
func Generators(name string) []Generator {
	n := strings.ToLower(strings.TrimSpace(name))
	var out []Generator
	for _, r := range generatorRules {
		for _, m := range r.markers {
			lm := strings.ToLower(m)
			if n == lm || strings.HasPrefix(n, lm+"/") || strings.HasPrefix(n, lm+"@") {
				out = append(out, r.g)
				break
			}
		}
	}
	return out
}
