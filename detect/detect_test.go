package detect_test

import (
	"strings"
	"testing"

	"github.com/Vulnetix/vdb-openapi/detect"
)

func TestLikelySpecName(t *testing.T) {
	yes := []string{"openapi.yaml", "api/openapi.json", "swagger.yml", "openapi-v2.yaml", "petstore.openapi.json", "api-spec.yaml", "OpenAPI.YAML", "oas.json"}
	no := []string{"package.json", "docker-compose.yml", "openapi.go", "values.yaml", "tsconfig.json"}
	for _, n := range yes {
		if !detect.LikelySpecName(n) {
			t.Errorf("%s not recognised", n)
		}
	}
	for _, n := range no {
		if detect.LikelySpecName(n) {
			t.Errorf("%s wrongly recognised", n)
		}
	}
}

func TestProbePaths(t *testing.T) {
	ps := detect.ProbePaths()
	if len(ps) < 10 {
		t.Fatalf("only %d probe paths", len(ps))
	}
	seen := map[string]bool{}
	for _, p := range append(ps, detect.UIPaths()...) {
		if !strings.HasPrefix(p.Path, "/") {
			t.Errorf("%q does not start with /", p.Path)
		}
		if seen[p.Path] {
			t.Errorf("%q listed twice", p.Path)
		}
		seen[p.Path] = true
	}
}

func TestGenerators(t *testing.T) {
	cases := map[string]string{
		"fastapi":                   "fastapi",
		"org.springdoc":             "springdoc",
		"@nestjs/swagger":           "nestjs",
		"github.com/swaggo/swag":    "swag",
		"github.com/swaggo/swag/v2": "swag",
		"Swashbuckle.AspNetCore":    "swashbuckle",
	}
	for dep, want := range cases {
		g := detect.Generators(dep)
		if len(g) == 0 || g[0].Framework != want {
			t.Errorf("Generators(%q) = %+v, want %s", dep, g, want)
		}
	}
	if g := detect.Generators("fastapi-utils"); len(g) != 0 {
		t.Errorf("fastapi-utils matched %+v", g)
	}
}
