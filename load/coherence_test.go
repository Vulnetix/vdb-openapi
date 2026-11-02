package load_test

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/Vulnetix/vdb-openapi/load"
	"github.com/Vulnetix/vdb-openapi/oas"
)

var update = flag.Bool("update", false, "rewrite golden files")

// TestCoherence is the module's main promise: the same API written as
// Swagger 2.0, OpenAPI 3.0 and OpenAPI 3.1 reads as the same contract,
// byte for byte, once Source (which names the input) is set aside.
func TestCoherence(t *testing.T) {
	inputs := []string{"petstore.swagger2.yaml", "petstore.oas30.yaml", "petstore.oas31.json"}
	var first []byte
	for _, name := range inputs {
		got := contractJSON(t, filepath.Join("..", "testdata", "coherence", name))
		if first == nil {
			first = got
			golden := filepath.Join("..", "testdata", "coherence", "petstore.contract.json")
			if *update {
				if err := os.WriteFile(golden, got, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("read golden (run with -update to create it): %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("%s differs from the golden contract; run go test ./load -update and review the diff", name)
			}
			continue
		}
		if !bytes.Equal(got, first) {
			t.Errorf("%s reads differently from %s:\n%s", name, inputs[0], firstDiff(first, got))
		}
	}
}

func contractJSON(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := load.Load(data, load.Options{})
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	doc.Source = oas.Source{}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

func firstDiff(a, b []byte) string {
	al, bl := bytes.Split(a, []byte("\n")), bytes.Split(b, []byte("\n"))
	for i := 0; i < len(al) && i < len(bl); i++ {
		if !bytes.Equal(al[i], bl[i]) {
			lo := i - 3
			if lo < 0 {
				lo = 0
			}
			var buf bytes.Buffer
			for j := lo; j <= i && j < len(al); j++ {
				buf.WriteString("  " + string(al[j]) + "\n")
			}
			buf.WriteString("- " + string(al[i]) + "\n+ " + string(bl[i]) + "\n")
			return buf.String()
		}
	}
	return "lengths differ"
}
