package route_test

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/Vulnetix/vdb-openapi/route"
)

func TestKeyCases(t *testing.T) {
	var file struct {
		Cases []struct {
			Method, Path, Key  string
			Noise, Identifying bool
		}
	}
	read(t, "../testdata/route/key-cases.json", &file)
	for _, c := range file.Cases {
		if got := route.Key(c.Method, c.Path); got != c.Key {
			t.Errorf("Key(%q, %q) = %q, want %q", c.Method, c.Path, got, c.Key)
		}
		if got := route.IsNoise(c.Path); got != c.Noise {
			t.Errorf("IsNoise(%q) = %v, want %v", c.Path, got, c.Noise)
		}
		if got := route.Identifying(route.Path(c.Path)); got != c.Identifying {
			t.Errorf("Identifying(%q) = %v, want %v", c.Path, got, c.Identifying)
		}
	}
}

func TestMatcherCases(t *testing.T) {
	var file struct {
		Templates []route.Template
		Cases     []struct {
			Method, Path string
			Key          *string
		}
	}
	read(t, "../testdata/route/matcher-cases.json", &file)
	m := route.Compile(file.Templates)
	for _, c := range file.Cases {
		got, ok := m.Match(c.Method, c.Path)
		switch {
		case c.Key == nil && ok:
			t.Errorf("Match(%s %s) = %q, want no match", c.Method, c.Path, got.Key)
		case c.Key != nil && !ok:
			t.Errorf("Match(%s %s) = no match, want %q", c.Method, c.Path, *c.Key)
		case c.Key != nil && got.Key != *c.Key:
			t.Errorf("Match(%s %s) = %q, want %q", c.Method, c.Path, got.Key, *c.Key)
		}
	}
}

// The serialised set must rebuild the same matcher, so a consumer that
// receives it over the wire gets the same answers.
func TestMatcherSetRoundTrip(t *testing.T) {
	var file struct {
		Templates []route.Template
		Cases     []struct {
			Method, Path string
			Key          *string
		}
	}
	read(t, "../testdata/route/matcher-cases.json", &file)
	m := route.Compile(file.Templates)
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var set route.Set
	if err := json.Unmarshal(data, &set); err != nil {
		t.Fatal(err)
	}
	if set.Version != route.MatcherVersion {
		t.Fatalf("version %q", set.Version)
	}
	again := route.Compile(set.Templates)
	for _, c := range file.Cases {
		a, aok := m.Match(c.Method, c.Path)
		b, bok := again.Match(c.Method, c.Path)
		if a != b || aok != bok {
			t.Errorf("%s %s: round trip changed the answer", c.Method, c.Path)
		}
	}
}

func TestJoin(t *testing.T) {
	cases := [][3]string{
		{"/v1", "/pets", "/v1/pets"},
		{"/v1/", "/pets", "/v1/pets"},
		{"", "/pets", "/pets"},
		{"v1", "/pets", "/v1/pets"},
		{"/v1", "/", "/v1"},
	}
	for _, c := range cases {
		if got := route.Join(c[0], c[1]); got != c[2] {
			t.Errorf("Join(%q, %q) = %q, want %q", c[0], c[1], got, c[2])
		}
	}
}

func read(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}
