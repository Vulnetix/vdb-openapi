// Package contract publishes the JSON Schema of oas.Document, for
// consumers in other languages (the website's TypeScript wire types, the
// Guardian Worker). The schema is generated from the Go types by
// Generate; contract.schema.json is the committed output and a test keeps
// the two equal.
package contract

import (
	_ "embed"
	"encoding/json"
	"reflect"
	"sort"
	"strings"

	"github.com/Vulnetix/vdb-openapi/oas"
)

//go:embed contract.schema.json
var schemaJSON []byte

// Schema returns the committed JSON Schema.
func Schema() []byte { return append([]byte(nil), schemaJSON...) }

// Generate builds the JSON Schema from the oas types.
func Generate() []byte {
	g := &gen{defs: map[string]any{}}
	root := g.ref(reflect.TypeOf(oas.Document{}))
	out := map[string]any{
		"$schema":     "https://json-schema.org/draft/2020-12/schema",
		"$id":         "https://github.com/Vulnetix/vdb-openapi/contract/contract.schema.json",
		"title":       "Vulnetix API description contract " + oas.ContractVersion,
		"description": "Every Swagger 2.0, OpenAPI 3.0 and OpenAPI 3.1 document reads as this shape. Generated from package oas; do not edit by hand.",
		"$ref":        root["$ref"],
		"$defs":       g.defs,
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

type gen struct {
	defs map[string]any
}

func (g *gen) ref(t reflect.Type) map[string]any {
	name := t.Name()
	if _, ok := g.defs[name]; !ok {
		g.defs[name] = nil // reserve, so recursive types stop here
		g.defs[name] = g.object(t)
	}
	return map[string]any{"$ref": "#/$defs/" + name}
}

func (g *gen) object(t reflect.Type) map[string]any {
	props := map[string]any{}
	var required []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		if tag == "-" || !f.IsExported() {
			continue
		}
		parts := strings.Split(tag, ",")
		name := parts[0]
		if name == "" {
			name = f.Name
		}
		omit := len(parts) > 1 && parts[1] == "omitempty"
		props[name] = g.typ(f.Type, !omit)
		if !omit {
			required = append(required, name)
		}
	}
	sort.Strings(required)
	o := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		o["required"] = required
	}
	return o
}

// typ maps a Go type. A pointer that is always written (no omitempty) may
// be null.
func (g *gen) typ(t reflect.Type, always bool) map[string]any {
	switch t.Kind() {
	case reflect.Pointer:
		inner := g.typ(t.Elem(), false)
		if always {
			return map[string]any{"anyOf": []any{inner, map[string]any{"type": "null"}}}
		}
		return inner
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int64, reflect.Int32:
		return map[string]any{"type": "integer"}
	case reflect.Float64, reflect.Float32:
		return map[string]any{"type": "number"}
	case reflect.Slice:
		return map[string]any{"type": "array", "items": g.typ(t.Elem(), false)}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": g.typ(t.Elem(), false)}
	case reflect.Struct:
		return g.ref(t)
	}
	panic("contract: unsupported type " + t.String())
}
