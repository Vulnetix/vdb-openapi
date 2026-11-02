package convert

import (
	"sort"

	"github.com/Vulnetix/vdb-openapi/internal/tree"
	"github.com/Vulnetix/vdb-openapi/oas"
)

const (
	maxProperties = 200
	maxVariants   = 20
	maxEnum       = 50
)

// unsupported keywords are JSON Schema features the summary cannot hold.
// Each becomes a Loss, so a consumer knows the constraint exists.
var unsupported = []string{
	"not", "if", "then", "else", "dependentSchemas", "dependentRequired",
	"patternProperties", "unevaluatedProperties", "unevaluatedItems",
	"prefixItems", "contains", "propertyNames", "$dynamicRef",
}

// schema summarises the schema at v. stack holds the refs being expanded,
// so a self-referencing schema stops instead of looping.
func (c *conv) schema(d *tree.Doc, v any, ptr string, depth int, stack map[string]bool) oas.SchemaSummary {
	m := obj(v)
	if m == nil {
		return oas.SchemaSummary{}
	}
	if ref, ok := m["$ref"].(string); ok {
		_, td, tptr, err := c.refs.Resolve(d, ref)
		key := ref
		if err == nil {
			key = td.Location + "#" + tptr
		}
		if stack[key] {
			_, _, _, name, _ := c.deref(d, m, ptr)
			return oas.SchemaSummary{Name: name, Recursive: true}
		}
		target, td2, tptr2, name, ok := c.deref(d, m, ptr)
		if !ok {
			return oas.SchemaSummary{}
		}
		stack[key] = true
		s := c.schema(td2, target, tptr2, depth, stack)
		delete(stack, key)
		s.Name = name
		return s
	}
	if depth > maxSchemaDepth {
		s := oas.SchemaSummary{Truncated: true}
		c.types(m, &s)
		return s
	}

	s := oas.SchemaSummary{}
	c.types(m, &s)
	if f := text(m["format"]); f != "" {
		s.Format = f
	}
	c.enum(m, &s)

	s.MinLength = intPtr(m["minLength"])
	s.MaxLength = intPtr(m["maxLength"])
	s.Pattern = text(m["pattern"])

	s.Minimum = floatPtr(m["minimum"])
	s.Maximum = floatPtr(m["maximum"])
	c.exclusive(m, &s)
	s.MultipleOf = floatPtr(m["multipleOf"])

	s.MinItems = intPtr(m["minItems"])
	s.MaxItems = intPtr(m["maxItems"])
	s.UniqueItems = boolean(m["uniqueItems"])
	if it, ok := m["items"]; ok {
		if im := obj(it); im != nil {
			sub := c.schema(d, im, ptr+"/items", depth+1, stack)
			s.Items = &sub
		}
	}

	c.properties(d, m, ptr, depth, stack, &s)
	s.MaxProperties = intPtr(m["maxProperties"])

	s.ContentMediaType = text(m["contentMediaType"])
	s.ContentEncoding = text(m["contentEncoding"])
	s.ReadOnly = boolean(m["readOnly"])
	s.WriteOnly = boolean(m["writeOnly"])
	c.binary(&s)

	for _, kw := range []string{"oneOf", "anyOf"} {
		for i, b := range arr(m[kw]) {
			if len(s.Variants) >= maxVariants {
				s.Truncated = true
				break
			}
			s.Variants = append(s.Variants, c.schema(d, b, ptr+"/"+kw+"/"+itoa(i), depth+1, stack))
		}
	}
	for i, b := range arr(m["allOf"]) {
		merge(&s, c.schema(d, b, ptr+"/allOf/"+itoa(i), depth, stack))
	}

	for _, kw := range unsupported {
		if _, ok := m[kw]; ok {
			if c.v == v20 && kw != "not" {
				continue
			}
			c.loss(at(d, ptr+"/"+kw), kw, "JSON Schema keyword not carried into the summary")
		}
	}
	return s
}

// types reads type, nullable (3.0) and x-nullable (2.0). A 3.1 type list
// that includes "null" sets Nullable, the same as 3.0's nullable: true.
func (c *conv) types(m map[string]any, s *oas.SchemaSummary) {
	var ts []string
	switch t := m["type"].(type) {
	case string:
		ts = []string{t}
	case []any:
		for _, e := range t {
			if x := text(e); x != "" {
				ts = append(ts, x)
			}
		}
	}
	var nonNull []string
	for _, t := range ts {
		if t == "null" {
			s.Nullable = true
			continue
		}
		if t == "file" {
			// Swagger 2.0 only.
			t = "string"
			if text(m["format"]) == "" {
				s.Format = "binary"
			}
		}
		nonNull = append(nonNull, t)
	}
	switch len(nonNull) {
	case 0:
	case 1:
		s.Type = nonNull[0]
	default:
		sort.Strings(nonNull)
		s.Types = nonNull
	}
	if boolean(m["nullable"]) || boolean(m["x-nullable"]) {
		s.Nullable = true
	}
}

func (c *conv) enum(m map[string]any, s *oas.SchemaSummary) {
	vals := arr(m["enum"])
	if cv, ok := m["const"]; ok {
		vals = []any{cv}
	}
	if len(vals) == 0 {
		return
	}
	for _, e := range vals {
		if e == nil {
			s.Nullable = true
			continue
		}
		s.EnumCount++
		if len(s.Enum) < maxEnum {
			s.Enum = append(s.Enum, clip(text(e), 200))
		}
	}
}

// exclusive reads exclusiveMinimum/Maximum, a boolean modifier in 2.0 and
// 3.0 and a number of its own in 3.1. Both become a bound plus a flag.
func (c *conv) exclusive(m map[string]any, s *oas.SchemaSummary) {
	apply := func(key string, bound **float64, flag *bool, lower bool) {
		switch t := m[key].(type) {
		case bool:
			*flag = t && *bound != nil
		case float64:
			// The stricter of minimum and exclusiveMinimum wins.
			if *bound == nil || (lower && t >= **bound) || (!lower && t <= **bound) {
				v := t
				*bound = &v
				*flag = true
			}
		}
	}
	apply("exclusiveMinimum", &s.Minimum, &s.ExclusiveMinimum, true)
	apply("exclusiveMaximum", &s.Maximum, &s.ExclusiveMaximum, false)
}

func (c *conv) properties(d *tree.Doc, m map[string]any, ptr string, depth int, stack map[string]bool, s *oas.SchemaSummary) {
	props := obj(m["properties"])
	if len(props) > 0 {
		s.Properties = map[string]oas.SchemaSummary{}
		for i, name := range sortedKeys(props) {
			if i >= maxProperties {
				s.Truncated = true
				break
			}
			s.Properties[name] = c.schema(d, props[name], ptr+"/properties/"+tree.Escape(name), depth+1, stack)
		}
	}
	for _, r := range arr(m["required"]) {
		if n := text(r); n != "" {
			s.Required = append(s.Required, n)
		}
	}
	sort.Strings(s.Required)
	switch ap := m["additionalProperties"].(type) {
	case bool:
		s.AdditionalProperties = boolPtr(ap)
	case map[string]any:
		s.AdditionalProperties = boolPtr(true)
	}
}

// binary settles the three ways a file or encoded string is written, so
// every version reads the same: 2.0 type file, 3.0 format binary/byte, and
// 3.1 contentMediaType/contentEncoding.
func (c *conv) binary(s *oas.SchemaSummary) {
	if s.Type != "string" {
		return
	}
	switch {
	case s.Format == "binary" && s.ContentMediaType == "":
		s.ContentMediaType = "application/octet-stream"
	case s.Format == "byte" && s.ContentEncoding == "":
		s.ContentEncoding = "base64"
	case s.Format == "" && s.ContentEncoding == "base64":
		s.Format = "byte"
	case s.Format == "" && s.ContentMediaType != "":
		s.Format = "binary"
	}
}

// merge folds an allOf branch into s. A limit already set on s stays; an
// unset one is taken from the branch.
func merge(s *oas.SchemaSummary, b oas.SchemaSummary) {
	if s.Type == "" && len(s.Types) == 0 {
		s.Type, s.Types = b.Type, b.Types
	}
	if s.Format == "" {
		s.Format = b.Format
	}
	s.Nullable = s.Nullable || b.Nullable
	if len(s.Enum) == 0 {
		s.Enum, s.EnumCount = b.Enum, b.EnumCount
	}
	if s.MinLength == nil {
		s.MinLength = b.MinLength
	}
	if s.MaxLength == nil {
		s.MaxLength = b.MaxLength
	}
	if s.Pattern == "" {
		s.Pattern = b.Pattern
	}
	if s.Minimum == nil {
		s.Minimum, s.ExclusiveMinimum = b.Minimum, b.ExclusiveMinimum
	}
	if s.Maximum == nil {
		s.Maximum, s.ExclusiveMaximum = b.Maximum, b.ExclusiveMaximum
	}
	if s.MultipleOf == nil {
		s.MultipleOf = b.MultipleOf
	}
	if s.MinItems == nil {
		s.MinItems = b.MinItems
	}
	if s.MaxItems == nil {
		s.MaxItems = b.MaxItems
	}
	s.UniqueItems = s.UniqueItems || b.UniqueItems
	if s.Items == nil {
		s.Items = b.Items
	}
	if len(b.Properties) > 0 {
		if s.Properties == nil {
			s.Properties = map[string]oas.SchemaSummary{}
		}
		for k, v := range b.Properties {
			if _, ok := s.Properties[k]; !ok {
				s.Properties[k] = v
			}
		}
	}
	if len(b.Required) > 0 {
		set := map[string]bool{}
		for _, r := range s.Required {
			set[r] = true
		}
		for _, r := range b.Required {
			if !set[r] {
				s.Required = append(s.Required, r)
			}
		}
		sort.Strings(s.Required)
	}
	switch {
	case b.AdditionalProperties != nil && !*b.AdditionalProperties:
		s.AdditionalProperties = boolPtr(false)
	case s.AdditionalProperties == nil:
		s.AdditionalProperties = b.AdditionalProperties
	}
	if s.MaxProperties == nil {
		s.MaxProperties = b.MaxProperties
	}
	s.Variants = append(s.Variants, b.Variants...)
	if s.ContentMediaType == "" {
		s.ContentMediaType = b.ContentMediaType
	}
	if s.ContentEncoding == "" {
		s.ContentEncoding = b.ContentEncoding
	}
	s.ReadOnly = s.ReadOnly || b.ReadOnly
	s.WriteOnly = s.WriteOnly || b.WriteOnly
	s.Recursive = s.Recursive || b.Recursive
	s.Truncated = s.Truncated || b.Truncated
}

func itoa(i int) string {
	return text(float64(i))
}
