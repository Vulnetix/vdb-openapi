// Package tree parses a JSON or YAML document into plain Go values
// (map[string]any, []any, string, float64, bool, nil) under hard caps, and
// resolves $ref pointers within and across documents.
//
// The caps are the reason this package exists instead of a bare
// yaml.Unmarshal: a hostile document can expand a few kilobytes of YAML
// aliases into gigabytes, or nest until the stack runs out. Every service
// that reads a customer's spec reads it through here.
package tree

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Limits bound the work one document may cause.
type Limits struct {
	MaxBytes int
	// MaxNodes counts every value visited, alias expansions included.
	MaxNodes int
	MaxDepth int
}

// DefaultLimits suit a large real-world spec (the GitHub REST description
// is about 11 MB of YAML) with headroom, and stop alias bombs early.
var DefaultLimits = Limits{MaxBytes: 32 << 20, MaxNodes: 4_000_000, MaxDepth: 256}

var (
	ErrTooLarge = errors.New("document exceeds the size limit")
	ErrTooMany  = errors.New("document expands past the node limit")
	ErrTooDeep  = errors.New("document nests past the depth limit")
)

// Parse reads data as JSON when it starts with "{" or "[", otherwise as
// YAML. It returns the root value and the encoding used.
func Parse(data []byte, lim Limits) (any, string, error) {
	if lim.MaxBytes > 0 && len(data) > lim.MaxBytes {
		return nil, "", ErrTooLarge
	}
	trimmed := bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	trimmed = bytes.TrimLeft(trimmed, " \t\r\n")
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		v, err := parseJSON(trimmed, lim)
		if err == nil {
			return v, "json", nil
		}
		if errors.Is(err, ErrTooMany) || errors.Is(err, ErrTooDeep) {
			return nil, "", err
		}
		// Fall through: flow-style YAML also starts with "{".
	}
	v, err := parseYAML(data, lim)
	if err != nil {
		return nil, "", err
	}
	return v, "yaml", nil
}

func parseJSON(data []byte, lim Limits) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var raw any
	if err := dec.Decode(&raw); err != nil {
		return nil, err
	}
	c := &counter{lim: lim}
	return c.fromJSON(raw, 0)
}

type counter struct {
	lim   Limits
	nodes int
}

func (c *counter) visit(depth int) error {
	c.nodes++
	if c.lim.MaxNodes > 0 && c.nodes > c.lim.MaxNodes {
		return ErrTooMany
	}
	if c.lim.MaxDepth > 0 && depth > c.lim.MaxDepth {
		return ErrTooDeep
	}
	return nil
}

func (c *counter) fromJSON(v any, depth int) (any, error) {
	if err := c.visit(depth); err != nil {
		return nil, err
	}
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			n, err := c.fromJSON(e, depth+1)
			if err != nil {
				return nil, err
			}
			t[k] = n
		}
		return t, nil
	case []any:
		for i, e := range t {
			n, err := c.fromJSON(e, depth+1)
			if err != nil {
				return nil, err
			}
			t[i] = n
		}
		return t, nil
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			return t.String(), nil
		}
		return f, nil
	default:
		return t, nil
	}
}

func parseYAML(data []byte, lim Limits) (any, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	c := &counter{lim: lim}
	return c.fromYAML(&root, 0)
}

func (c *counter) fromYAML(n *yaml.Node, depth int) (any, error) {
	if err := c.visit(depth); err != nil {
		return nil, err
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return nil, nil
		}
		return c.fromYAML(n.Content[0], depth+1)
	case yaml.AliasNode:
		if n.Alias == nil {
			return nil, nil
		}
		return c.fromYAML(n.Alias, depth+1)
	case yaml.MappingNode:
		out := make(map[string]any, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Tag == "!!merge" {
				merged, err := c.fromYAML(v, depth+1)
				if err != nil {
					return nil, err
				}
				if mm, ok := merged.(map[string]any); ok {
					for mk, mv := range mm {
						if _, set := out[mk]; !set {
							out[mk] = mv
						}
					}
				}
				continue
			}
			val, err := c.fromYAML(v, depth+1)
			if err != nil {
				return nil, err
			}
			out[k.Value] = val
		}
		return out, nil
	case yaml.SequenceNode:
		out := make([]any, 0, len(n.Content))
		for _, e := range n.Content {
			v, err := c.fromYAML(e, depth+1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case yaml.ScalarNode:
		return scalar(n), nil
	}
	return nil, nil
}

func scalar(n *yaml.Node) any {
	switch n.ShortTag() {
	case "!!null":
		return nil
	case "!!bool":
		b, err := strconv.ParseBool(strings.ToLower(n.Value))
		if err != nil {
			return n.Value
		}
		return b
	case "!!int", "!!float":
		f, err := strconv.ParseFloat(strings.ReplaceAll(n.Value, "_", ""), 64)
		if err != nil {
			// 0x, 0o and .inf forms: keep the text rather than guess.
			return n.Value
		}
		return f
	default:
		return n.Value
	}
}

// Pointer walks a JSON pointer ("/components/schemas/Pet") from root.
func Pointer(root any, ptr string) (any, error) {
	if ptr == "" || ptr == "/" {
		return root, nil
	}
	if !strings.HasPrefix(ptr, "/") {
		return nil, fmt.Errorf("pointer %q does not start with /", ptr)
	}
	cur := root
	for _, raw := range strings.Split(ptr[1:], "/") {
		tok := strings.ReplaceAll(strings.ReplaceAll(unescapePercent(raw), "~1", "/"), "~0", "~")
		switch t := cur.(type) {
		case map[string]any:
			v, ok := t[tok]
			if !ok {
				return nil, fmt.Errorf("pointer %q: %q not found", ptr, tok)
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(t) {
				return nil, fmt.Errorf("pointer %q: bad index %q", ptr, tok)
			}
			cur = t[i]
		default:
			return nil, fmt.Errorf("pointer %q: cannot descend into a scalar", ptr)
		}
	}
	return cur, nil
}

func unescapePercent(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(v))
				i += 2
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Escape escapes one token for a JSON pointer.
func Escape(tok string) string {
	return strings.ReplaceAll(strings.ReplaceAll(tok, "~", "~0"), "/", "~1")
}
