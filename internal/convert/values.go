package convert

import (
	"encoding/json"
	"sort"
	"strconv"
	"strings"
)

func obj(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func arr(v any) []any {
	a, _ := v.([]any)
	return a
}

func text(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

func boolean(v any) bool {
	b, _ := v.(bool)
	return b
}

func number(v any) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}

func intPtr(v any) *int {
	f, ok := number(v)
	if !ok || f < 0 {
		return nil
	}
	i := int(f)
	return &i
}

func floatPtr(v any) *float64 {
	f, ok := number(v)
	if !ok {
		return nil
	}
	return &f
}

func boolPtr(b bool) *bool { return &b }

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary.
	for n > 0 && !utf8Start(s[n]) {
		n--
	}
	return s[:n]
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

// extensionAllow lists the x- keys the contract keeps. Most extensions are
// tool configuration; these few say something about exposure.
var extensionAllow = map[string]bool{
	"x-internal": true, "x-public": true, "x-audience": true, "x-visibility": true,
	"x-rate-limit": true, "x-ratelimit-limit": true, "x-throttling-tier": true,
	"x-amazon-apigateway-auth": true, "x-google-backend": true, "x-api-status": true,
}

func extensions(m map[string]any) map[string]string {
	var out map[string]string
	for k, v := range m {
		lk := strings.ToLower(k)
		if !extensionAllow[lk] {
			continue
		}
		if out == nil {
			out = map[string]string{}
		}
		out[lk] = clip(text(v), 200)
	}
	return out
}
