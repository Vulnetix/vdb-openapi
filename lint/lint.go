// Package lint runs a small set of structural checks over a contract
// Document. These are the problems that break correlation or testing (an
// operation nobody can name, a path parameter with no definition), not a
// style guide.
package lint

import (
	"regexp"
	"sort"

	"github.com/Vulnetix/vdb-openapi/oas"
)

// Finding is one problem on one operation (Key) or the document (Key "").
type Finding struct {
	Rule     string `json:"rule"`
	Key      string `json:"key,omitempty"`
	Message  string `json:"message"`
	Severity string `json:"severity"`
}

// Summary counts findings by severity.
type Summary struct {
	Errors   int       `json:"errors"`
	Warnings int       `json:"warnings"`
	Findings []Finding `json:"findings"`
}

var templateParam = regexp.MustCompile(`\{([^}]+)\}`)

// Check runs every rule.
func Check(d *oas.Document) Summary {
	var out []Finding
	add := func(rule, key, sev, msg string) {
		out = append(out, Finding{Rule: rule, Key: key, Message: msg, Severity: sev})
	}

	if len(d.Servers) == 0 {
		add("no-servers", "", "warning", "no servers declared, so live requests cannot be matched to a host")
	}
	ids := map[string]string{}
	for _, o := range d.Operations {
		if o.OperationID == "" {
			add("operation-id", o.Key, "warning", "operation has no operationId")
		} else if prev, dup := ids[o.OperationID]; dup {
			add("duplicate-operation-id", o.Key, "error", "operationId "+o.OperationID+" is also used by "+prev)
		} else {
			ids[o.OperationID] = o.Key
		}

		declared := map[string]bool{}
		for _, p := range o.Parameters {
			if p.In == oas.InPath {
				declared[p.Name] = true
			}
		}
		inTemplate := map[string]bool{}
		for _, m := range templateParam.FindAllStringSubmatch(o.PathTemplate, -1) {
			inTemplate[m[1]] = true
			if !declared[m[1]] {
				add("path-parameter-undeclared", o.Key, "error", "path parameter {"+m[1]+"} is not declared")
			}
		}
		for name := range declared {
			if !inTemplate[name] {
				add("path-parameter-unused", o.Key, "warning", "path parameter "+name+" is declared but not in the path")
			}
		}
		if len(o.Responses) == 0 {
			add("no-responses", o.Key, "error", "operation declares no responses")
		}
		for _, s := range o.Security.Alternatives {
			for _, u := range s {
				if _, ok := d.SecuritySchemes[u.Scheme]; !ok {
					add("unknown-security-scheme", o.Key, "error", "security scheme "+u.Scheme+" is not defined")
				}
			}
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		return out[i].Rule < out[j].Rule
	})
	s := Summary{Findings: out}
	if s.Findings == nil {
		s.Findings = []Finding{}
	}
	for _, f := range out {
		switch f.Severity {
		case "error":
			s.Errors++
		case "warning":
			s.Warnings++
		}
	}
	return s
}
