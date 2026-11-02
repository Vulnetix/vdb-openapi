// Package diff compares two versions of one API in contract form. It is
// what turns "a new spec was uploaded" into "DELETE /pets/{param} lost its
// authentication" or "a required query parameter was added".
//
// Operations are matched on Key (method plus normalised path), so renaming
// a path parameter is not a change, and changing a path is a removal plus
// an addition.
package diff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Vulnetix/vdb-openapi/oas"
)

// Kind names one change.
type Kind string

const (
	OperationAdded       Kind = "operation_added"
	OperationRemoved     Kind = "operation_removed"
	OperationDeprecated  Kind = "operation_deprecated"
	SecurityRemoved      Kind = "security_removed"
	SecurityWeakened     Kind = "security_weakened"
	SecurityAdded        Kind = "security_added"
	ParameterAdded       Kind = "parameter_added"
	ParameterRemoved     Kind = "parameter_removed"
	ParameterRequired    Kind = "parameter_now_required"
	ParameterTypeChanged Kind = "parameter_type_changed"
	BodyAdded            Kind = "request_body_added"
	BodyRemoved          Kind = "request_body_removed"
	BodyRequired         Kind = "request_body_now_required"
	ContentTypeRemoved   Kind = "content_type_removed"
	ResponseRemoved      Kind = "response_removed"
	ResponseAdded        Kind = "response_added"
	ServerRemoved        Kind = "server_removed"
	ServerAdded          Kind = "server_added"
)

// Change is one difference. Breaking means a client written against the
// old version can fail against the new one. SecurityRegression means the
// new version asks less of a caller than the old one did.
type Change struct {
	Kind               Kind   `json:"kind"`
	Key                string `json:"key,omitempty"`
	Detail             string `json:"detail"`
	Breaking           bool   `json:"breaking"`
	SecurityRegression bool   `json:"securityRegression"`
}

// Result is every change, in a stable order, with counts for a summary.
type Result struct {
	Changes             []Change `json:"changes"`
	Added               int      `json:"added"`
	Removed             int      `json:"removed"`
	Breaking            int      `json:"breaking"`
	SecurityRegressions int      `json:"securityRegressions"`
}

// strength orders security states: a move to a lower one is a regression.
var strength = map[oas.SecurityState]int{
	oas.SecurityNone: 0, oas.SecurityOptional: 1, oas.SecurityUnspecified: 1, oas.SecurityRequired: 2,
}

// Compare lists the changes from old to cur.
func Compare(old, cur *oas.Document) Result {
	var out []Change
	add := func(c Change) { out = append(out, c) }

	oldOps, curOps := index(old), index(cur)
	for _, k := range keys(oldOps) {
		if _, ok := curOps[k]; !ok {
			add(Change{Kind: OperationRemoved, Key: k, Detail: "operation removed", Breaking: true})
		}
	}
	for _, k := range keys(curOps) {
		o, ok := oldOps[k]
		if !ok {
			add(Change{Kind: OperationAdded, Key: k, Detail: "operation added"})
			continue
		}
		operation(k, o, curOps[k], add)
	}
	servers(old, cur, add)

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Key != out[j].Key {
			return out[i].Key < out[j].Key
		}
		return out[i].Kind < out[j].Kind
	})
	r := Result{Changes: out}
	if r.Changes == nil {
		r.Changes = []Change{}
	}
	for _, c := range out {
		switch c.Kind {
		case OperationAdded:
			r.Added++
		case OperationRemoved:
			r.Removed++
		}
		if c.Breaking {
			r.Breaking++
		}
		if c.SecurityRegression {
			r.SecurityRegressions++
		}
	}
	return r
}

func index(d *oas.Document) map[string]oas.Operation {
	m := map[string]oas.Operation{}
	if d == nil {
		return m
	}
	for _, o := range d.Operations {
		if o.Key != "" {
			m[o.Key] = o
		}
	}
	return m
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func operation(k string, o, n oas.Operation, add func(Change)) {
	if !o.Deprecated && n.Deprecated {
		add(Change{Kind: OperationDeprecated, Key: k, Detail: "operation deprecated"})
	}

	os, ns := o.Security.State, n.Security.State
	switch {
	case os == oas.SecurityRequired && ns == oas.SecurityNone:
		add(Change{Kind: SecurityRemoved, Key: k, Detail: "authentication was required and is now declared as none", SecurityRegression: true})
	case strength[ns] < strength[os]:
		add(Change{Kind: SecurityWeakened, Key: k, Detail: fmt.Sprintf("security went from %s to %s", os, ns), SecurityRegression: true})
	case strength[ns] > strength[os]:
		add(Change{Kind: SecurityAdded, Key: k, Detail: fmt.Sprintf("security went from %s to %s", os, ns), Breaking: true})
	case os == oas.SecurityRequired && ns == oas.SecurityRequired:
		if lost := lostSchemes(o.Security, n.Security); lost != "" {
			// A new alternative that needs less is a weaker requirement.
			add(Change{Kind: SecurityWeakened, Key: k, Detail: "a weaker way to authenticate was added: " + lost, SecurityRegression: true})
		}
	}

	params(k, o, n, add)
	body(k, o, n, add)
	responses(k, o, n, add)
}

// lostSchemes reports alternatives in n that need fewer schemes or scopes
// than every alternative in o.
func lostSchemes(o, n oas.Security) string {
	need := func(a []oas.SchemeUse) map[string]bool {
		m := map[string]bool{}
		for _, u := range a {
			m[u.Scheme] = true
			for _, s := range u.Scopes {
				m[u.Scheme+":"+s] = true
			}
		}
		return m
	}
	var weaker []string
	for _, na := range n.Alternatives {
		nn := need(na)
		covered := false
		for _, oa := range o.Alternatives {
			on := need(oa)
			subset := true
			for k := range on {
				if !nn[k] {
					subset = false
					break
				}
			}
			if subset {
				covered = true
				break
			}
		}
		if !covered {
			var names []string
			for _, u := range na {
				names = append(names, u.Scheme)
			}
			weaker = append(weaker, strings.Join(names, "+"))
		}
	}
	return strings.Join(weaker, ", ")
}

func paramKey(p oas.Parameter) string { return string(p.In) + ":" + p.Name }

func params(k string, o, n oas.Operation, add func(Change)) {
	om, nm := map[string]oas.Parameter{}, map[string]oas.Parameter{}
	for _, p := range o.Parameters {
		om[paramKey(p)] = p
	}
	for _, p := range n.Parameters {
		nm[paramKey(p)] = p
	}
	for _, pk := range keys(om) {
		if _, ok := nm[pk]; !ok {
			add(Change{Kind: ParameterRemoved, Key: k, Detail: "parameter " + pk + " removed"})
		}
	}
	for _, pk := range keys(nm) {
		np := nm[pk]
		op, ok := om[pk]
		if !ok {
			add(Change{Kind: ParameterAdded, Key: k, Detail: "parameter " + pk + " added", Breaking: np.Required})
			continue
		}
		if !op.Required && np.Required {
			add(Change{Kind: ParameterRequired, Key: k, Detail: "parameter " + pk + " is now required", Breaking: true})
		}
		if op.Schema.Type != np.Schema.Type && op.Schema.Type != "" && np.Schema.Type != "" {
			add(Change{Kind: ParameterTypeChanged, Key: k, Detail: fmt.Sprintf("parameter %s type %s → %s", pk, op.Schema.Type, np.Schema.Type), Breaking: true})
		}
	}
}

func body(k string, o, n oas.Operation, add func(Change)) {
	switch {
	case o.RequestBody == nil && n.RequestBody != nil:
		add(Change{Kind: BodyAdded, Key: k, Detail: "request body added", Breaking: n.RequestBody.Required})
		return
	case o.RequestBody != nil && n.RequestBody == nil:
		add(Change{Kind: BodyRemoved, Key: k, Detail: "request body removed"})
		return
	case o.RequestBody == nil:
		return
	}
	if !o.RequestBody.Required && n.RequestBody.Required {
		add(Change{Kind: BodyRequired, Key: k, Detail: "request body is now required", Breaking: true})
	}
	nt := map[string]bool{}
	for _, c := range n.RequestBody.Content {
		nt[c.Type] = true
	}
	for _, c := range o.RequestBody.Content {
		if !nt[c.Type] {
			add(Change{Kind: ContentTypeRemoved, Key: k, Detail: "request content type " + c.Type + " no longer accepted", Breaking: true})
		}
	}
}

func responses(k string, o, n oas.Operation, add func(Change)) {
	om, nm := map[string]bool{}, map[string]bool{}
	for _, r := range o.Responses {
		om[r.Code] = true
	}
	for _, r := range n.Responses {
		nm[r.Code] = true
	}
	for _, c := range keys(om) {
		if !nm[c] {
			add(Change{Kind: ResponseRemoved, Key: k, Detail: "response " + c + " removed", Breaking: strings.HasPrefix(c, "2")})
		}
	}
	for _, c := range keys(nm) {
		if !om[c] {
			add(Change{Kind: ResponseAdded, Key: k, Detail: "response " + c + " added"})
		}
	}
}

func servers(old, cur *oas.Document, add func(Change)) {
	if old == nil || cur == nil {
		return
	}
	om, nm := map[string]bool{}, map[string]bool{}
	for _, s := range old.Servers {
		om[s.Resolved] = true
	}
	for _, s := range cur.Servers {
		nm[s.Resolved] = true
	}
	for _, u := range keys(om) {
		if !nm[u] {
			add(Change{Kind: ServerRemoved, Detail: "server " + u + " removed", Breaking: true})
		}
	}
	for _, u := range keys(nm) {
		if !om[u] {
			add(Change{Kind: ServerAdded, Detail: "server " + u + " added"})
		}
	}
}
