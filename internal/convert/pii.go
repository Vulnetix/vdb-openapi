package convert

import (
	"regexp"
	"sort"
	"strings"

	"github.com/Vulnetix/vdb-openapi/oas"
)

// piiRules match field names, not values. A hint is a reason to look, not a
// finding: "email" in a query string is worth seeing; whether it is
// sensitive is the reader's call.
var piiRules = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"credential", regexp.MustCompile(`(?i)^(password|passwd|pwd|secret|api_?key|apikey|access_?token|refresh_?token|token|client_?secret|private_?key)$`)},
	{"email", regexp.MustCompile(`(?i)(^|_|-)e?mail(_?address)?$|^email`)},
	{"phone", regexp.MustCompile(`(?i)(phone|mobile|msisdn|tel(ephone)?)(_?number)?$`)},
	{"government_id", regexp.MustCompile(`(?i)^(ssn|sin|nino|tfn|tax_?id|national_?id|passport(_?number)?|driver_?licen[cs]e(_?number)?)$`)},
	{"date_of_birth", regexp.MustCompile(`(?i)^(dob|date_?of_?birth|birth_?date|birthday)$`)},
	{"payment_card", regexp.MustCompile(`(?i)^(card_?number|pan|cvv|cvc|cc_?number|credit_?card)$`)},
	{"bank_account", regexp.MustCompile(`(?i)^(iban|bsb|routing_?number|account_?number|sort_?code)$`)},
	{"address", regexp.MustCompile(`(?i)^(address|street|postcode|post_?code|zip|zip_?code|address_?line_?\d)$`)},
	{"person_name", regexp.MustCompile(`(?i)^(first_?name|last_?name|full_?name|given_?name|family_?name|surname)$`)},
	{"location", regexp.MustCompile(`(?i)^(lat|lng|lon|latitude|longitude|geo(location)?)$`)},
	{"ip_address", regexp.MustCompile(`(?i)^(ip|ip_?address|client_?ip|remote_?addr)$`)},
}

func piiKind(name string) string {
	n := strings.ReplaceAll(strings.TrimSpace(name), "-", "_")
	for _, r := range piiRules {
		if r.re.MatchString(n) {
			return r.kind
		}
	}
	return ""
}

func piiHints(o *oas.Operation) []oas.PIIHint {
	seen := map[string]bool{}
	out := []oas.PIIHint{}
	add := func(kind, where string) {
		if kind == "" || seen[where] {
			return
		}
		seen[where] = true
		out = append(out, oas.PIIHint{Kind: kind, Where: where})
	}
	for _, p := range o.Parameters {
		add(piiKind(p.Name), string(p.In)+":"+p.Name)
	}
	if o.RequestBody != nil {
		for _, mt := range o.RequestBody.Content {
			if mt.Schema != nil {
				walkPII(*mt.Schema, "body:", 0, add)
			}
		}
	}
	for _, r := range o.Responses {
		if !strings.HasPrefix(r.Code, "2") {
			continue
		}
		for _, mt := range r.Content {
			if mt.Schema != nil {
				walkPII(*mt.Schema, "response:"+r.Code+":", 0, add)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Where < out[j].Where })
	return out
}

func walkPII(s oas.SchemaSummary, prefix string, depth int, add func(string, string)) {
	if depth > 4 {
		return
	}
	if s.Items != nil {
		walkPII(*s.Items, prefix, depth+1, add)
	}
	for _, v := range s.Variants {
		walkPII(v, prefix, depth+1, add)
	}
	names := make([]string, 0, len(s.Properties))
	for n := range s.Properties {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		add(piiKind(n), prefix+n)
		walkPII(s.Properties[n], prefix+n+".", depth+1, add)
	}
}
