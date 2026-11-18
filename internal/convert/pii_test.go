package convert

import "testing"

func TestPIIPhoneRuleMatchesWordsNotSuffixes(t *testing.T) {
	for name, want := range map[string]string{
		"phone":         "phone",
		"phone_number":  "phone",
		"phoneNumber":   "phone",
		"contactPhone":  "phone",
		"mobile":        "phone",
		"tel":           "phone",
		"home-tel":      "phone",
		"withVulnIntel": "",
		"hotel":         "",
		"intel":         "",
	} {
		if got := piiKind(name); got != want {
			t.Errorf("piiKind(%q) = %q, want %q", name, got, want)
		}
	}
}
