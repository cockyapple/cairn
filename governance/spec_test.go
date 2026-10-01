package governance

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The codes in SPEC section 10.6 must be exactly the codes this package
// returns, as section 7 is for the ledger.
func TestSpecGovernanceCodesMatchCode(t *testing.T) {
	raw, err := os.ReadFile("../docs/SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	i := strings.Index(s, "### 10.6 Error codes")
	if i < 0 {
		t.Fatal("SPEC section 10.6 not found")
	}
	var spec []string
	for _, m := range regexp.MustCompile("`([a-z_]+)`").FindAllStringSubmatch(s[i:], -1) {
		spec = append(spec, m[1])
	}
	// The ledger codes named in prose there are allowed, not required, in the list.
	var filtered []string
	for _, c := range spec {
		if c != "bad_payload" && c != "bad_trust_config" {
			filtered = append(filtered, c)
		}
	}
	code := append([]string(nil), AllCodes...)
	sort.Strings(filtered)
	sort.Strings(code)
	if strings.Join(filtered, ",") != strings.Join(code, ",") {
		t.Fatalf("SPEC 10.6 and governance codes differ\nspec: %v\ncode: %v", filtered, code)
	}
}
