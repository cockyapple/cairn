package vectorgen

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/cockyapple/cairn/ledger"
)

// The error codes in SPEC section 7 must be exactly the codes the ledger
// package returns. They drifted once (found by external audit); never again.
func TestSpecErrorCodesMatchCode(t *testing.T) {
	raw, err := os.ReadFile("../../docs/SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	i := strings.Index(s, "## 7. Error codes")
	j := strings.Index(s, "## 8.")
	if i < 0 || j < i {
		t.Fatal("SPEC section 7 not found")
	}
	var spec []string
	for _, m := range regexp.MustCompile("`([a-z_]+)`").FindAllStringSubmatch(s[i:j], -1) {
		spec = append(spec, m[1])
	}
	code := []string{
		ledger.CodeBadLength, ledger.CodeBadVersion, ledger.CodeUnknownKind, ledger.CodeBadGenesis,
		ledger.CodeDuplicateGenesis, ledger.CodeBadHeight, ledger.CodeBadPrevHash, ledger.CodeBadSignature,
		ledger.CodeBadPayload, ledger.CodeSizeMismatch, ledger.CodeRootMismatch, ledger.CodeHeadMismatch,
		ledger.CodeEpochMismatch, ledger.CodeBelowQuorum, ledger.CodeBelowWitnesses, ledger.CodeDuplicateSigner,
		ledger.CodeBadTrustConfig, ledger.CodeBadCheckpointLen, ledger.CodeUnknownSigner, ledger.CodeUnsortedSigners,
	}
	sort.Strings(spec)
	sort.Strings(code)
	if strings.Join(spec, ",") != strings.Join(code, ",") {
		t.Fatalf("SPEC section 7 and ledger codes differ\nspec: %v\ncode: %v", spec, code)
	}
}
