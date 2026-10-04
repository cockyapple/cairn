package review

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/cockyapple/cairn/eval"
	"github.com/cockyapple/cairn/ledger"
)

func hkey(n string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("review-hardening/" + n))
	return ed25519.NewKeyFromSeed(s[:])
}

func hpub(k ed25519.PrivateKey) (p [32]byte) { copy(p[:], k.Public().(ed25519.PublicKey)); return }

func TestRefusedAppendLeavesNoBlobsBehind(t *testing.T) {
	val, outsider := hkey("val"), hkey("outsider")
	trust := ledger.TrustConfig{Keys: []ledger.Key{{Role: ledger.RoleValidator, Public: hpub(val)}}}
	var now uint64 = 1_000_000
	l, err := New(val, ledger.BlobHash([]byte("c")), trust, func() uint64 { now++; return now })
	if err != nil {
		t.Fatal(err)
	}
	before := len(l.Blobs)
	for i := 0; i < 20; i++ {
		if _, err := l.Vote(outsider, ledger.Hash{1}, ledger.VerdictApprove, bytes.Repeat([]byte{byte(i)}, 1000)); err == nil {
			t.Fatal("an outsider's vote was taken")
		}
		if _, err := l.Propose(outsider, ledger.T3, "t", []byte{byte(i), 1}, []byte{byte(i), 2}, nil); err == nil {
			t.Fatal("an outsider's proposal was taken")
		}
	}
	if len(l.Blobs) != before {
		t.Fatalf("%d blobs leaked by refused appends", len(l.Blobs)-before)
	}
}

func TestLineCountAndFirstLinesAgreeWithSplitLines(t *testing.T) {
	for _, s := range []string{"", "\n", "a", "a\n", "a\n\n", "a\nb", "\n\n\n", "a\n\nb\n"} {
		b := []byte(s)
		want := splitLines(b)
		if lineCount(b) != len(want) {
			t.Errorf("%q: count %d, want %d", s, lineCount(b), len(want))
		}
		got := firstLines(b, 1<<30)
		if strings.Join(got, "|") != strings.Join(want, "|") || len(got) != len(want) {
			t.Errorf("%q: %q vs %q", s, got, want)
		}
		if n := firstLines(b, 1); len(n) > 1 {
			t.Errorf("%q: firstLines(1) gave %d", s, len(n))
		}
	}
}

func TestProposeRefusesAnEvalResultNoCouncilCouldRead(t *testing.T) {
	val := hkey("val")
	trust := ledger.TrustConfig{Keys: []ledger.Key{{Role: ledger.RoleValidator, Public: hpub(val)}}}
	var now uint64 = 1_000_000
	l, err := New(val, ledger.BlobHash([]byte("c")), trust, func() uint64 { now++; return now })
	if err != nil {
		t.Fatal(err)
	}
	bad := &eval.Result{Suite: "s", Cases: []eval.CaseScore{{Name: "b", Baseline: 1, Candidate: 2}, {Name: "a", Baseline: 1, Candidate: 2}}}
	before, entries := len(l.Blobs), len(l.Entries)
	_, err = l.Propose(val, ledger.T3, "t", []byte("d"), []byte("r"), bad)
	if err == nil || !strings.Contains(err.Error(), "would not decode") {
		t.Fatalf("want an eval decode refusal, got %v", err)
	}
	if len(l.Blobs) != before || len(l.Entries) != entries {
		t.Fatal("a refused proposal left blobs or entries behind")
	}
}
