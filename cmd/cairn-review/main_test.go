package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cockyapple/cairn/ledger"
	"github.com/cockyapple/cairn/review"
)

func k(n string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("review-cli-" + n))
	return ed25519.NewKeyFromSeed(s[:])
}

func pub(p ed25519.PrivateKey) (o [32]byte) { copy(o[:], p.Public().(ed25519.PublicKey)); return }

func bundle(t *testing.T) string {
	t.Helper()
	v, p := k("v"), k("p")
	tc := ledger.TrustConfig{Keys: []ledger.Key{{Role: ledger.RoleValidator, Public: pub(v)}, {Role: ledger.RoleProposer, Public: pub(p)}}}
	var n uint64 = 100
	l, err := review.New(v, ledger.BlobHash([]byte("c")), tc, func() uint64 { n++; return n })
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Propose(p, ledger.T0, "t/x", []byte("body"), []byte("why"), nil); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "b")
	if err := review.SaveBundle(dir, l.Entries, l.Blobs); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestWritesPage(t *testing.T) {
	dir, out := bundle(t), filepath.Join(t.TempDir(), "r.html")
	var e bytes.Buffer
	if c := run([]string{"-bundle", dir, "-out", out}, &e); c != 0 {
		t.Fatalf("exit %d: %s", c, e.String())
	}
	b, _ := os.ReadFile(out)
	if !strings.Contains(string(b), "t/x") {
		t.Fatal("page lacks the proposal")
	}
}

func TestUsageAndBadInput(t *testing.T) {
	var e bytes.Buffer
	if c := run(nil, &e); c != 2 {
		t.Fatalf("no flags: %d", c)
	}
	if c := run([]string{"-bundle", "/nonexistent", "-out", filepath.Join(t.TempDir(), "x")}, &e); c != 2 {
		t.Fatalf("missing bundle: %d", c)
	}
	if c := run([]string{"-bundle", bundle(t), "-out", filepath.Join(t.TempDir(), "x"), "-constitution", "zz"}, &e); c != 2 {
		t.Fatalf("bad constitution: %d", c)
	}
}

func TestWrongConstitutionExitsOneAndShowsNothing(t *testing.T) {
	out := filepath.Join(t.TempDir(), "r.html")
	var e bytes.Buffer
	wrong := strings.Repeat("ab", 32)
	if c := run([]string{"-bundle", bundle(t), "-out", out, "-constitution", wrong}, &e); c != 1 {
		t.Fatalf("exit %d: %s", c, e.String())
	}
	b, _ := os.ReadFile(out)
	if !strings.Contains(string(b), "does not verify") || strings.Contains(string(b), "t/x") {
		t.Fatal("a log that fails its constitution check must show only the failure")
	}
}
