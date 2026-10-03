package review

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cockyapple/cairn/eval"
	"github.com/cockyapple/cairn/governance"
)

func TestCloneSharesNothingMutable(t *testing.T) {
	m := &Material{
		Info:      governance.ProposalInfo{Votes: []governance.VoteInfo{{Height: 1}}},
		Artifact:  []byte("a"),
		Previous:  []byte("p"),
		Rationale: []byte("r"),
		Eval:      &eval.Result{Suite: "s", Cases: []eval.CaseScore{{Name: "c", Candidate: 1}}},
	}
	c := clone(m)
	c.Artifact[0], c.Previous[0], c.Rationale[0] = 'X', 'X', 'X'
	c.Info.Votes[0].Height = 99
	c.Eval.Cases[0].Candidate = -1
	c.Eval.Suite = "changed"
	if string(m.Artifact) != "a" || string(m.Previous) != "p" || string(m.Rationale) != "r" ||
		m.Info.Votes[0].Height != 1 || m.Eval.Cases[0].Candidate != 1 || m.Eval.Suite != "s" {
		t.Fatalf("a reviewer's copy aliases the shared material: %+v", m)
	}
}

func TestStoreCopiesTheCallersSlice(t *testing.T) {
	l := &Log{Blobs: governance.MapBlobs{}}
	b := []byte("payload")
	h := l.store(b)
	b[0] = 'X'
	if string(l.Blobs[h]) != "payload" {
		t.Fatal("a stored blob changed when the caller reused its slice")
	}
}

func TestLoadBundleRefusesAnOversizedLog(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "log.bin"), make([]byte, 11), 0o600); err != nil {
		t.Fatal(err)
	}
	old := maxLogBytes
	maxLogBytes = 10
	defer func() { maxLogBytes = old }()
	if _, _, err := LoadBundle(dir); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("want a size refusal, got %v", err)
	}
}
