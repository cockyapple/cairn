package gatekeeper_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cockyapple/cairn/gatekeeper"
	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
)

func stores(t *testing.T) map[string]gatekeeper.OpeningStore {
	d, err := gatekeeper.NewDirOpenings(filepath.Join(t.TempDir(), "openings"))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]gatekeeper.OpeningStore{"memory": &gatekeeper.MemoryOpenings{}, "dir": d}
}

func TestOpeningStoresRoundTrip(t *testing.T) {
	for name, s := range stores(t) {
		o, c, err := governance.NewOpening([]byte("payload"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.Get(c); !errors.Is(err, gatekeeper.ErrNoOpening) {
			t.Fatalf("%s: empty store: %v", name, err)
		}
		p := bytes.Clone(o)
		if err := s.Put(c, p); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		p[0] ^= 1 // the caller reuses its buffer
		got, err := s.Get(c)
		if err != nil || !bytes.Equal(got, o) {
			t.Fatalf("%s: %x %v", name, got, err)
		}
		got[0] ^= 1 // a caller cannot reach into the store
		if again, _ := s.Get(c); !bytes.Equal(again, o) {
			t.Fatalf("%s: Get returned the store's own buffer", name)
		}
		if err := s.Delete(c); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := s.Get(c); !errors.Is(err, gatekeeper.ErrNoOpening) {
			t.Fatalf("%s: after delete: %v", name, err)
		}
		if err := s.Delete(c); err != nil {
			t.Fatalf("%s: deleting twice: %v", name, err)
		}
	}
}

func TestDirOpeningsSurviveANewInstance(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "o")
	a, err := gatekeeper.NewDirOpenings(dir)
	if err != nil {
		t.Fatal(err)
	}
	o, c, _ := governance.NewOpening([]byte("kept"))
	if err := a.Put(c, o); err != nil {
		t.Fatal(err)
	}
	b, _ := gatekeeper.NewDirOpenings(dir)
	if got, err := b.Get(c); err != nil || !bytes.Equal(got, o) {
		t.Fatalf("%v", err)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("%v %v", fi, err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("%d files, want 1 (no temporary left behind)", len(ents))
	}
}

func TestDirOpeningsRefuseWhatDoesNotMatch(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "o")
	s, _ := gatekeeper.NewDirOpenings(dir)
	o, c, _ := governance.NewOpening([]byte("x"))
	other, _, _ := governance.NewOpening([]byte("x"))
	if err := s.Put(c, other); err == nil {
		t.Fatal("stored an opening that does not hash to the commitment")
	}
	if _, err := s.Get(c); !errors.Is(err, gatekeeper.ErrNoOpening) {
		t.Fatalf("a refused Put left something behind: %v", err)
	}
	if err := s.Put(c, o); err != nil {
		t.Fatal(err)
	}
	// Corrupt the file on disk: Get must not hand it back as the opening.
	file := filepath.Join(dir, fmt.Sprintf("%x", c[:]))
	bad := append([]byte(nil), o...)
	bad[len(bad)-1] ^= 1
	if err := os.WriteFile(file, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(c)
	if err == nil || errors.Is(err, gatekeeper.ErrNoOpening) || got != nil {
		t.Fatalf("%x %v", got, err)
	}
}

// flaky wraps a store and lets a test fail or watch its calls.
type flaky struct {
	gatekeeper.OpeningStore
	failPut func(n int) bool
	puts    []ledger.Hash
	deleted []ledger.Hash
	onPut   func(ledger.Hash)
}

func (f *flaky) Put(c ledger.Hash, o []byte) error {
	f.puts = append(f.puts, c)
	if f.onPut != nil {
		f.onPut(c)
	}
	if f.failPut != nil && f.failPut(len(f.puts)) {
		return errors.New("disk full")
	}
	return f.OpeningStore.Put(c, o)
}

func (f *flaky) Delete(c ledger.Hash) error {
	f.deleted = append(f.deleted, c)
	return f.OpeningStore.Delete(c)
}

func flakyEnv(t *testing.T, wait bool) (*genv, *flaky, *int) {
	e := grantSetup(t, testGrant(), wait, &gatekeeper.Agent{Allow: []string{"shell"}, HashOnly: true})
	f := &flaky{OpeningStore: &gatekeeper.MemoryOpenings{}}
	e.g.Store = f
	ran := new(int)
	e.g.Handle("shell", func(context.Context, []byte) ([]byte, error) { *ran++; return []byte("done"), nil })
	return e, f, ran
}

func TestHashOnlyFailsClosedWhenTheOpeningCannotBeStored(t *testing.T) {
	e, f, ran := flakyEnv(t, false)
	f.failPut = func(int) bool { return true }
	before := len(e.l.Entries)
	_, err := e.g.Do(context.Background(), "actor", "shell", []byte("secret"))
	if err == nil || !strings.Contains(err.Error(), "storing the opening") {
		t.Fatalf("%v", err)
	}
	if *ran != 0 {
		t.Fatal("the handler ran although the opening was not kept")
	}
	if len(e.l.Entries) != before {
		t.Fatalf("an entry was appended for an opening nobody holds")
	}
}

func TestHashOnlyDoesNotCompleteWhenTheResultOpeningCannotBeStored(t *testing.T) {
	e, f, ran := flakyEnv(t, false)
	f.failPut = func(n int) bool { return n == 2 } // the args opening is kept, the result's is not
	_, err := e.g.Do(context.Background(), "actor", "shell", []byte("secret"))
	if err == nil || !strings.Contains(err.Error(), "storing the opening") {
		t.Fatalf("%v", err)
	}
	if *ran != 1 {
		t.Fatalf("ran %d times", *ran)
	}
	for _, c := range f.puts[1:] {
		for _, ent := range e.l.Entries {
			a, err := ledger.DecodeAction(e.l.Blobs[ent.PayloadHash])
			if err == nil && a.ResultHash == c {
				t.Fatal("a result was committed whose opening was not stored")
			}
		}
	}
}

func TestOpeningIsStoredBeforeTheEntryThatCommitsToIt(t *testing.T) {
	e, f, _ := flakyEnv(t, false)
	f.onPut = func(c ledger.Hash) {
		for _, ent := range e.l.Entries {
			if a, err := ledger.DecodeAction(e.l.Blobs[ent.PayloadHash]); err == nil && (a.ArgsHash == c || a.ResultHash == c) {
				t.Errorf("commitment %x is already on the log", c[:4])
			}
		}
	}
	if _, err := e.g.Do(context.Background(), "actor", "shell", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if len(f.puts) != 2 {
		t.Fatalf("%d puts", len(f.puts))
	}
}

func TestOpeningIsDeletedWhenTheLogRefusesTheEntry(t *testing.T) {
	e, f, ran := flakyEnv(t, true)
	_, err := e.g.DoUse(context.Background(), "actor", "shell", []byte("x"), "a.example", 500)
	if gatekeeper.ErrCode(err) != gatekeeper.CodeOutOfGrant {
		t.Fatalf("%v", err)
	}
	if *ran != 0 {
		t.Fatal("the handler ran")
	}
	if len(f.deleted) == 0 {
		t.Fatal("the refused intent's opening was kept")
	}
	for _, c := range f.deleted {
		if _, err := f.Get(c); !errors.Is(err, gatekeeper.ErrNoOpening) {
			t.Fatalf("%x: %v", c[:4], err)
		}
	}
	// Every opening still held is for an entry that is on the log.
	onLog := map[ledger.Hash]bool{}
	for _, ent := range e.l.Entries {
		a, err := ledger.DecodeAction(e.l.Blobs[ent.PayloadHash])
		if err != nil {
			continue
		}
		onLog[a.ArgsHash], onLog[a.ResultHash] = true, true
		if u, err := governance.DecodeUse(e.l.Blobs[a.ArgsHash]); err == nil && u.Commit != nil {
			onLog[*u.Commit] = true
		}
	}
	for _, c := range f.puts {
		if _, err := f.Get(c); err == nil && !onLog[c] {
			t.Fatalf("an opening is held for %x, which is not on the log", c[:4])
		}
	}
}

func TestLocateFindsWhereACommitmentAppears(t *testing.T) {
	e := grantSetup(t, testGrant(), true, &gatekeeper.Agent{Allow: []string{"shell"}, HashOnly: true})
	ctx := context.Background()
	if _, err := e.g.DoUse(ctx, "actor", "shell", []byte("bound args"), "a.example", 5); err != nil {
		t.Fatal(err)
	}
	intent, done := e.lastAction(t, 1), e.lastAction(t, 0)
	u, _ := governance.DecodeUse(e.l.Blobs[intent.ArgsHash])
	n := uint64(len(e.l.Entries))
	at := func(c ledger.Hash) []governance.Location { return governance.Locate(e.l.Entries, e.l.Blobs, c) }

	if got := at(*u.Commit); len(got) != 2 || got[0] != (governance.Location{Height: n - 2, Field: "use"}) || got[1] != (governance.Location{Height: n - 1, Field: "use"}) {
		t.Fatalf("args commitment: %+v", got)
	}
	if got := at(done.ResultHash); len(got) != 1 || got[0] != (governance.Location{Height: n - 1, Field: "result"}) {
		t.Fatalf("result commitment: %+v", got)
	}
	if got := at(ledger.BlobHash([]byte("never committed"))); len(got) != 0 {
		t.Fatalf("%+v", got)
	}

	// An unbound agent's args commitment is the intent's and the completion's args_hash.
	e2 := grantSetup(t, testGrant(), false, &gatekeeper.Agent{Allow: []string{"shell"}, HashOnly: true})
	if _, err := e2.g.Do(ctx, "free", "shell", []byte("plain")); err != nil {
		t.Fatal(err)
	}
	c := e2.lastAction(t, 1).ArgsHash
	n2 := uint64(len(e2.l.Entries))
	got := governance.Locate(e2.l.Entries, e2.l.Blobs, c)
	if len(got) != 2 || got[0] != (governance.Location{Height: n2 - 2, Field: "args"}) || got[1] != (governance.Location{Height: n2 - 1, Field: "args"}) {
		t.Fatalf("%+v", got)
	}
}

func TestResultOpeningIsDeletedWhenTheLogRefusesTheCompletion(t *testing.T) {
	e, f, _ := flakyEnv(t, false)
	e.g.Handle("shell", func(context.Context, []byte) ([]byte, error) {
		// Someone closes the open intent behind the gatekeeper's back, so the
		// gatekeeper's own completion is refused.
		argsHash := e.lastAction(t, 0).ArgsHash
		if _, err := e.l.CompleteHash(e.actor, "shell", argsHash, ledger.BlobHash([]byte("elsewhere"))); err != nil {
			t.Error(err)
		}
		return []byte("done"), nil
	})
	if _, err := e.g.Do(context.Background(), "actor", "shell", []byte("x")); err == nil {
		t.Fatal("the completion was accepted twice")
	}
	if len(f.puts) != 2 || len(f.deleted) != 1 || f.deleted[0] != f.puts[1] {
		t.Fatalf("puts %d, deleted %d", len(f.puts), len(f.deleted))
	}
	if _, err := f.Get(f.puts[1]); !errors.Is(err, gatekeeper.ErrNoOpening) {
		t.Fatalf("the refused completion's opening is still held: %v", err)
	}
}

func TestOpeningStoresRefuseAMismatchedOpening(t *testing.T) {
	for name, s := range stores(t) {
		_, c, _ := governance.NewOpening([]byte("x"))
		other, _, _ := governance.NewOpening([]byte("x"))
		if err := s.Put(c, other); err == nil {
			t.Fatalf("%s: accepted an opening that does not hash to the commitment", name)
		}
		if _, err := s.Get(c); !errors.Is(err, gatekeeper.ErrNoOpening) {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestNewDirOpeningsChecksTheDirectory(t *testing.T) {
	root := t.TempDir()
	open := filepath.Join(root, "open")
	if err := os.Mkdir(open, 0o755); err != nil {
		t.Fatal(err)
	}
	os.Chmod(open, 0o755) // whatever the umask said
	if _, err := gatekeeper.NewDirOpenings(open); err == nil {
		t.Fatal("accepted a directory other users can read")
	}
	file := filepath.Join(root, "file")
	os.WriteFile(file, nil, 0o600)
	if _, err := gatekeeper.NewDirOpenings(file); err == nil {
		t.Fatal("accepted a plain file")
	}
	deep := filepath.Join(root, "a", "b", "c")
	if _, err := gatekeeper.NewDirOpenings(deep); err != nil {
		t.Fatalf("a nested new directory: %v", err)
	}
	for _, d := range []string{"a", "a/b", "a/b/c"} {
		if fi, err := os.Stat(filepath.Join(root, d)); err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v", d, fi, err)
		}
	}
	if _, err := gatekeeper.NewDirOpenings(deep); err != nil {
		t.Fatalf("reopening: %v", err)
	}
}
