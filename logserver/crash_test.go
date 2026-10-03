package logserver_test

import (
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/cockyapple/cairn/ledger"
	"github.com/cockyapple/cairn/logserver"
)

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o700)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
}

type snap struct {
	point  string
	height uint64
	dir    string
}

// A real run of the append path is snapshotted at every step of persist, as if
// the process had died there. Each snapshot must reopen to a log that is either
// exactly before or exactly after the interrupted entry, with every payload
// present and no blob left over that no entry refers to.
func TestCrashAtEveryStepOfPersistRecovers(t *testing.T) {
	f := newFx(t, nil)
	var snaps []snap
	f.srv.SetCrashHook(func(point string, height uint64) {
		d := filepath.Join(t.TempDir(), "log")
		copyTree(t, f.dir, d)
		snaps = append(snaps, snap{point, height, d})
	})
	f.fullFlow()
	if len(snaps) < 20 {
		t.Fatalf("only %d crash points were exercised", len(snaps))
	}
	seen := map[string]bool{}
	for _, sn := range snaps {
		seen[sn.point] = true
		cfg := f.cfg
		cfg.Dir = sn.dir
		srv, err := logserver.Open(cfg)
		if err != nil {
			t.Fatalf("crash at %s (height %d): reopen failed: %v", sn.point, sn.height, err)
		}
		n := uint64(srv.Status().Entries)
		committed := sn.point != "staged"
		switch {
		case sn.point == "staged" && n != sn.height:
			t.Fatalf("crash at staged (height %d): log has %d entries", sn.height, n)
		case sn.point == "entry-written" && n != sn.height && n != sn.height+1:
			t.Fatalf("crash at entry-written (height %d): log has %d entries", sn.height, n)
		case committed && sn.point != "entry-written" && n != sn.height+1:
			t.Fatalf("crash at %s (height %d): acknowledged entry lost, log has %d", sn.point, sn.height, n)
		}
		raw, _ := srv.Entries(0, int(n))
		want := map[string]bool{}
		for i := 0; i < int(n); i++ {
			var e ledger.Entry
			e, err = ledger.DecodeEntry(raw[i*ledger.EntrySize : (i+1)*ledger.EntrySize])
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := srv.Blob(e.PayloadHash); !ok {
				t.Fatalf("crash at %s (height %d): entry %d has no payload", sn.point, sn.height, i)
			}
			want[hexOf(e.PayloadHash)] = true
		}
		des, err := os.ReadDir(filepath.Join(sn.dir, "blobs"))
		if err != nil {
			t.Fatal(err)
		}
		for _, de := range des {
			if !want[de.Name()] {
				t.Fatalf("crash at %s (height %d): blob %s is not referenced by any entry", sn.point, sn.height, de.Name())
			}
		}
		if _, err := os.Stat(filepath.Join(sn.dir, "staging")); !os.IsNotExist(err) {
			t.Fatalf("crash at %s (height %d): staging survived recovery", sn.point, sn.height)
		}
		srv.Close()
	}
	for _, p := range []string{"staged", "entry-written", "entry-synced", "renamed", "blobs-synced"} {
		if !seen[p] {
			t.Fatalf("crash point %q was never reached", p)
		}
	}
}

func hexOf(h ledger.Hash) string { return hex.EncodeToString(h[:]) }
