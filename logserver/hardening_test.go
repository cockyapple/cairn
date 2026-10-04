package logserver_test

import (
	"encoding/hex"
	"encoding/json"
	"runtime"
	"testing"

	"github.com/cockyapple/cairn/ledger"
	"github.com/cockyapple/cairn/logserver"
)

func TestSecondServerOnTheSameDirectoryIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" || runtime.GOOS == "plan9" {
		t.Skip("no directory lock on this platform")
	}
	f := newFx(t, nil)
	if s, err := logserver.Open(f.cfg); err == nil {
		s.Close()
		t.Fatal("a second server opened a directory that is already in use")
	}
	f.srv.Close()
	f.ts.Close()
	s, err := logserver.Open(f.cfg)
	if err != nil {
		t.Fatalf("the directory stayed locked after Close: %v", err)
	}
	s.Close()
	f.open()
}

func TestBlobReturnsACopy(t *testing.T) {
	f := newFx(t, nil)
	f.fullFlow()
	var h ledger.Hash
	var b []byte
	for k := range f.l.Blobs {
		if got, ok := f.srv.Blob(k); ok && len(got) > 0 {
			h, b = k, got
			break
		}
	}
	if b == nil {
		t.Fatal("the server holds no blob to test with")
	}
	b[0] ^= 0xff
	again, _ := f.srv.Blob(h)
	if ledger.BlobHash(again) != h {
		t.Fatal("a caller changed the server's stored blob")
	}
}

func TestCachedRootsMatchAFreshComputation(t *testing.T) {
	f := newFx(t, nil)
	f.fullFlow()
	n := len(f.l.Entries)
	check := func(size int) {
		t.Helper()
		got, rj := f.srv.CheckpointBody(uint64(size))
		if rj != nil {
			t.Fatalf("size %d: %v", size, rj)
		}
		want := ledger.NewCheckpoint(0, f.l.Entries[:size])
		if string(got) != string(want.Body()) {
			t.Fatalf("size %d: cached checkpoint differs from a fresh one", size)
		}
	}
	for s := n; s >= 1; s-- {
		check(s)
	}
	for s := 1; s <= n; s++ {
		check(s)
		check(s)
	}
	f.propose("later")
	f.sendAll(n)
	m := len(f.l.Entries)
	if m <= n {
		t.Fatal("the log did not grow")
	}
	check(m)
	check(n)
	var st logserver.Status
	json.Unmarshal(f.do("GET", "/v1/status", nil).Body, &st)
	root := ledger.LogRoot(f.l.Entries)
	if st.Entries != m || st.Root != hex.EncodeToString(root[:]) {
		t.Fatalf("status after growth: %+v", st)
	}
}

func TestLimitsAboveWhatTheVerifierReadsAreRefused(t *testing.T) {
	f := newFx(t, nil)
	f.srv.Close()
	f.ts.Close()
	for name, mod := range map[string]func(*logserver.Limits){
		"entries": func(l *logserver.Limits) { l.MaxEntries = logserver.VerifierMaxEntries + 1 },
		"blob":    func(l *logserver.Limits) { l.MaxBlobBytes = logserver.VerifierMaxBlobBytes + 1 },
		"blobs":   func(l *logserver.Limits) { l.MaxBlobs = logserver.VerifierMaxBlobs + 1 },
		"store":   func(l *logserver.Limits) { l.MaxStoreBytes = logserver.VerifierMaxStoreBytes + 1 },
	} {
		cfg := f.cfg
		mod(&cfg.Limits)
		if s, err := logserver.Open(cfg); err == nil {
			s.Close()
			t.Errorf("%s: a limit past the verifier's ceiling was accepted", name)
		}
	}
	f.open()
}
