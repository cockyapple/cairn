package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cockyapple/cairn/ledger"
)

func TestPublishedTestKeysMatchTheVectorFile(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/vectors-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Keys []struct{ Name, Public string } `json:"keys"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	known := publishedTestKeys()
	if len(v.Keys) != len(testKeyNames) || len(known) != len(testKeyNames) {
		t.Fatalf("vector file has %d keys, checker lists %d", len(v.Keys), len(testKeyNames))
	}
	for _, k := range v.Keys {
		b, _ := hex.DecodeString(k.Public)
		var p [32]byte
		copy(p[:], b)
		if known[p] != k.Name {
			t.Errorf("key %q from the vector file is not recognised as a published test key", k.Name)
		}
	}
}

func TestGenesisPin(t *testing.T) {
	f := build(t, "agent")
	raw, _ := os.ReadFile(f.entries)
	entries, err := ledger.DecodeChain([][]byte{raw[:ledger.EntrySize], raw[ledger.EntrySize:]})
	if err != nil {
		t.Fatal(err)
	}
	good := hexOf(entries[0].Hash())

	code, out := do("-entries", f.entries, "-blobs", f.blobs, "-checkpoint", f.cp, "-genesis", good)
	if code != 0 || !strings.Contains(out, "ok genesis") || !strings.Contains(out, "starts at the genesis you pinned") {
		t.Errorf("correct pin: exit %d\n%s", code, out)
	}
	if strings.Contains(out, "without a genesis you pinned yourself") {
		t.Errorf("a pinned run must not say it was unpinned:\n%s", out)
	}

	code, out = do("-entries", f.entries, "-blobs", f.blobs, "-genesis", strings.Repeat("0", 64))
	if code != 1 || !strings.Contains(out, "FAIL wrong_genesis") {
		t.Errorf("wrong pin: exit %d\n%s", code, out)
	}
	// a wrong pin must fail even with no -blobs, where governance is skipped
	code, out = do("-entries", f.entries, "-genesis", strings.Repeat("0", 64))
	if code != 1 || !strings.Contains(out, "wrong_genesis") {
		t.Errorf("wrong pin without blobs: exit %d\n%s", code, out)
	}
	for _, bad := range []string{"zz", strings.Repeat("a", 63), strings.Repeat("a", 66)} {
		if code, out = do("-entries", f.entries, "-genesis", bad); code != 2 {
			t.Errorf("-genesis %q: exit %d, want 2\n%s", bad, code, out)
		}
	}
}

func atTime(t *testing.T, unix int64) {
	t.Helper()
	old := now
	now = func() time.Time { return time.Unix(unix, 0) }
	t.Cleanup(func() { now = old })
}

func TestMaxAge(t *testing.T) {
	f := build(t, "agent") // newest covered entry is dated 1001
	atTime(t, 1001+3600)

	code, out := do("-entries", f.entries, "-blobs", f.blobs, "-checkpoint", f.cp, "-max-age", "2h")
	if code != 0 || !strings.Contains(out, "ok age:") {
		t.Errorf("fresh enough: exit %d\n%s", code, out)
	}
	code, out = do("-entries", f.entries, "-blobs", f.blobs, "-checkpoint", f.cp, "-max-age", "30m")
	if code != 1 || !strings.Contains(out, "FAIL stale_checkpoint") {
		t.Errorf("too old: exit %d\n%s", code, out)
	}
	// exactly at the limit passes; one second past fails
	code, _ = do("-entries", f.entries, "-blobs", f.blobs, "-checkpoint", f.cp, "-max-age", "1h")
	if code != 0 {
		t.Errorf("age equal to the limit should pass, exit %d", code)
	}
	atTime(t, 1001+3601)
	if code, _ = do("-entries", f.entries, "-blobs", f.blobs, "-checkpoint", f.cp, "-max-age", "1h"); code != 1 {
		t.Errorf("one second over the limit should fail, exit %d", code)
	}
	// a clock far behind the log is reported, not passed
	atTime(t, 10)
	code, out = do("-entries", f.entries, "-blobs", f.blobs, "-checkpoint", f.cp, "-max-age", "1h")
	if code != 1 || !strings.Contains(out, "FAIL future_dated") {
		t.Errorf("entry dated ahead of the clock: exit %d\n%s", code, out)
	}
}

func TestMaxAgeUsageErrors(t *testing.T) {
	f := build(t, "agent")
	for name, args := range map[string][]string{
		"no head to date": {"-entries", f.entries, "-blobs", f.blobs, "-max-age", "1h"},
		"negative":        {"-entries", f.entries, "-blobs", f.blobs, "-checkpoint", f.cp, "-max-age", "-1h"},
		"no blobs":        {"-entries", f.entries, "-checkpoint", f.cp, "-max-age", "1h"},
	} {
		if code, out := do(args...); code != 2 {
			t.Errorf("%s: exit %d, want 2\n%s", name, code, out)
		}
	}
}

func TestWeakConfigurationsWarnButDoNotFail(t *testing.T) {
	f := build(t, "agent") // one validator, threshold 0, ordinary (non-published) keys
	code, out := do("-entries", f.entries, "-blobs", f.blobs, "-checkpoint", f.cp)
	if code != 0 {
		t.Fatalf("warnings must not fail the run: exit %d\n%s", code, out)
	}
	for _, want := range []string{"warn: this log has a single validator", "warn: the witness threshold is 0"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "published test key") {
		t.Errorf("fixture keys are not published test keys:\n%s", out)
	}
}

func TestTrustWarningsNameAPublishedTestKey(t *testing.T) {
	var founder, other [32]byte
	for p, n := range publishedTestKeys() {
		if n == "founder" {
			founder = p
		}
	}
	other[0] = 9
	w := trustWarnings(ledger.TrustConfig{WitnessThreshold: 1, Keys: []ledger.Key{
		{Role: ledger.RoleValidator, Public: founder},
		{Role: ledger.RoleValidator, Public: other},
	}})
	if len(w) != 1 || !strings.Contains(w[0], `"founder"`) || !strings.Contains(w[0], "validator") {
		t.Errorf("want one warning naming the founder key, got %v", w)
	}
	if got := trustWarnings(ledger.TrustConfig{WitnessThreshold: 1, Keys: []ledger.Key{
		{Role: ledger.RoleValidator, Public: other}, {Role: ledger.RoleValidator, Public: [32]byte{8}},
	}}); len(got) != 0 {
		t.Errorf("a sound configuration should not warn: %v", got)
	}
}
