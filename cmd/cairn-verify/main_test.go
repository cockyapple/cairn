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
	"github.com/cockyapple/cairn/note"
)

func testKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("cairn-verify-cli-" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func pub(k ed25519.PrivateKey) (p [32]byte) { copy(p[:], k.Public().(ed25519.PublicKey)); return }

type fixture struct {
	dir     string
	entries string
	blobs   string
	cp      string
	constit string
}

// build writes a two-entry log: genesis by the validator, then an ACTION by
// actor ("agent" is lawful, "val" is a validator acting outside its role).
func build(t *testing.T, actor string) fixture {
	t.Helper()
	val, agent := testKey("val"), testKey("agent")
	cons := ledger.BlobHash([]byte("constitution"))
	trust := ledger.TrustConfig{Keys: []ledger.Key{
		{Role: ledger.RoleValidator, Public: pub(val)},
		{Role: ledger.RoleAgent, Public: pub(agent)},
	}}
	g := ledger.Genesis{SpecVersion: 1, ConstitutionHash: cons, Trust: trust}
	a := ledger.Action{ActionType: "tool_call", ArgsHash: ledger.BlobHash([]byte("args"))}

	f := fixture{dir: t.TempDir()}
	f.blobs = filepath.Join(f.dir, "blobs")
	if err := os.Mkdir(f.blobs, 0o755); err != nil {
		t.Fatal(err)
	}
	var entries []ledger.Entry
	add := func(kind ledger.Kind, key ed25519.PrivateKey, payload []byte) {
		e := ledger.Entry{Height: uint64(len(entries)), Kind: kind, PayloadHash: ledger.BlobHash(payload), Time: 1000 + uint64(len(entries))}
		if len(entries) > 0 {
			e.PrevHash = entries[len(entries)-1].Hash()
		}
		e.Sign(key)
		entries = append(entries, e)
		if err := os.WriteFile(filepath.Join(f.blobs, "p"+string(rune('a'+len(entries)))), payload, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	add(ledger.KindGenesis, val, g.Encode())
	actorKey := agent
	if actor == "val" {
		actorKey = val
	}
	add(ledger.KindAction, actorKey, a.Encode())

	var raw []byte
	for i := range entries {
		raw = append(raw, entries[i].Encode()...)
	}
	f.entries = filepath.Join(f.dir, "log.bin")
	if err := os.WriteFile(f.entries, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	sc := ledger.SignedCheckpoint{Checkpoint: ledger.NewCheckpoint(0, entries)}
	sc.Cosign(val)
	f.cp = filepath.Join(f.dir, "cp.bin")
	if err := os.WriteFile(f.cp, sc.Encode(), 0o644); err != nil {
		t.Fatal(err)
	}
	f.constit = hexOf(cons)
	return f
}

func hexOf(h ledger.Hash) string {
	const d = "0123456789abcdef"
	var b strings.Builder
	for _, c := range h {
		b.WriteByte(d[c>>4])
		b.WriteByte(d[c&15])
	}
	return b.String()
}

func do(args ...string) (int, string) {
	var out, errw bytes.Buffer
	code := run(args, &out, &errw)
	return code, out.String() + errw.String()
}

func TestVerifiesALawfulLog(t *testing.T) {
	f := build(t, "agent")
	code, out := do("-entries", f.entries, "-blobs", f.blobs, "-checkpoint", f.cp, "-constitution", f.constit)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	for _, want := range []string{"ok chain: 2 entries", "ok governance", "1 open intents", "ok checkpoint: size 2"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if !strings.HasSuffix(out, "not proof of what any agent did, that its payloads are true, or that any agent is safe.\n") {
		t.Errorf("a pass must end with the scope notice:\n%s", out)
	}
}

func TestChainOnlyWithoutBlobs(t *testing.T) {
	f := build(t, "agent")
	code, out := do("-entries", f.entries)
	if code != 0 || !strings.Contains(out, "skipped governance") {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(out, "That is not proof of lawful governance") {
		t.Errorf("a chain-only pass must say governance was not checked:\n%s", out)
	}
}

func TestGovernanceViolationIsNamed(t *testing.T) {
	f := build(t, "val")
	code, out := do("-entries", f.entries, "-blobs", f.blobs)
	if code != 1 || !strings.Contains(out, "FAIL unauthorized_author") {
		t.Fatalf("exit %d: %s", code, out)
	}
	if strings.Contains(out, "note:") {
		t.Errorf("a failure must not print the scope notice:\n%s", out)
	}
}

func TestTamperedEntryFails(t *testing.T) {
	f := build(t, "agent")
	raw, _ := os.ReadFile(f.entries)
	raw[ledger.EntrySize+10] ^= 1
	os.WriteFile(f.entries, raw, 0o644)
	code, out := do("-entries", f.entries, "-blobs", f.blobs)
	if code != 1 || !strings.Contains(out, "FAIL bad_prev_hash") && !strings.Contains(out, "FAIL bad_signature") {
		t.Fatalf("exit %d: %s", code, out)
	}
}

func TestWrongConstitutionFails(t *testing.T) {
	f := build(t, "agent")
	code, out := do("-entries", f.entries, "-blobs", f.blobs, "-constitution", strings.Repeat("00", 32))
	if code != 1 || !strings.Contains(out, "FAIL constitution_mismatch") {
		t.Fatalf("exit %d: %s", code, out)
	}
}

func TestTamperedCheckpointFails(t *testing.T) {
	f := build(t, "agent")
	raw, _ := os.ReadFile(f.cp)
	raw[20] ^= 1
	os.WriteFile(f.cp, raw, 0o644)
	code, out := do("-entries", f.entries, "-blobs", f.blobs, "-checkpoint", f.cp)
	if code != 1 || !strings.Contains(out, "FAIL") {
		t.Fatalf("exit %d: %s", code, out)
	}
}

func TestTruncatedEntriesFile(t *testing.T) {
	f := build(t, "agent")
	raw, _ := os.ReadFile(f.entries)
	os.WriteFile(f.entries, raw[:len(raw)-1], 0o644)
	code, out := do("-entries", f.entries)
	if code != 1 || !strings.Contains(out, "FAIL bad_length") {
		t.Fatalf("exit %d: %s", code, out)
	}
}

func TestUsageErrors(t *testing.T) {
	if code, _ := do(); code != 2 {
		t.Errorf("no args: exit %d", code)
	}
	f := build(t, "agent")
	if code, _ := do("-entries", f.entries, "-checkpoint", f.cp); code != 2 {
		t.Errorf("checkpoint without blobs: exit %d", code)
	}
	if code, _ := do("-entries", f.entries, "-blobs", f.blobs, "-constitution", "xyz"); code != 2 {
		t.Errorf("bad constitution hex: exit %d", code)
	}
	if code, _ := do("-entries", filepath.Join(f.dir, "missing")); code != 2 {
		t.Errorf("missing file: exit %d", code)
	}
}

func TestLoadBlobsRefusesMoreThanTheTotalCap(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a", "b"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("12345678"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := maxBlobTotal
	maxBlobTotal = 10
	defer func() { maxBlobTotal = old }()
	if _, err := loadBlobs(dir); err == nil || !strings.Contains(err.Error(), "add up to more than") {
		t.Fatalf("want a total-size refusal, got %v", err)
	}
}

func writeNote(t *testing.T, f fixture, origin string, tamperRoot bool) string {
	t.Helper()
	raw, _ := os.ReadFile(f.entries)
	var enc [][]byte
	for i := 0; i < len(raw); i += ledger.EntrySize {
		enc = append(enc, raw[i:i+ledger.EntrySize])
	}
	entries, err := ledger.DecodeChain(enc)
	if err != nil {
		t.Fatal(err)
	}
	cp := ledger.NewCheckpoint(0, entries)
	if tamperRoot {
		cp.Root[0] ^= 1
	}
	text, err := note.Text("cairn.test/log", cp.Size, cp.Root)
	if err != nil {
		t.Fatal(err)
	}
	l, err := note.SignValidator(testKey("val"), origin, text)
	if err != nil {
		t.Fatal(err)
	}
	n, err := note.Assemble(text, l)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(f.dir, "cp.note")
	if err := os.WriteFile(p, n, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVerifiesANote(t *testing.T) {
	f := build(t, "agent")
	n := writeNote(t, f, "cairn.test/log", false)
	code, out := do("-entries", f.entries, "-blobs", f.blobs, "-note", n, "-origin", "cairn.test/log")
	if code != 0 || !strings.Contains(out, "ok note: size 2, 1 validator signatures and 0 witness") {
		t.Fatalf("exit %d: %s", code, out)
	}
	if !strings.Contains(out, "note: this log followed its governance rules and carries signatures") {
		t.Errorf("a note pass must end with the scope notice:\n%s", out)
	}
}

func TestNoteFailuresAreNamed(t *testing.T) {
	f := build(t, "agent")
	good := writeNote(t, f, "cairn.test/log", false)
	args := func(n, origin string) []string {
		return []string{"-entries", f.entries, "-blobs", f.blobs, "-note", n, "-origin", origin}
	}
	if code, out := do(args(good, "other.test/log")...); code != 1 || !strings.Contains(out, "FAIL origin_mismatch") {
		t.Errorf("wrong origin: exit %d: %s", code, out)
	}
	wrongRoot := writeNote(t, f, "cairn.test/log", true)
	if code, out := do(args(wrongRoot, "cairn.test/log")...); code != 1 || !strings.Contains(out, "FAIL root_mismatch") {
		t.Errorf("wrong root: exit %d: %s", code, out)
	}
	raw, _ := os.ReadFile(good)
	raw[len(raw)-5] ^= 1
	os.WriteFile(good, raw, 0o644)
	if code, out := do(args(good, "cairn.test/log")...); code != 1 || !strings.Contains(out, "FAIL") {
		t.Errorf("tampered note: exit %d: %s", code, out)
	}
}

func TestNoteUsageErrors(t *testing.T) {
	f := build(t, "agent")
	n := writeNote(t, f, "cairn.test/log", false)
	if code, _ := do("-entries", f.entries, "-note", n, "-origin", "cairn.test/log"); code != 2 {
		t.Errorf("note without blobs: exit %d", code)
	}
	if code, _ := do("-entries", f.entries, "-blobs", f.blobs, "-note", n); code != 2 {
		t.Errorf("note without origin: exit %d", code)
	}
	if code, _ := do("-entries", f.entries, "-blobs", f.blobs, "-note", n, "-origin", "o", "-witness", "nope"); code != 2 {
		t.Errorf("bad witness flag: exit %d", code)
	}
	if code, _ := do("-entries", f.entries, "-blobs", f.blobs, "-note", filepath.Join(f.dir, "missing"), "-origin", "o"); code != 2 {
		t.Errorf("missing note: exit %d", code)
	}
}

func TestReadCappedRefusesAnOversizedFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big")
	if err := os.WriteFile(p, make([]byte, 11), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCapped(p, 10); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("want a size refusal, got %v", err)
	}
	if b, err := readCapped(p, 11); err != nil || len(b) != 11 {
		t.Fatalf("a file at the cap must load: %v", err)
	}
}

func TestABlobAtTheWireCeilingIsAccepted(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a"), make([]byte, 2<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBlobs(dir); err != nil {
		t.Fatalf("a 2 MiB payload is legal on the wire and must load: %v", err)
	}
}

func TestLoadBlobsCountsFilesNotDistinctContents(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 8; i++ {
		if err := os.WriteFile(filepath.Join(dir, "f"+string(rune('a'+i))), []byte("same"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := maxBlobs
	maxBlobs = 5
	defer func() { maxBlobs = old }()
	if _, err := loadBlobs(dir); err == nil {
		t.Fatal("eight files passed a limit of five because they hold one distinct blob")
	}
}

func TestMinTierFlagRefusesALowTierProposal(t *testing.T) {
	val, prop := testKey("val"), testKey("prop")
	trust := ledger.TrustConfig{Keys: []ledger.Key{
		{Role: ledger.RoleValidator, Public: pub(val)},
		{Role: ledger.RoleProposer, Public: pub(prop)},
	}}
	g := ledger.Genesis{SpecVersion: 1, ConstitutionHash: ledger.BlobHash([]byte("c")), Trust: trust}
	p := ledger.Proposal{Tier: ledger.T0, Target: "agent/app", DiffHash: ledger.BlobHash([]byte("d"))}
	dir := t.TempDir()
	blobs := filepath.Join(dir, "blobs")
	if err := os.Mkdir(blobs, 0o755); err != nil {
		t.Fatal(err)
	}
	var entries []ledger.Entry
	var raw []byte
	for i, s := range []struct {
		kind ledger.Kind
		key  ed25519.PrivateKey
		pl   []byte
	}{{ledger.KindGenesis, val, g.Encode()}, {ledger.KindProposal, prop, p.Encode()}} {
		e := ledger.Entry{Height: uint64(i), Kind: s.kind, PayloadHash: ledger.BlobHash(s.pl), Time: 1000 + uint64(i)}
		if i > 0 {
			e.PrevHash = entries[i-1].Hash()
		}
		e.Sign(s.key)
		entries = append(entries, e)
		raw = append(raw, e.Encode()...)
		if err := os.WriteFile(filepath.Join(blobs, hexOf(ledger.BlobHash(s.pl))), s.pl, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	log := filepath.Join(dir, "log.bin")
	if err := os.WriteFile(log, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out := do("-entries", log, "-blobs", blobs); code != 0 {
		t.Fatalf("without a floor: exit %d: %s", code, out)
	}
	if code, out := do("-entries", log, "-blobs", blobs, "-min-tier", "0"); code != 0 {
		t.Fatalf("floor 0: exit %d: %s", code, out)
	}
	if code, out := do("-entries", log, "-blobs", blobs, "-min-tier", "1"); code != 1 || !strings.Contains(out, "FAIL tier_too_low") {
		t.Fatalf("floor 1: exit %d: %s", code, out)
	}
	for _, bad := range []string{"-1", "5", "x"} {
		if code, _ := do("-entries", log, "-blobs", blobs, "-min-tier", bad); code != 2 {
			t.Errorf("-min-tier %s: exit %d, want 2", bad, code)
		}
	}
}

func TestScopeNoticeDoesNotCallAnUnanchoredLogAuthentic(t *testing.T) {
	f := build(t, "agent")
	code, out := do("-entries", f.entries, "-blobs", f.blobs)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out)
	}
	if strings.Contains(out, "authentic") || !strings.Contains(out, "no checkpoint or note was verified") {
		t.Errorf("a pass with no checkpoint or note must say it is not anchored:\n%s", out)
	}
}
