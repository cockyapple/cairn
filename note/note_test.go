package note

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/cockyapple/cairn/ledger"
)

const origin = "cairn.example/log"

func key(name string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("note-test/" + name))
	return ed25519.NewKeyFromSeed(s[:])
}

func pub(k ed25519.PrivateKey) (p [32]byte) { copy(p[:], k.Public().(ed25519.PublicKey)); return }

// The signed-note spec's own example: an independent implementation's output,
// not ours.
const (
	specVKey = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
	specNote = "This is an example message.\n\n— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n"
)

func TestSpecExampleVerifies(t *testing.T) {
	name, typ, pk, err := ParseVKey(specVKey)
	if err != nil || name != "example.com/foo" || typ != SigEd25519 {
		t.Fatalf("vkey did not parse: %v %q %d", err, name, typ)
	}
	text, lines, err := splitNote([]byte(specNote))
	if err != nil || len(lines) != 1 {
		t.Fatalf("split: %v", err)
	}
	n, payload, err := parseSigLine(lines[0])
	if err != nil || n != name {
		t.Fatalf("sig line: %v", err)
	}
	if id := KeyID(name, typ, pk); string(payload[:4]) != string(id[:]) {
		t.Fatal("key id derived by us differs from the spec's")
	}
	s := signer{pk, ledger.RoleValidator}
	if !sigOK(s, payload[4:], text) {
		t.Fatal("the spec's example signature does not verify")
	}
	bad := append([]byte(nil), text...)
	bad[0] ^= 1
	if sigOK(s, payload[4:], bad) {
		t.Fatal("a modified text verified")
	}
	got, err := VKey(name, typ, pk)
	if err != nil || got != specVKey {
		t.Fatalf("VKey round trip: %v %q", err, got)
	}
}

type fixture struct {
	vals, wits []ed25519.PrivateKey
	trust      ledger.TrustConfig
	cfg        Config
	root       ledger.Hash
}

// 4 validators (quorum 3), 2 witnesses (threshold 1), 1 agent.
func newFixture() *fixture {
	f := &fixture{cfg: Config{Origin: origin, WitnessNames: map[[32]byte]string{}}}
	for _, n := range []string{"v1", "v2", "v3", "v4"} {
		k := key(n)
		f.vals = append(f.vals, k)
		f.trust.Keys = append(f.trust.Keys, ledger.Key{Role: ledger.RoleValidator, Public: pub(k)})
	}
	for _, n := range []string{"w1", "w2"} {
		k := key(n)
		f.wits = append(f.wits, k)
		f.trust.Keys = append(f.trust.Keys, ledger.Key{Role: ledger.RoleWitness, Public: pub(k)})
		f.cfg.WitnessNames[pub(k)] = "witness.example/" + n
	}
	f.trust.Keys = append(f.trust.Keys, ledger.Key{Role: ledger.RoleAgent, Public: pub(key("agent"))})
	f.trust.WitnessThreshold = 1
	f.root = sha256.Sum256([]byte("root"))
	return f
}

func (f *fixture) text(t *testing.T, size uint64) []byte {
	t.Helper()
	b, err := Text(origin, size, f.root)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *fixture) vline(t *testing.T, i int, text []byte) string {
	t.Helper()
	l, err := SignValidator(f.vals[i], origin, text)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func (f *fixture) wline(t *testing.T, i int, text []byte) string {
	t.Helper()
	l, err := Cosign(f.wits[i], f.cfg.WitnessNames[pub(f.wits[i])], 1700000000+uint64(i), text)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func (f *fixture) note(t *testing.T, text []byte, lines ...string) []byte {
	t.Helper()
	n, err := Assemble(text, lines...)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if got := ledger.ErrCode(err); got != code {
		t.Fatalf("want %s, got %q (%v)", code, got, err)
	}
}

func TestRoundTrip(t *testing.T) {
	f := newFixture()
	text := f.text(t, 7)
	n := f.note(t, text, f.vline(t, 0, text), f.vline(t, 1, text), f.vline(t, 2, text), f.wline(t, 0, text))
	res, err := Verify(n, f.cfg, &f.trust)
	if err != nil || res.Size != 7 || res.Root != f.root || res.Validators != 3 || res.Witnesses != 1 {
		t.Fatalf("verify: %v %+v", err, res)
	}
	o, sz, rt, err := Peek(n)
	if err != nil || o != origin || sz != 7 || rt != f.root {
		t.Fatalf("peek: %v", err)
	}
	// Surplus signers are fine.
	n2 := f.note(t, text, f.vline(t, 0, text), f.vline(t, 1, text), f.vline(t, 2, text), f.vline(t, 3, text), f.wline(t, 0, text), f.wline(t, 1, text))
	if res, err := Verify(n2, f.cfg, &f.trust); err != nil || res.Validators != 4 || res.Witnesses != 2 {
		t.Fatalf("surplus: %v %+v", err, res)
	}
}

func TestAssembleIsDeterministic(t *testing.T) {
	f := newFixture()
	text := f.text(t, 3)
	a, b := f.vline(t, 0, text), f.vline(t, 1, text)
	if string(f.note(t, text, a, b)) != string(f.note(t, text, b, a)) {
		t.Fatal("signature order changed the bytes")
	}
}

func TestQuorumAndThreshold(t *testing.T) {
	f := newFixture()
	text := f.text(t, 5)
	v := []string{f.vline(t, 0, text), f.vline(t, 1, text), f.vline(t, 2, text)}
	_, err := Verify(f.note(t, text, v[0], v[1], f.wline(t, 0, text)), f.cfg, &f.trust)
	wantCode(t, err, ledger.CodeBelowQuorum)
	_, err = Verify(f.note(t, text, v...), f.cfg, &f.trust)
	wantCode(t, err, ledger.CodeBelowWitnesses)
	// An agent key is a known key of the wrong role: it is ignored, not counted.
	ag := key("agent")
	al, _ := SignValidator(ag, origin, text)
	_, err = Verify(f.note(t, text, v[0], v[1], al, f.wline(t, 0, text)), f.cfg, &f.trust)
	wantCode(t, err, ledger.CodeBelowQuorum)
}

func TestUnknownSignersAreIgnoredKnownFailuresReject(t *testing.T) {
	f := newFixture()
	text := f.text(t, 5)
	good := []string{f.vline(t, 0, text), f.vline(t, 1, text), f.vline(t, 2, text), f.wline(t, 0, text)}
	stranger, _ := SignValidator(key("stranger"), origin, text)
	otherLog, _ := SignValidator(key("v4"), "other.example/log", text)
	if _, err := Verify(f.note(t, text, append(good, stranger, otherLog)...), f.cfg, &f.trust); err != nil {
		t.Fatalf("unknown signers must be ignored: %v", err)
	}
	// A known key signing a different text: same name and id, bad signature.
	other := f.text(t, 6)
	forged, _ := SignValidator(f.vals[3], origin, other)
	_, err := Verify(f.note(t, text, append(good, forged)...), f.cfg, &f.trust)
	wantCode(t, err, ledger.CodeBadSignature)
	// A witness cosignature over different text.
	wf := f.wline(t, 1, other)
	_, err = Verify(f.note(t, text, append(good, wf)...), f.cfg, &f.trust)
	wantCode(t, err, ledger.CodeBadSignature)
	// A cosignature whose timestamp was altered no longer verifies.
	_, payload, _ := parseSigLine(strings.TrimSuffix(f.wline(t, 0, text), "\n"))
	payload[4+7] ^= 1
	name := f.cfg.WitnessNames[pub(f.wits[0])]
	tampered := sigPrefix + name + " " + base64.StdEncoding.EncodeToString(payload) + "\n"
	_, err = Verify(f.note(t, text, f.vline(t, 0, text), f.vline(t, 1, text), f.vline(t, 2, text), tampered), f.cfg, &f.trust)
	wantCode(t, err, ledger.CodeBadSignature)
}

func TestDuplicateSignerRejected(t *testing.T) {
	f := newFixture()
	text := f.text(t, 5)
	l := f.vline(t, 0, text)
	_, err := Verify(f.note(t, text, l, l, f.vline(t, 1, text), f.wline(t, 0, text)), f.cfg, &f.trust)
	wantCode(t, err, ledger.CodeDuplicateSigner)
}

func TestValidatorSignatureIsNotACosignature(t *testing.T) {
	f := newFixture()
	text := f.text(t, 5)
	// A witness key signing as a plain note signature under its own name has
	// the wrong key id for its role and is ignored, so the threshold is unmet.
	w := f.cfg.WitnessNames[pub(f.wits[0])]
	l, _ := SignValidator(f.wits[0], w, text)
	_, err := Verify(f.note(t, text, f.vline(t, 0, text), f.vline(t, 1, text), f.vline(t, 2, text), l), f.cfg, &f.trust)
	wantCode(t, err, ledger.CodeBelowWitnesses)
}

func TestTextIsStrict(t *testing.T) {
	f := newFixture()
	r := base64.StdEncoding.EncodeToString(f.root[:])
	cases := map[string]string{
		"extension line":     origin + "\n5\n" + r + "\nextra\n",
		"leading zero":       origin + "\n05\n" + r + "\n",
		"plus sign":          origin + "\n+5\n" + r + "\n",
		"zero size":          origin + "\n0\n" + r + "\n",
		"short root":         origin + "\n5\n" + base64.StdEncoding.EncodeToString(f.root[:31]) + "\n",
		"url-safe root":      origin + "\n5\n" + strings.NewReplacer("+", "-", "/", "_").Replace(r) + "\n",
		"unpadded root":      origin + "\n5\n" + strings.TrimRight(r, "=") + "\n",
		"missing newline":    origin + "\n5\n" + r,
		"empty origin":       "\n5\n" + r + "\n",
		"space in origin":    "a b\n5\n" + r + "\n",
		"plus in origin":     "a+b\n5\n" + r + "\n",
		"size overflow":      origin + "\n18446744073709551616\n" + r + "\n",
		"blank in the text":  origin + "\n\n5\n" + r + "\n",
		"two-line":           origin + "\n5\n",
		"trailing blank":     origin + "\n5\n" + r + "\n\n",
		"origin over 255 B":  strings.Repeat("a", 256) + "\n5\n" + r + "\n",
		"noncanonical b64":   origin + "\n5\n" + r[:len(r)-2] + "B=\n",
		"carriage return":    origin + "\r\n5\n" + r + "\n",
		"cr inside root":     origin + "\n5\n" + r[:10] + "\r" + r[10:] + "\n",
		"origin with a NBSP": "a b\n5\n" + r + "\n",
	}
	for name, txt := range cases {
		if _, _, _, err := parseText([]byte(txt)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, _, _, err := parseText([]byte(origin + "\n5\n" + r + "\n")); err != nil {
		t.Fatalf("canonical text rejected: %v", err)
	}
}

func TestNoteFramingIsStrict(t *testing.T) {
	f := newFixture()
	text := f.text(t, 5)
	l := f.vline(t, 0, text)
	good := string(text) + "\n" + l
	if _, _, err := splitNote([]byte(good)); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"no blank line":      string(text) + l,
		"no signatures":      string(text) + "\n",
		"unterminated sig":   strings.TrimSuffix(good, "\n"),
		"hyphen not dash":    string(text) + "\n- " + strings.TrimPrefix(l, sigPrefix),
		"no space after":     string(text) + "\n—" + strings.TrimPrefix(l, sigPrefix),
		"bad utf8":           good + "\xff",
		"control char":       string(text) + "\n" + strings.Replace(l, "cairn", "ca\x01rn", 1),
		"tab in text":        strings.Replace(good, origin, "ca\tirn", 1),
		"cr inside sig":      string(text) + "\n" + l[:20] + "\r" + l[20:],
		"two spaces":         string(text) + "\n— a  b\n",
		"empty b64":          string(text) + "\n— a \n",
		"short payload":      string(text) + "\n— a " + base64.StdEncoding.EncodeToString([]byte{1, 2, 3}) + "\n",
		"unpadded b64":       string(text) + "\n" + strings.TrimSuffix(l, "=\n") + "\n",
		"huge":               good + strings.Repeat("x", maxNote),
		"too many sig lines": string(text) + "\n" + strings.Repeat(l, maxSigLines+1),
	}
	for name, raw := range cases {
		_, lines, err := splitNote([]byte(raw))
		if err == nil {
			for _, ln := range lines {
				if _, _, err = parseSigLine(ln); err != nil {
					break
				}
			}
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOriginMismatchAndConfig(t *testing.T) {
	f := newFixture()
	text := f.text(t, 5)
	n := f.note(t, text, f.vline(t, 0, text), f.vline(t, 1, text), f.vline(t, 2, text), f.wline(t, 0, text))
	cfg := f.cfg
	cfg.Origin = "someone.else/log"
	_, err := Verify(n, cfg, &f.trust)
	wantCode(t, err, CodeOriginMismatch)
	cfg.Origin = ""
	_, err = Verify(n, cfg, &f.trust)
	wantCode(t, err, CodeBadOrigin)
	_, err = Verify(n, f.cfg, nil)
	wantCode(t, err, ledger.CodeBadTrustConfig)
	bad := f.trust
	bad.WitnessThreshold = 9
	_, err = Verify(n, f.cfg, &bad)
	wantCode(t, err, ledger.CodeBadTrustConfig)
	// A witness the config gives no name is unusable.
	cfg = f.cfg
	cfg.WitnessNames = nil
	_, err = Verify(n, cfg, &f.trust)
	wantCode(t, err, ledger.CodeBelowWitnesses)
}

func TestSignersRejectBadInput(t *testing.T) {
	f := newFixture()
	text := f.text(t, 5)
	if _, err := SignValidator(ed25519.PrivateKey{1, 2}, origin, text); err == nil {
		t.Error("short private key accepted")
	}
	if _, err := Cosign(nil, "w", 1, text); err == nil {
		t.Error("nil private key accepted")
	}
	if _, err := SignValidator(f.vals[0], "has space", text); err == nil {
		t.Error("bad origin accepted")
	}
	if _, err := Cosign(f.wits[0], "a+b", 1, text); err == nil {
		t.Error("bad witness name accepted")
	}
	if _, err := Text(origin, 0, f.root); err == nil {
		t.Error("size 0 accepted")
	}
	if _, err := Assemble(text); err == nil {
		t.Error("note with no signatures accepted")
	}
	if _, err := Assemble([]byte("junk\n")); err == nil {
		t.Error("bad text accepted")
	}
	if _, err := Assemble(text, "no newline"); err == nil {
		t.Error("bad line accepted")
	}
}

func TestVKeyRejectsMismatch(t *testing.T) {
	for _, s := range []string{
		"example.com/foo+530d903b+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k",
		"example.com/bar+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k",
		"example.com/foo+530D903A+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k",
		"example.com/foo+530d903a",
		"example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k+x",
		"+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k",
	} {
		if _, _, _, err := ParseVKey(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func genesisLog(t *testing.T, f *fixture, extra int) []ledger.Entry {
	t.Helper()
	g := ledger.Genesis{SpecVersion: ledger.SpecVersion, Trust: f.trust}
	author := key("author")
	e := ledger.Entry{Kind: ledger.KindGenesis, Time: 1700000000, PayloadHash: ledger.BlobHash(g.Encode())}
	copy(e.Author[:], author.Public().(ed25519.PublicKey))
	e.Sign(author)
	log := []ledger.Entry{e}
	for i := 0; i < extra; i++ {
		n := ledger.Entry{Height: uint64(len(log)), PrevHash: log[len(log)-1].Hash(), Kind: ledger.KindAction,
			PayloadHash: ledger.BlobHash([]byte{byte(i)}), Author: e.Author, Time: 1700000001 + uint64(i)}
		n.Sign(author)
		log = append(log, n)
	}
	return log
}

func TestVerifyLogBindsNoteToEntries(t *testing.T) {
	f := newFixture()
	log := genesisLog(t, f, 4)
	cp := ledger.NewCheckpoint(0, log)
	text, _ := Text(origin, cp.Size, cp.Root)
	n := f.note(t, text, f.vline(t, 0, text), f.vline(t, 1, text), f.vline(t, 2, text), f.wline(t, 1, text))
	if res, err := VerifyLog(log, n, f.cfg, &f.trust); err != nil || res.Size != 5 {
		t.Fatalf("verify log: %v", err)
	}
	// Validly signed, but over a different size or root than the entries give.
	_, err := VerifyLog(log[:4], n, f.cfg, &f.trust)
	wantCode(t, err, ledger.CodeSizeMismatch)
	f.root[0] ^= 1
	wrong := f.text(t, cp.Size)
	n2 := f.note(t, wrong, f.vline(t, 0, wrong), f.vline(t, 1, wrong), f.vline(t, 2, wrong), f.wline(t, 1, wrong))
	_, err = VerifyLog(log, n2, f.cfg, &f.trust)
	wantCode(t, err, ledger.CodeRootMismatch)
	// A broken chain is caught before the note is trusted.
	broken := append([]ledger.Entry(nil), log...)
	broken[2].PayloadHash[0] ^= 1
	_, err = VerifyLog(broken, n, f.cfg, &f.trust)
	wantCode(t, err, ledger.CodeBadSignature)
}

// The note is a second signature over the same tree head, so a native
// checkpoint and a note built from the same keys must agree.
func TestNoteAndNativeCheckpointAgree(t *testing.T) {
	f := newFixture()
	log := genesisLog(t, f, 3)
	cp := ledger.NewCheckpoint(0, log)
	sc := ledger.SignedCheckpoint{Checkpoint: cp}
	for _, k := range []ed25519.PrivateKey{f.vals[0], f.vals[1], f.vals[2], f.wits[0]} {
		sc.Cosign(k)
	}
	sortSigs(&sc)
	if err := ledger.VerifyLog(log, &sc, &f.trust); err != nil {
		t.Fatalf("native: %v", err)
	}
	text, _ := Text(origin, cp.Size, cp.Root)
	n := f.note(t, text, f.vline(t, 0, text), f.vline(t, 1, text), f.vline(t, 2, text), f.wline(t, 0, text))
	if _, err := VerifyLog(log, n, f.cfg, &f.trust); err != nil {
		t.Fatalf("note: %v", err)
	}
}

func sortSigs(sc *ledger.SignedCheckpoint) {
	for i := 1; i < len(sc.Sigs); i++ {
		for j := i; j > 0 && string(sc.Sigs[j-1].Public[:]) > string(sc.Sigs[j].Public[:]); j-- {
			sc.Sigs[j-1], sc.Sigs[j] = sc.Sigs[j], sc.Sigs[j-1]
		}
	}
}

func FuzzVerify(f *testing.F) {
	fx := newFixture()
	text, _ := Text(origin, 5, fx.root)
	l, _ := SignValidator(fx.vals[0], origin, text)
	n, _ := Assemble(text, l)
	f.Add(n)
	f.Add([]byte(specNote))
	f.Add([]byte(""))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Verify(b, fx.cfg, &fx.trust)
		_, _, _, _ = Peek(b)
	})
}

// A native checkpoint signature input starts with a NUL-bearing domain, so it
// can never be a note text, and a note signature can never be a native one.
func TestNativeSignatureInputCannotBeANoteText(t *testing.T) {
	f := newFixture()
	log := genesisLog(t, f, 1)
	cp := ledger.NewCheckpoint(0, log)
	native := append([]byte("cairn/checkpoint/v1\x00"), cp.Body()...)
	l, _ := SignValidator(f.vals[0], origin, native)
	raw := append(append(append([]byte(nil), native...), '\n'), l...)
	if _, _, err := splitNote(raw); err == nil {
		t.Fatal("a note whose text is a native signature input was accepted")
	}
	if _, err := Assemble(native, l); err == nil {
		t.Fatal("Assemble accepted a native signature input as text")
	}
}
