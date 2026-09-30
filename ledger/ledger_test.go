package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
)

func testKey(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("cairn-test-key-" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func pub(k ed25519.PrivateKey) (p [32]byte) { copy(p[:], k.Public().(ed25519.PublicKey)); return }

func TestEntrySizeAndRoundTrip(t *testing.T) {
	k := testKey("a")
	e := Entry{Height: 3, Kind: KindAction, Time: 99}
	e.PrevHash[0], e.PayloadHash[5] = 1, 2
	e.Sign(k)
	b := e.Encode()
	if len(b) != EntrySize {
		t.Fatalf("encoded %d bytes, want %d", len(b), EntrySize)
	}
	got, err := DecodeEntry(b)
	if err != nil || got != e {
		t.Fatalf("round trip failed: %v", err)
	}
	if !got.VerifySignature() {
		t.Fatal("signature should verify")
	}
}

func TestDecodeEntryRejectsGarbage(t *testing.T) {
	k := testKey("a")
	e := Entry{Kind: KindGenesis}
	e.Sign(k)
	good := e.Encode()

	for n := 0; n < EntrySize; n++ {
		if _, err := DecodeEntry(good[:n]); ErrCode(err) != CodeBadLength {
			t.Fatalf("len %d: got %v", n, err)
		}
	}
	if _, err := DecodeEntry(append(append([]byte{}, good...), 0)); ErrCode(err) != CodeBadLength {
		t.Fatal("trailing byte must be rejected")
	}
	bad := append([]byte{}, good...)
	bad[0] = 2
	if _, err := DecodeEntry(bad); ErrCode(err) != CodeBadVersion {
		t.Fatal("version must be checked")
	}
	bad = append([]byte{}, good...)
	bad[1+8+32] = 200 // kind byte
	if _, err := DecodeEntry(bad); ErrCode(err) != CodeUnknownKind {
		t.Fatal("unknown kind must be rejected")
	}
}

func TestEveryBitFlipBreaksSignature(t *testing.T) {
	k := testKey("a")
	e := Entry{Height: 1, Kind: KindVote, Time: 5}
	e.Sign(k)
	good := e.Encode()
	for i := 0; i < len(good)*8; i++ {
		b := append([]byte{}, good...)
		b[i/8] ^= 1 << (i % 8)
		d, err := DecodeEntry(b)
		if err != nil {
			continue // structurally rejected, also fine
		}
		if d.VerifySignature() {
			t.Fatalf("flipping bit %d still verifies", i)
		}
	}
}

func TestSignatureDomainSeparation(t *testing.T) {
	k := testKey("a")
	e := Entry{Kind: KindGenesis}
	e.Sign(k)
	if ed25519.Verify(k.Public().(ed25519.PublicKey), e.signingBytes(), e.Signature[:]) {
		t.Fatal("signature must not verify without the domain tag")
	}
}

func TestMerkleKnownShapes(t *testing.T) {
	if MerkleRoot(nil) != sha256.Sum256(nil) {
		t.Fatal("empty root")
	}
	a, b, c := []byte("a"), []byte("b"), []byte("c")
	if MerkleRoot([][]byte{a}) != leafHash(a) {
		t.Fatal("single leaf")
	}
	if MerkleRoot([][]byte{a, b}) != nodeHash(leafHash(a), leafHash(b)) {
		t.Fatal("two leaves")
	}
	want := nodeHash(nodeHash(leafHash(a), leafHash(b)), leafHash(c))
	if MerkleRoot([][]byte{a, b, c}) != want {
		t.Fatal("three leaves must split 2|1")
	}
}

func TestMerkleLeafNodeSeparation(t *testing.T) {
	a, b := []byte("a"), []byte("b")
	l, r := leafHash(a), leafHash(b)
	forged := append(append([]byte{}, l[:]...), r[:]...)
	if MerkleRoot([][]byte{forged}) == MerkleRoot([][]byte{a, b}) {
		t.Fatal("a leaf must never collide with an interior node")
	}
}

func TestValidatorQuorum(t *testing.T) {
	want := map[int]int{0: 0, 1: 1, 2: 2, 3: 3, 4: 3, 5: 4, 6: 5, 7: 5, 10: 7}
	for n, q := range want {
		if got := ValidatorQuorum(n); got != q {
			t.Errorf("n=%d got %d want %d", n, got, q)
		}
	}
	// any two quorums must overlap by at least f+1 members
	for n := 1; n <= 40; n++ {
		f := (n - 1) / 3
		if 2*ValidatorQuorum(n)-n < f+1 {
			t.Errorf("n=%d quorums may overlap in only faulty nodes", n)
		}
	}
}

func TestPayloadRoundTrips(t *testing.T) {
	h := BlobHash([]byte("x"))
	tc := TrustConfig{Epoch: 2, WitnessThreshold: 1, Keys: []Key{
		{RoleValidator, pub(testKey("v"))}, {RoleWitness, pub(testKey("w"))}}}
	g := Genesis{SpecVersion: SpecVersion, ConstitutionHash: h, Trust: tc}
	if d, err := DecodeGenesis(g.Encode()); err != nil || !bytes.Equal(d.Encode(), g.Encode()) {
		t.Fatalf("genesis: %v", err)
	}
	p := Proposal{Tier: T2, Target: "tools/allow", DiffHash: h, RationaleHash: h}
	if d, err := DecodeProposal(p.Encode()); err != nil || d != p {
		t.Fatalf("proposal: %v", err)
	}
	v := Vote{ProposalHash: h, Verdict: VerdictApprove, CommentHash: h}
	if d, err := DecodeVote(v.Encode()); err != nil || d != v {
		t.Fatalf("vote: %v", err)
	}
	a := Activate{ProposalHash: h, VoteHashes: []Hash{h, h}, EffectiveAfter: 7}
	if d, err := DecodeActivate(a.Encode()); err != nil || !bytes.Equal(d.Encode(), a.Encode()) {
		t.Fatalf("activate: %v", err)
	}
	ac := Action{ActionType: "tool_call", ArgsHash: h, ResultHash: h}
	if d, err := DecodeAction(ac.Encode()); err != nil || d != ac {
		t.Fatalf("action: %v", err)
	}
	f := Freeze{Scope: FreezeActivations, ReasonHash: h}
	if d, err := DecodeFreeze(f.Encode()); err != nil || d != f {
		t.Fatalf("freeze: %v", err)
	}
}

func TestPayloadRejectsBadValues(t *testing.T) {
	if _, err := DecodeProposal((&Proposal{Tier: 9}).Encode()); ErrCode(err) != CodeBadPayload {
		t.Fatal("tier 9")
	}
	if _, err := DecodeVote((&Vote{Verdict: 0}).Encode()); ErrCode(err) != CodeBadPayload {
		t.Fatal("verdict 0")
	}
	if _, err := DecodeFreeze((&Freeze{Scope: 9}).Encode()); ErrCode(err) != CodeBadPayload {
		t.Fatal("scope 9")
	}
	if _, err := DecodeActivate([]byte{1, 2, 3}); ErrCode(err) != CodeBadPayload {
		t.Fatal("short activate")
	}
	// a vote-count far larger than the input must fail without allocating it
	huge := append(make([]byte, 32), 0xff, 0xff, 0xff, 0xff)
	if _, err := DecodeActivate(huge); ErrCode(err) != CodeBadPayload {
		t.Fatal("hostile count")
	}
}

func TestTrustConfigRules(t *testing.T) {
	v, w := pub(testKey("v")), pub(testKey("w"))
	cases := map[string]TrustConfig{
		"no validator":          {Keys: []Key{{RoleWitness, w}}},
		"duplicate key":         {Keys: []Key{{RoleValidator, v}, {RoleWitness, v}}},
		"threshold > witnesses": {Keys: []Key{{RoleValidator, v}}, WitnessThreshold: 1},
		"bad role":              {Keys: []Key{{RoleValidator, v}, {Role(9), w}}},
	}
	for name, tc := range cases {
		if _, err := DecodeTrustConfig(tc.Encode()); ErrCode(err) != CodeBadTrustConfig {
			t.Errorf("%s: got %v", name, err)
		}
	}
}
