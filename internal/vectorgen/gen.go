// Package vectorgen builds Cairn's language-neutral test vectors. Every key
// here is derived from a public string and is for TESTING ONLY.
package vectorgen

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/cockyapple/cairn/ledger"
)

type KeyVec struct {
	Name   string `json:"name"`
	Seed   string `json:"seed"`
	Public string `json:"public"`
}

type MerkleVec struct {
	Leaves []string `json:"leaves_hex"`
	Root   string   `json:"root"`
}

type PayloadVec struct {
	Kind     string `json:"kind"`
	Hex      string `json:"hex"`
	BlobHash string `json:"blob_hash"`
}

type EntryVec struct {
	Height    uint64 `json:"height"`
	Kind      string `json:"kind"`
	Author    string `json:"author"`
	Hex       string `json:"hex"`
	EntryHash string `json:"entry_hash"`
}

type ChainCase struct {
	Name       string   `json:"name"`
	EntriesHex []string `json:"entries_hex"`
	Valid      bool     `json:"valid"`
	Error      string   `json:"error,omitempty"`
}

type CheckpointCase struct {
	Name          string   `json:"name"`
	TrustHex      string   `json:"trust_hex"`
	EntriesHex    []string `json:"entries_hex"`
	CheckpointHex string   `json:"checkpoint_hex"`
	Valid         bool     `json:"valid"`
	Error         string   `json:"error,omitempty"`
}

type File struct {
	Version     int               `json:"version"`
	Note        string            `json:"note"`
	Keys        []KeyVec          `json:"keys"`
	Merkle      []MerkleVec       `json:"merkle"`
	Payloads    []PayloadVec      `json:"payloads"`
	MainChain   []EntryVec        `json:"main_chain"`
	MainRoot    string            `json:"main_chain_root"`
	Chains      []ChainCase       `json:"chain_cases"`
	Checkpoints []CheckpointCase  `json:"checkpoint_cases"`
	UseBlobs    []UseVec          `json:"use_blobs"`
	Openings    []OpeningVec      `json:"openings"`
	Locate      []LocateCase      `json:"locate_cases"`
	Inclusion   []InclusionCase   `json:"inclusion_cases"`
	Consistency []ConsistencyCase `json:"consistency_cases"`
}

const baseTime = 1790726400 // 2026-09-30T00:00:00Z

var keyNames = []string{"founder", "v1", "v2", "v3", "v4", "v5", "w1", "w2",
	"r1", "r2", "r3", "s1", "s2", "p1", "a1", "outsider"}

type builder struct {
	keys map[string]ed25519.PrivateKey
}

func newBuilder() *builder {
	b := &builder{keys: map[string]ed25519.PrivateKey{}}
	for _, n := range keyNames {
		seed := sha256.Sum256([]byte("cairn-test-key-" + n))
		b.keys[n] = ed25519.NewKeyFromSeed(seed[:])
	}
	return b
}

func (b *builder) pub(n string) (p [32]byte) {
	copy(p[:], b.keys[n].Public().(ed25519.PublicKey))
	return
}

func (b *builder) trust(epoch uint64, validators ...string) ledger.TrustConfig {
	t := ledger.TrustConfig{Epoch: epoch, WitnessThreshold: 2}
	add := func(role ledger.Role, names ...string) {
		for _, n := range names {
			t.Keys = append(t.Keys, ledger.Key{Role: role, Public: b.pub(n)})
		}
	}
	add(ledger.RoleValidator, validators...)
	add(ledger.RoleWitness, "w1", "w2")
	add(ledger.RoleReviewer, "r1", "r2", "r3")
	add(ledger.RoleSecurityReviewer, "s1", "s2")
	add(ledger.RoleProposer, "p1")
	add(ledger.RoleAgent, "a1")
	return t
}

func (b *builder) entry(height uint64, prev ledger.Hash, kind ledger.Kind, payload []byte, signer string) ledger.Entry {
	e := ledger.Entry{
		Height: height, PrevHash: prev, Kind: kind,
		PayloadHash: ledger.BlobHash(payload), Time: baseTime + height*60,
	}
	e.Sign(b.keys[signer])
	return e
}

func hx(b []byte) string { return hex.EncodeToString(b) }

func hashes(entries []ledger.Entry) []string {
	out := make([]string, len(entries))
	for i := range entries {
		out[i] = hx(entries[i].Encode())
	}
	return out
}

func h(s string) ledger.Hash { return ledger.BlobHash([]byte(s)) }

// Build produces the full vector file deterministically.
func Build() *File {
	b := newBuilder()
	f := &File{
		Version: 1,
		Note:    "TEST VECTORS. Every key is derived from a public string. Never reuse these keys.",
	}
	for _, n := range keyNames {
		seed := sha256.Sum256([]byte("cairn-test-key-" + n))
		p := b.pub(n)
		f.Keys = append(f.Keys, KeyVec{Name: n, Seed: hx(seed[:]), Public: hx(p[:])})
	}

	for n := 0; n <= 9; n++ {
		var leaves [][]byte
		var lh []string
		for i := 0; i < n; i++ {
			l := []byte(fmt.Sprintf("leaf-%d", i))
			leaves = append(leaves, l)
			lh = append(lh, hx(l))
		}
		root := ledger.MerkleRoot(leaves)
		f.Merkle = append(f.Merkle, MerkleVec{Leaves: lh, Root: hx(root[:])})
	}

	trust0 := b.trust(0, "v1", "v2", "v3", "v4")
	trust1 := b.trust(1, "v1", "v2", "v3", "v4", "v5")

	prop := &ledger.Proposal{Tier: ledger.T2, Target: "tools/allow",
		DiffHash: h("diff: allow tool web_fetch"), RationaleHash: h("rationale: needed for feed reader"),
		EvalHash: h("eval: suite-7 passed 212/212")}
	genesis := &ledger.Genesis{SpecVersion: ledger.SpecVersion,
		ConstitutionHash: h("cairn-test-constitution"), Trust: trust0}

	type step struct {
		kind    ledger.Kind
		payload func(chain []ledger.Entry) []byte
		signer  string
	}
	steps := []step{
		{ledger.KindGenesis, func([]ledger.Entry) []byte { return genesis.Encode() }, "founder"},
		{ledger.KindProposal, func([]ledger.Entry) []byte { return prop.Encode() }, "p1"},
		{ledger.KindVote, func(c []ledger.Entry) []byte {
			v := &ledger.Vote{ProposalHash: c[1].Hash(), Verdict: ledger.VerdictApprove, CommentHash: h("comment: r1 ok")}
			return v.Encode()
		}, "r1"},
		{ledger.KindVote, func(c []ledger.Entry) []byte {
			v := &ledger.Vote{ProposalHash: c[1].Hash(), Verdict: ledger.VerdictApprove, CommentHash: h("comment: s1 ok")}
			return v.Encode()
		}, "s1"},
		{ledger.KindActivate, func(c []ledger.Entry) []byte {
			a := &ledger.Activate{ProposalHash: c[1].Hash(), VoteHashes: []ledger.Hash{c[2].Hash(), c[3].Hash()},
				EffectiveAfter: c[1].Time + 72*3600}
			return a.Encode()
		}, "v1"},
		{ledger.KindAction, func([]ledger.Entry) []byte {
			a := &ledger.Action{ActionType: "tool_call", ArgsHash: h("args: web_fetch feed.xml"), ResultHash: h("result: 200 OK")}
			return a.Encode()
		}, "a1"},
		{ledger.KindFreeze, func([]ledger.Entry) []byte {
			fz := &ledger.Freeze{Scope: ledger.FreezeActivations, ReasonHash: h("reason: suspicious request pattern")}
			return fz.Encode()
		}, "s1"},
		{ledger.KindRevoke, func([]ledger.Entry) []byte {
			rv := &ledger.Revoke{Key: b.pub("a1"), ReasonHash: h("reason: agent key leaked")}
			return rv.Encode()
		}, "s1"},
		{ledger.KindValidators, func([]ledger.Entry) []byte { return trust1.Encode() }, "v1"},
	}

	var chain []ledger.Entry
	var payloads [][]byte
	for i, s := range steps {
		var prev ledger.Hash
		if i > 0 {
			prev = chain[i-1].Hash()
		}
		p := s.payload(chain)
		payloads = append(payloads, p)
		e := b.entry(uint64(i), prev, s.kind, p, s.signer)
		chain = append(chain, e)
		f.Payloads = append(f.Payloads, PayloadVec{Kind: s.kind.String(), Hex: hx(p), BlobHash: hx(e.PayloadHash[:])})
		eh := e.Hash()
		f.MainChain = append(f.MainChain, EntryVec{Height: e.Height, Kind: e.Kind.String(),
			Author: hx(e.Author[:]), Hex: hx(e.Encode()), EntryHash: hx(eh[:])})
	}
	root := ledger.LogRoot(chain)
	f.MainRoot = hx(root[:])

	f.Chains = append(f.Chains, ChainCase{Name: "main_chain", EntriesHex: hashes(chain), Valid: true})
	f.Chains = append(f.Chains, b.invalidChains(chain)...)
	f.Checkpoints = b.checkpointCases(chain, trust0)
	f.UseBlobs = b.useVectors()
	f.Openings = b.openingVectors()
	f.Locate = b.locateCases()
	f.Inclusion = b.inclusionCases(chain)
	f.Consistency = b.consistencyCases(chain)
	return f
}

func cp(e []ledger.Entry) []ledger.Entry { return append([]ledger.Entry(nil), e...) }

func (b *builder) invalidChains(chain []ledger.Entry) []ChainCase {
	var out []ChainCase
	add := func(name, code string, entries []ledger.Entry) {
		out = append(out, ChainCase{Name: name, EntriesHex: hashes(entries), Error: code})
	}

	c := cp(chain)
	c[4].Time++ // signature is now stale
	add("tampered_field_without_resigning", ledger.CodeBadSignature, c)

	c = append(cp(chain[:3]), chain[4:]...)
	add("dropped_entry", ledger.CodeBadHeight, c)

	c = cp(chain)
	c[2], c[3] = c[3], c[2]
	add("swapped_entries", ledger.CodeBadHeight, c)

	c = cp(chain)
	c[4] = b.entry(4, chain[2].Hash(), chain[4].Kind, []byte("x"), "v1")
	add("wrong_prev_hash_resigned", ledger.CodeBadPrevHash, c)

	c = cp(chain)
	c[0] = b.entry(0, h("not zero"), ledger.KindGenesis, []byte("x"), "founder")
	add("genesis_with_nonzero_prev", ledger.CodeBadGenesis, c)

	c = cp(chain)
	c[0] = b.entry(0, ledger.Hash{}, ledger.KindProposal, []byte("x"), "founder")
	add("first_entry_not_genesis", ledger.CodeBadGenesis, c)

	add("empty_chain", ledger.CodeBadGenesis, []ledger.Entry{})

	c = cp(chain)
	c[4] = b.entry(4, chain[3].Hash(), ledger.KindGenesis, []byte("x"), "v1")
	add("second_genesis", ledger.CodeDuplicateGenesis, c)

	c = cp(chain[1:])
	add("missing_genesis", ledger.CodeBadHeight, c)

	// Encoding-level failures are produced by editing raw bytes.
	raw := hashes(chain)
	edit := func(name, code string, f func(b []byte) []byte) {
		r := append([]string(nil), raw...)
		bs, _ := hex.DecodeString(r[4])
		r[4] = hx(f(bs))
		out = append(out, ChainCase{Name: name, EntriesHex: r, Error: code})
	}
	edit("truncated_entry", ledger.CodeBadLength, func(b []byte) []byte { return b[:len(b)-1] })
	edit("entry_with_trailing_byte", ledger.CodeBadLength, func(b []byte) []byte { return append(b, 0) })
	edit("unsupported_version", ledger.CodeBadVersion, func(b []byte) []byte { b[0] = 2; return b })
	edit("unknown_kind", ledger.CodeUnknownKind, func(b []byte) []byte { b[1+8+32] = 99; return b })
	return out
}

func (b *builder) signed(c ledger.Checkpoint, signers ...string) ledger.SignedCheckpoint {
	sc := ledger.SignedCheckpoint{Checkpoint: c}
	for _, n := range signers {
		sc.Cosign(b.keys[n])
	}
	sort.SliceStable(sc.Sigs, func(i, j int) bool { return bytes.Compare(sc.Sigs[i].Public[:], sc.Sigs[j].Public[:]) < 0 })
	return sc
}

func (b *builder) checkpointCases(chain []ledger.Entry, trust ledger.TrustConfig) []CheckpointCase {
	var out []CheckpointCase
	th := hx(trust.Encode())
	add := func(name, code string, entries []ledger.Entry, sc ledger.SignedCheckpoint) {
		out = append(out, CheckpointCase{Name: name, TrustHex: th, EntriesHex: hashes(entries),
			CheckpointHex: hx(sc.Encode()), Valid: code == "", Error: code})
	}
	full := ledger.NewCheckpoint(0, chain)
	quorum := []string{"v1", "v2", "v3", "w1", "w2"}

	add("quorum_3_of_4_full_log", "", chain, b.signed(full, quorum...))
	add("all_4_validators_prefix_of_4_entries", "", chain[:4],
		b.signed(ledger.NewCheckpoint(0, chain[:4]), "v1", "v2", "v3", "v4", "w1", "w2"))
	add("rejects_signature_from_unadmitted_key", ledger.CodeUnknownSigner, chain,
		b.signed(full, "v1", "v2", "v3", "w1", "w2", "outsider"))

	unsorted := b.signed(full, quorum...)
	unsorted.Sigs[0], unsorted.Sigs[1] = unsorted.Sigs[1], unsorted.Sigs[0]
	add("signatures_not_in_key_order", ledger.CodeUnsortedSigners, chain, unsorted)

	add("below_validator_quorum", ledger.CodeBelowQuorum, chain, b.signed(full, "v1", "v2", "w1", "w2"))
	add("below_witness_threshold", ledger.CodeBelowWitnesses, chain, b.signed(full, "v1", "v2", "v3", "w1"))
	add("reviewer_signature_does_not_count_as_validator", ledger.CodeBelowQuorum, chain,
		b.signed(full, "v1", "v2", "r1", "w1", "w2"))

	bad := b.signed(full, quorum...)
	bad.Sigs[1].Signature[0] ^= 1
	add("corrupted_signature_by_admitted_key", ledger.CodeBadSignature, chain, bad)

	add("same_signer_twice", ledger.CodeDuplicateSigner, chain,
		b.signed(full, "v1", "v1", "v2", "v3", "w1", "w2"))

	wrongRoot := full
	wrongRoot.Root[0] ^= 1
	add("root_mismatch_properly_signed", ledger.CodeRootMismatch, chain, b.signed(wrongRoot, quorum...))

	wrongHead := full
	wrongHead.Head[0] ^= 1
	add("head_mismatch_properly_signed", ledger.CodeHeadMismatch, chain, b.signed(wrongHead, quorum...))

	add("size_does_not_match_entries", ledger.CodeSizeMismatch, chain,
		b.signed(ledger.NewCheckpoint(0, chain[:5]), quorum...))

	wrongEpoch := full
	wrongEpoch.Epoch = 1
	add("epoch_not_in_force", ledger.CodeEpochMismatch, chain, b.signed(wrongEpoch, quorum...))
	return out
}

// JSON renders the file with stable formatting.
func (f *File) JSON() []byte {
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(out, '\n')
}
