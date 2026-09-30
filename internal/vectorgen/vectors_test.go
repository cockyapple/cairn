package vectorgen

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/cockyapple/cairn/ledger"
)

const goldenPath = "../../testdata/vectors-v1.json"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func load(t *testing.T) *File {
	t.Helper()
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	var f File
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

// The committed file must equal what the generator produces today. A diff
// means the wire format changed, which is a spec change and needs a new version.
func TestGoldenFileIsCurrent(t *testing.T) {
	want := Build().JSON()
	got, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("testdata/vectors-v1.json is stale: run `make vectors` and review the diff")
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	if !bytes.Equal(Build().JSON(), Build().JSON()) {
		t.Fatal("generator output changed between runs")
	}
}

func TestEveryEntryKindHasAVector(t *testing.T) {
	f := load(t)
	seen := map[string]bool{}
	for _, e := range f.MainChain {
		seen[e.Kind] = true
	}
	for _, k := range []ledger.Kind{ledger.KindGenesis, ledger.KindProposal, ledger.KindVote,
		ledger.KindActivate, ledger.KindAction, ledger.KindValidators, ledger.KindFreeze} {
		if !seen[k.String()] {
			t.Errorf("no vector for %s", k)
		}
	}
}

func TestEveryErrorCodeIsExercised(t *testing.T) {
	f := load(t)
	seen := map[string]bool{}
	for _, c := range f.Chains {
		seen[c.Error] = true
	}
	for _, c := range f.Checkpoints {
		seen[c.Error] = true
	}
	for _, code := range []string{
		ledger.CodeBadLength, ledger.CodeBadVersion, ledger.CodeUnknownKind, ledger.CodeBadGenesis,
		ledger.CodeDuplicateGenesis, ledger.CodeBadHeight, ledger.CodeBadPrevHash, ledger.CodeBadSignature,
		ledger.CodeSizeMismatch, ledger.CodeRootMismatch, ledger.CodeHeadMismatch, ledger.CodeEpochMismatch,
		ledger.CodeBelowQuorum, ledger.CodeBelowWitnesses, ledger.CodeDuplicateSigner,
	} {
		if !seen[code] {
			t.Errorf("error code %q has no vector", code)
		}
	}
}

func TestPayloadVectorsDecodeAndRehash(t *testing.T) {
	f := load(t)
	for _, p := range f.Payloads {
		b := mustHex(t, p.Hex)
		if h := ledger.BlobHash(b); hex.EncodeToString(h[:]) != p.BlobHash {
			t.Errorf("%s: blob hash mismatch", p.Kind)
		}
		var err error
		var re []byte
		switch p.Kind {
		case "GENESIS":
			var v ledger.Genesis
			v, err = ledger.DecodeGenesis(b)
			re = v.Encode()
		case "PROPOSAL":
			var v ledger.Proposal
			v, err = ledger.DecodeProposal(b)
			re = v.Encode()
		case "VOTE":
			var v ledger.Vote
			v, err = ledger.DecodeVote(b)
			re = v.Encode()
		case "ACTIVATE":
			var v ledger.Activate
			v, err = ledger.DecodeActivate(b)
			re = v.Encode()
		case "ACTION":
			var v ledger.Action
			v, err = ledger.DecodeAction(b)
			re = v.Encode()
		case "VALIDATORS":
			var v ledger.TrustConfig
			v, err = ledger.DecodeTrustConfig(b)
			re = v.Encode()
		case "FREEZE":
			var v ledger.Freeze
			v, err = ledger.DecodeFreeze(b)
			re = v.Encode()
		default:
			t.Fatalf("unhandled kind %s", p.Kind)
		}
		if err != nil {
			t.Errorf("%s: %v", p.Kind, err)
		} else if !bytes.Equal(re, b) {
			t.Errorf("%s: decode/encode is not the identity", p.Kind)
		}
	}
}

func decodeAll(t *testing.T, hexes []string) ([]ledger.Entry, error) {
	t.Helper()
	enc := make([][]byte, len(hexes))
	for i, h := range hexes {
		enc[i] = mustHex(t, h)
	}
	return ledger.DecodeChain(enc)
}

func TestChainCases(t *testing.T) {
	for _, c := range load(t).Chains {
		_, err := decodeAll(t, c.EntriesHex)
		if c.Valid {
			if err != nil {
				t.Errorf("%s: expected valid, got %v", c.Name, err)
			}
			continue
		}
		if ledger.ErrCode(err) != c.Error {
			t.Errorf("%s: want %q, got %v", c.Name, c.Error, err)
		}
	}
}

func TestCheckpointCases(t *testing.T) {
	for _, c := range load(t).Checkpoints {
		entries, err := decodeAll(t, c.EntriesHex)
		if err != nil {
			t.Errorf("%s: entries must form a valid chain: %v", c.Name, err)
			continue
		}
		trust, err := ledger.DecodeTrustConfig(mustHex(t, c.TrustHex))
		if err != nil {
			t.Fatal(err)
		}
		sc, err := ledger.DecodeSignedCheckpoint(mustHex(t, c.CheckpointHex))
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		err = ledger.VerifyLog(entries, &sc, &trust)
		if c.Valid && err != nil {
			t.Errorf("%s: expected valid, got %v", c.Name, err)
		}
		if !c.Valid && ledger.ErrCode(err) != c.Error {
			t.Errorf("%s: want %q, got %v", c.Name, c.Error, err)
		}
	}
}

// naiveMerkle is an independent RFC 9162 implementation using only crypto/sha256.
func naiveMerkle(leaves [][]byte) [32]byte {
	if len(leaves) == 0 {
		return sha256.Sum256(nil)
	}
	if len(leaves) == 1 {
		return sha256.Sum256(append([]byte{0}, leaves[0]...))
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	l, r := naiveMerkle(leaves[:k]), naiveMerkle(leaves[k:])
	return sha256.Sum256(append(append([]byte{1}, l[:]...), r[:]...))
}

func TestMerkleVectorsAgainstIndependentImplementation(t *testing.T) {
	for _, m := range load(t).Merkle {
		var leaves [][]byte
		for _, l := range m.Leaves {
			leaves = append(leaves, mustHex(t, l))
		}
		want := naiveMerkle(leaves)
		if hex.EncodeToString(want[:]) != m.Root {
			t.Errorf("%d leaves: vector root disagrees with independent implementation", len(leaves))
		}
		if got := ledger.MerkleRoot(leaves); got != want {
			t.Errorf("%d leaves: ledger disagrees with independent implementation", len(leaves))
		}
	}
}

// TestMainChainAgainstRawStdlib re-derives every entry hash, link and
// signature from the raw bytes using only crypto/sha256 and crypto/ed25519,
// with field offsets written out by hand. If this passes, the format in SPEC.md
// can be implemented from the vectors alone.
func TestMainChainAgainstRawStdlib(t *testing.T) {
	f := load(t)
	var prevHash [32]byte
	var leaves [][]byte
	for i, e := range f.MainChain {
		raw := mustHex(t, e.Hex)
		if len(raw) != 178 || raw[0] != 1 {
			t.Fatalf("entry %d: bad length/version", i)
		}
		if binary.BigEndian.Uint64(raw[1:9]) != uint64(i) {
			t.Fatalf("entry %d: height", i)
		}
		if !bytes.Equal(raw[9:41], prevHash[:]) {
			t.Fatalf("entry %d: prev_hash", i)
		}
		pub, sig := raw[74:106], raw[114:178]
		in := append([]byte("cairn/entry/v1\x00"), raw[:114]...)
		if !ed25519.Verify(pub, in, sig) {
			t.Fatalf("entry %d: signature", i)
		}
		prevHash = sha256.Sum256(append([]byte("cairn/entry-hash/v1\x00"), raw...))
		if hex.EncodeToString(prevHash[:]) != e.EntryHash {
			t.Fatalf("entry %d: entry_hash", i)
		}
		leaves = append(leaves, raw)
	}
	root := naiveMerkle(leaves)
	if hex.EncodeToString(root[:]) != f.MainRoot {
		t.Fatal("main chain root")
	}
}
