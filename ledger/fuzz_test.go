package ledger

import (
	"bytes"
	"testing"
)

// Each fuzz target checks two properties: a decoder never panics, and
// whatever it accepts re-encodes to exactly the input bytes (no second
// encoding of the same value, ADR-12).

func FuzzDecodeEntry(f *testing.F) {
	f.Add(make([]byte, EntrySize))
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := DecodeEntry(b)
		if err == nil && !bytes.Equal(e.Encode(), b) {
			t.Fatal("entry re-encodes differently")
		}
	})
}

func FuzzDecodeSignedCheckpoint(f *testing.F) {
	f.Add(make([]byte, CheckpointBodySize+4))
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := DecodeSignedCheckpoint(b)
		if err == nil && !bytes.Equal(s.Encode(), b) {
			t.Fatal("checkpoint re-encodes differently")
		}
	})
}

func FuzzDecodeTrustConfig(f *testing.F) {
	f.Add(make([]byte, 16))
	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := DecodeTrustConfig(b)
		if err == nil && !bytes.Equal(c.Encode(), b) {
			t.Fatal("trust config re-encodes differently")
		}
	})
}

func FuzzDecodePayloads(f *testing.F) {
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, b []byte) {
		if g, err := DecodeGenesis(b); err == nil && !bytes.Equal(g.Encode(), b) {
			t.Fatal("genesis")
		}
		if p, err := DecodeProposal(b); err == nil && !bytes.Equal(p.Encode(), b) {
			t.Fatal("proposal")
		}
		if v, err := DecodeVote(b); err == nil && !bytes.Equal(v.Encode(), b) {
			t.Fatal("vote")
		}
		if a, err := DecodeActivate(b); err == nil && !bytes.Equal(a.Encode(), b) {
			t.Fatal("activate")
		}
		if a, err := DecodeAction(b); err == nil && !bytes.Equal(a.Encode(), b) {
			t.Fatal("action")
		}
		if x, err := DecodeFreeze(b); err == nil && !bytes.Equal(x.Encode(), b) {
			t.Fatal("freeze")
		}
	})
}

// FuzzProofs feeds arbitrary paths to the verifiers: they may reject but
// must not panic or loop on any input.
func FuzzProofs(f *testing.F) {
	f.Add(uint64(1), uint64(3), uint64(7), make([]byte, 64))
	f.Fuzz(func(t *testing.T, a, b, c uint64, raw []byte) {
		var path []Hash
		for len(raw) >= 32 && len(path) < 70 {
			var h Hash
			copy(h[:], raw[:32])
			path = append(path, h)
			raw = raw[32:]
		}
		_ = VerifyInclusion([]byte("leaf"), a, b, path, Hash{})
		_ = VerifyConsistency(a, b, Hash{}, Hash{}, path)
		_ = c
	})
}
