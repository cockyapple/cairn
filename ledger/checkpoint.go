package ledger

import (
	"bytes"
	"crypto/ed25519"

	"github.com/cockyapple/cairn/wire"
)

const (
	CheckpointBodySize = 81 // 1 + 8 + 8 + 32 + 32
	checkpointDomain   = "cairn/checkpoint/v1\x00"
	maxCheckpointSigs  = 1024
)

// Checkpoint commits to the first Size entries of the log.
type Checkpoint struct {
	Epoch uint64
	Size  uint64
	Root  Hash // Merkle root over all Size entries
	Head  Hash // entry hash of the entry at height Size-1
}

type CheckpointSig struct {
	Public    [32]byte
	Signature [64]byte
}

type SignedCheckpoint struct {
	Checkpoint
	Sigs []CheckpointSig
}

func (c *Checkpoint) Body() []byte {
	var w wire.Writer
	w.U8(Version)
	w.U64(c.Epoch)
	w.U64(c.Size)
	w.Fixed(c.Root[:])
	w.Fixed(c.Head[:])
	return w.Out()
}

func checkpointSigInput(c *Checkpoint) []byte {
	return append([]byte(checkpointDomain), c.Body()...)
}

// NewCheckpoint builds the checkpoint for an entry prefix.
func NewCheckpoint(epoch uint64, entries []Entry) Checkpoint {
	c := Checkpoint{Epoch: epoch, Size: uint64(len(entries)), Root: LogRoot(entries)}
	if len(entries) > 0 {
		c.Head = entries[len(entries)-1].Hash()
	}
	return c
}

// Cosign appends a signature by priv. It does not deduplicate, and it panics on a
// malformed private key, as ed25519.Sign does.
func (s *SignedCheckpoint) Cosign(priv ed25519.PrivateKey) {
	var cs CheckpointSig
	copy(cs.Public[:], priv.Public().(ed25519.PublicKey))
	copy(cs.Signature[:], ed25519.Sign(priv, checkpointSigInput(&s.Checkpoint)))
	s.Sigs = append(s.Sigs, cs)
}

func (s *SignedCheckpoint) Encode() []byte {
	var w wire.Writer
	w.Fixed(s.Body())
	w.U32(uint32(len(s.Sigs)))
	for _, cs := range s.Sigs {
		w.Fixed(cs.Public[:])
		w.Fixed(cs.Signature[:])
	}
	return w.Out()
}

func DecodeSignedCheckpoint(b []byte) (SignedCheckpoint, error) {
	var s SignedCheckpoint
	r := wire.NewReader(b)
	v := r.U8()
	if r.Err() != nil {
		return s, fail(CodeBadCheckpointLen, r.Err().Error())
	}
	if v != Version {
		return s, fail(CodeBadVersion, "unsupported checkpoint version")
	}
	s.Epoch = r.U64()
	s.Size = r.U64()
	copy(s.Root[:], r.Fixed(32))
	copy(s.Head[:], r.Fixed(32))
	n := r.Count(maxCheckpointSigs)
	for i := 0; i < n; i++ {
		var cs CheckpointSig
		copy(cs.Public[:], r.Fixed(32))
		copy(cs.Signature[:], r.Fixed(64))
		s.Sigs = append(s.Sigs, cs)
	}
	if err := r.Done(); err != nil {
		return s, fail(CodeBadCheckpointLen, err.Error())
	}
	return s, nil
}

// VerifyCheckpoint checks sc against the log prefix it claims to cover and
// the trust configuration in force. The caller must already have verified the
// chain (see VerifyLog). A checkpoint is canonical: signatures are in strictly
// ascending public-key order and every signer is admitted, so a given set of
// signatures cannot be padded or reordered into a second valid byte string
// (ADR-12). It is not one checkpoint per tree head: quorum subsets differ, and
// one signer can produce several valid signatures over the same body.
func VerifyCheckpoint(sc *SignedCheckpoint, entries []Entry, trust *TrustConfig) error {
	if sc == nil {
		return fail(CodeBadCheckpointLen, "no checkpoint supplied")
	}
	if trust == nil {
		return fail(CodeBadTrustConfig, "no trust configuration supplied")
	}
	if err := trust.validate(); err != nil {
		return err
	}
	if sc.Size == 0 || sc.Size != uint64(len(entries)) {
		return fail(CodeSizeMismatch, "checkpoint size does not match the entries supplied")
	}
	if sc.Root != LogRoot(entries) {
		return fail(CodeRootMismatch, "merkle root differs from the entries")
	}
	if sc.Head != entries[len(entries)-1].Hash() {
		return fail(CodeHeadMismatch, "head hash differs from the last entry")
	}
	if sc.Epoch != trust.Epoch {
		return fail(CodeEpochMismatch, "checkpoint epoch is not the epoch in force")
	}

	validators, witnesses := 0, 0
	in := checkpointSigInput(&sc.Checkpoint)
	for i, cs := range sc.Sigs {
		if i > 0 {
			switch c := bytes.Compare(sc.Sigs[i-1].Public[:], cs.Public[:]); {
			case c == 0:
				return fail(CodeDuplicateSigner, "a key signed more than once")
			case c > 0:
				return fail(CodeUnsortedSigners, "signatures must be in ascending public-key order")
			}
		}
		role, ok := trust.RoleOf(cs.Public)
		if !ok {
			return fail(CodeUnknownSigner, "signature by a key outside the trust configuration")
		}
		if !ed25519.Verify(ed25519.PublicKey(cs.Public[:]), in, cs.Signature[:]) {
			return fail(CodeBadSignature, "invalid signature by an admitted key")
		}
		switch role {
		case RoleValidator:
			validators++
		case RoleWitness:
			witnesses++
		default:
			return fail(CodeUnknownSigner, "signature by a key whose role does not sign checkpoints")
		}
	}
	if validators < ValidatorQuorum(trust.count(RoleValidator)) {
		return fail(CodeBelowQuorum, "not enough validator signatures")
	}
	if witnesses < int(trust.WitnessThreshold) {
		return fail(CodeBelowWitnesses, "not enough witness cosignatures")
	}
	return nil
}

// VerifyLog is the full check an outside party runs: the chain is sound and
// the checkpoint is a valid commitment to it.
func VerifyLog(entries []Entry, sc *SignedCheckpoint, trust *TrustConfig) error {
	if err := VerifyChain(entries); err != nil {
		return err
	}
	return VerifyCheckpoint(sc, entries, trust)
}

// VerifySig reports whether sig is a valid signature by pub over this checkpoint.
// It judges the signature alone, not whether pub is admitted or quorum is met.
func (c *Checkpoint) VerifySig(pub [32]byte, sig [64]byte) bool {
	return !smallOrder(pub) && ed25519.Verify(ed25519.PublicKey(pub[:]), checkpointSigInput(c), sig[:])
}
