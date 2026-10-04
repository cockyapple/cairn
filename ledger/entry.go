// Package ledger is the core of Cairn: the entry format, hash chain, Merkle
// tree, checkpoints and the verification rules an outside party can run.
// It depends only on the Go standard library.
package ledger

import (
	"crypto/ed25519"
	"crypto/sha256"

	"github.com/cockyapple/cairn/wire"
)

const (
	Version   = 1
	EntrySize = 178 // 1 + 8 + 32 + 1 + 32 + 32 + 8 + 64

	entrySigDomain  = "cairn/entry/v1\x00"
	entryHashDomain = "cairn/entry-hash/v1\x00"
)

type Hash [32]byte

type Kind uint8

const (
	KindGenesis    Kind = 0
	KindProposal   Kind = 1
	KindVote       Kind = 2
	KindActivate   Kind = 3
	KindAction     Kind = 4
	KindValidators Kind = 5
	KindFreeze     Kind = 6
	KindRevoke     Kind = 7
)

var kindNames = map[Kind]string{
	KindGenesis: "GENESIS", KindProposal: "PROPOSAL", KindVote: "VOTE",
	KindActivate: "ACTIVATE", KindAction: "ACTION", KindValidators: "VALIDATORS",
	KindFreeze: "FREEZE",
	KindRevoke: "REVOKE",
}

func (k Kind) String() string {
	if n, ok := kindNames[k]; ok {
		return n
	}
	return "UNKNOWN"
}

func (k Kind) Valid() bool { _, ok := kindNames[k]; return ok }

type Entry struct {
	Height      uint64
	PrevHash    Hash
	Kind        Kind
	PayloadHash Hash
	Author      [32]byte
	Time        uint64 // unix seconds; advisory only, never used for ordering
	Signature   [64]byte
}

func (e *Entry) signingBytes() []byte {
	var w wire.Writer
	w.U8(Version)
	w.U64(e.Height)
	w.Fixed(e.PrevHash[:])
	w.U8(uint8(e.Kind))
	w.Fixed(e.PayloadHash[:])
	w.Fixed(e.Author[:])
	w.U64(e.Time)
	return w.Out()
}

func sigInput(e *Entry) []byte { return append([]byte(entrySigDomain), e.signingBytes()...) }

// Encode returns the fixed-length canonical encoding, signature included.
func (e *Entry) Encode() []byte { return append(e.signingBytes(), e.Signature[:]...) }

// DecodeEntry parses and structurally validates one entry. It does not check
// the signature or the entry's place in a chain.
func DecodeEntry(b []byte) (Entry, error) {
	var e Entry
	if len(b) != EntrySize {
		return e, fail(CodeBadLength, "entry must be exactly 178 bytes")
	}
	r := wire.NewReader(b)
	if r.U8() != Version {
		return e, fail(CodeBadVersion, "unsupported entry version")
	}
	e.Height = r.U64()
	copy(e.PrevHash[:], r.Fixed(32))
	e.Kind = Kind(r.U8())
	copy(e.PayloadHash[:], r.Fixed(32))
	copy(e.Author[:], r.Fixed(32))
	e.Time = r.U64()
	copy(e.Signature[:], r.Fixed(64))
	if err := r.Done(); err != nil {
		return e, fail(CodeBadLength, err.Error())
	}
	if !e.Kind.Valid() {
		return e, fail(CodeUnknownKind, "unrecognised entry kind")
	}
	return e, nil
}

// Hash is the chain link: SHA-256 over a domain tag and the full encoding,
// so the signature is committed to by every later entry.
func (e *Entry) Hash() Hash {
	h := sha256.New()
	h.Write([]byte(entryHashDomain))
	h.Write(e.Encode())
	var out Hash
	h.Sum(out[:0])
	return out
}

// Sign sets Author to the key's public half and signs the entry.
// Sign sets Author and Signature. Like ed25519.Sign it panics if priv is not a
// well-formed 64-byte private key: that is a caller bug, not an input error.
func (e *Entry) Sign(priv ed25519.PrivateKey) {
	copy(e.Author[:], priv.Public().(ed25519.PublicKey))
	copy(e.Signature[:], ed25519.Sign(priv, sigInput(e)))
}

func (e *Entry) VerifySignature() bool {
	if smallOrder(e.Author) {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(e.Author[:]), sigInput(e), e.Signature[:])
}

// BlobHash is the content address of a payload or blob: plain SHA-256, so any
// tool can reproduce it.
func BlobHash(b []byte) Hash { return sha256.Sum256(b) }
