package governance

import (
	"crypto/rand"
	"errors"

	"github.com/cockyapple/cairn/ledger"
)

// SaltSize is the length of the random prefix of every opening.
const SaltSize = 32

// An opening lets an agent publish a commitment to a payload now and show the
// payload later. It is salt (32 random bytes) | payload, and the commitment is
// the blob hash of the whole. The salt is what stops anyone confirming a guess
// at a short or predictable payload from the commitment alone. The log only ever
// holds the commitment; the replay never reads an opening.

// NewOpening returns an opening for payload and the commitment that stands for it.
func NewOpening(payload []byte) (opening []byte, commit ledger.Hash, err error) {
	opening = make([]byte, SaltSize, SaltSize+len(payload))
	if _, err = rand.Read(opening); err != nil {
		return nil, ledger.Hash{}, err
	}
	opening = append(opening, payload...)
	return opening, ledger.BlobHash(opening), nil
}

// CheckOpening returns the payload an opening commits to, or an error if the
// opening does not hash to commit.
func CheckOpening(commit ledger.Hash, opening []byte) ([]byte, error) {
	if len(opening) < SaltSize {
		return nil, errors.New("opening is shorter than its salt")
	}
	if ledger.BlobHash(opening) != commit {
		return nil, errors.New("opening does not match the commitment")
	}
	return append([]byte(nil), opening[SaltSize:]...), nil
}

// Location is where a commitment appears on the log.
type Location struct {
	Height uint64
	// Field is "args" (the intent's or completion's args_hash), "use" (the args
	// commitment inside a published use blob) or "result".
	Field string
}

// Locate lists every place in entries where commit appears as an ACTION's args
// commitment, use-blob commitment or result commitment. A verifier that is shown
// an opening calls CheckOpening and then Locate: the opening is genuine only for
// the entries Locate returns. Entries whose payload blob is missing or is not an
// action are skipped, so an empty result is conclusive only for a complete set of
// blobs.
func Locate(entries []ledger.Entry, blobs map[ledger.Hash][]byte, commit ledger.Hash) []Location {
	var out []Location
	for i := range entries {
		e := &entries[i]
		if e.Kind != ledger.KindAction {
			continue
		}
		pb, ok := blobs[e.PayloadHash]
		if !ok || ledger.BlobHash(pb) != e.PayloadHash {
			continue
		}
		a, err := ledger.DecodeAction(pb)
		if err != nil {
			continue
		}
		if a.ArgsHash == commit {
			out = append(out, Location{e.Height, "args"})
		}
		if ub, ok := blobs[a.ArgsHash]; ok && ledger.BlobHash(ub) == a.ArgsHash {
			if u, err := DecodeUse(ub); err == nil && u.Commit != nil && *u.Commit == commit {
				out = append(out, Location{e.Height, "use"})
			}
		}
		if a.ResultHash == commit {
			out = append(out, Location{e.Height, "result"})
		}
	}
	return out
}
