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
