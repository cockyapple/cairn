package ledger

import "fmt"

// VerifyChain checks structure only: genesis first and only first, contiguous
// heights, correct prev-hash links and valid signatures. Whether an author is
// allowed to write a given kind is the review state machine's job (Phase 2).
// Checks run in a fixed order so each failure has exactly one code.
func VerifyChain(entries []Entry) error {
	if len(entries) == 0 {
		return fail(CodeBadGenesis, "a chain must begin with GENESIS; this one is empty")
	}
	for i := range entries {
		e := &entries[i]
		if !e.Kind.Valid() {
			return fail(CodeUnknownKind, fmt.Sprintf("height %d", i))
		}
		if e.Height != uint64(i) {
			return fail(CodeBadHeight, fmt.Sprintf("index %d has height %d", i, e.Height))
		}
		if i == 0 {
			if e.Kind != KindGenesis {
				return fail(CodeBadGenesis, "first entry must be GENESIS")
			}
			if e.PrevHash != (Hash{}) {
				return fail(CodeBadGenesis, "genesis prev_hash must be zero")
			}
		} else {
			if e.Kind == KindGenesis {
				return fail(CodeDuplicateGenesis, fmt.Sprintf("height %d", i))
			}
			if e.PrevHash != entries[i-1].Hash() {
				return fail(CodeBadPrevHash, fmt.Sprintf("height %d", i))
			}
		}
		if !e.VerifySignature() {
			return fail(CodeBadSignature, fmt.Sprintf("height %d", i))
		}
	}
	return nil
}

// DecodeChain parses each encoded entry and then verifies the whole chain.
func DecodeChain(encoded [][]byte) ([]Entry, error) {
	entries := make([]Entry, 0, len(encoded))
	for _, b := range encoded {
		e, err := DecodeEntry(b)
		if err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}
	return entries, VerifyChain(entries)
}
