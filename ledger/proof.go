package ledger

import "math/bits"

// Inclusion and consistency proofs, RFC 9162 sections 2.1.3 and 2.1.4.
// Verification needs only hashes, so a light client can check that an entry
// is in a log, or that a newer checkpoint extends an older one, without the
// entries themselves.

// split returns the largest power of two strictly less than n (n >= 2).
func split(n int) int { return 1 << (bits.Len(uint(n-1)) - 1) }

// InclusionProof returns the audit path for leaves[m].
func InclusionProof(leaves [][]byte, m int) ([]Hash, error) {
	if m < 0 || m >= len(leaves) {
		return nil, fail(CodeBadProof, "leaf index out of range")
	}
	return inclusionPath(leaves, m), nil
}

func inclusionPath(d [][]byte, m int) []Hash {
	if len(d) == 1 {
		return nil
	}
	k := split(len(d))
	if m < k {
		return append(inclusionPath(d[:k], m), MerkleRoot(d[k:]))
	}
	return append(inclusionPath(d[k:], m-k), MerkleRoot(d[:k]))
}

// VerifyInclusion checks that a leaf with the given data sits at index in a
// tree of size leaves whose root is root.
func VerifyInclusion(leaf []byte, index, size uint64, path []Hash, root Hash) error {
	if index >= size {
		return fail(CodeBadProof, "leaf index outside the tree")
	}
	fn, sn := index, size-1
	r := leafHash(leaf)
	for _, p := range path {
		if sn == 0 {
			return fail(CodeBadProof, "audit path is too long")
		}
		if fn&1 == 1 || fn == sn {
			r = nodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = nodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return fail(CodeBadProof, "audit path is too short")
	}
	if r != root {
		return fail(CodeBadProof, "audit path does not lead to the root")
	}
	return nil
}

// ConsistencyProof proves that the tree over the first m leaves is a prefix
// of the tree over all of them.
func ConsistencyProof(leaves [][]byte, m int) ([]Hash, error) {
	if m < 1 || m > len(leaves) {
		return nil, fail(CodeBadProof, "old size out of range")
	}
	return consistencySub(leaves, m, true), nil
}

func consistencySub(d [][]byte, m int, complete bool) []Hash {
	if m == len(d) {
		if complete {
			return nil
		}
		return []Hash{MerkleRoot(d)}
	}
	k := split(len(d))
	if m <= k {
		return append(consistencySub(d[:k], m, complete), MerkleRoot(d[k:]))
	}
	return append(consistencySub(d[k:], m-k, false), MerkleRoot(d[:k]))
}

// VerifyConsistency checks that the tree of size second with root secondRoot
// extends the tree of size first with root firstRoot.
func VerifyConsistency(first, second uint64, firstRoot, secondRoot Hash, proof []Hash) error {
	switch {
	case first < 1 || first > second:
		return fail(CodeBadProof, "sizes are not 1 <= first <= second")
	case first == second:
		if len(proof) != 0 || firstRoot != secondRoot {
			return fail(CodeBadProof, "equal sizes need an empty proof and equal roots")
		}
		return nil
	}
	if first&(first-1) == 0 {
		proof = append([]Hash{firstRoot}, proof...)
	}
	if len(proof) == 0 {
		return fail(CodeBadProof, "empty consistency proof")
	}
	fn, sn := first-1, second-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	fr, sr := proof[0], proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return fail(CodeBadProof, "consistency proof is too long")
		}
		if fn&1 == 1 || fn == sn {
			fr = nodeHash(c, fr)
			sr = nodeHash(c, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = nodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return fail(CodeBadProof, "consistency proof is too short")
	}
	if fr != firstRoot || sr != secondRoot {
		return fail(CodeBadProof, "proof does not link the two roots")
	}
	return nil
}
