package ledger

import "crypto/sha256"

// Merkle tree hashing follows RFC 9162 section 2.1.1: leaves and interior
// nodes are domain-separated by a one-byte prefix, and an n-leaf tree splits
// at the largest power of two strictly less than n.

func leafHash(data []byte) Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out Hash
	h.Sum(out[:0])
	return out
}

func nodeHash(l, r Hash) Hash {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l[:])
	h.Write(r[:])
	var out Hash
	h.Sum(out[:0])
	return out
}

// MerkleRoot returns the tree head over the given leaf data. The empty tree's
// root is SHA-256 of the empty string.
func MerkleRoot(leaves [][]byte) Hash {
	switch len(leaves) {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return leafHash(leaves[0])
	}
	k := 1
	for k*2 < len(leaves) {
		k *= 2
	}
	return nodeHash(MerkleRoot(leaves[:k]), MerkleRoot(leaves[k:]))
}

// LogRoot is the Merkle root over the full encoding of every entry.
func LogRoot(entries []Entry) Hash {
	leaves := make([][]byte, len(entries))
	for i := range entries {
		leaves[i] = entries[i].Encode()
	}
	return MerkleRoot(leaves)
}
