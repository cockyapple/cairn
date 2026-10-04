package vectorgen

import (
	"crypto/sha256"
	"fmt"
	"math"

	"github.com/cockyapple/cairn/ledger"
)

// InclusionCase is one RFC 9162 inclusion check: does the leaf at index sit in
// a tree of the given size with this root, given this audit path?
type InclusionCase struct {
	Name    string   `json:"name"`
	LeafHex string   `json:"leaf_hex"`
	Index   uint64   `json:"index"`
	Size    uint64   `json:"size"`
	PathHex []string `json:"path_hex"`
	Root    string   `json:"root"`
	Valid   bool     `json:"valid"`
	Error   string   `json:"error,omitempty"`
}

// ConsistencyCase is one RFC 9162 consistency check between two tree heads.
type ConsistencyCase struct {
	Name       string   `json:"name"`
	First      uint64   `json:"first_size"`
	Second     uint64   `json:"second_size"`
	FirstRoot  string   `json:"first_root"`
	SecondRoot string   `json:"second_root"`
	ProofHex   []string `json:"proof_hex"`
	Valid      bool     `json:"valid"`
	Error      string   `json:"error,omitempty"`
}

func proofLeaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("leaf-%d", i))
	}
	return out
}

func pathHex(p []ledger.Hash) []string {
	out := make([]string, len(p))
	for i := range p {
		out[i] = hx(p[i][:])
	}
	return out
}

func flip(p []ledger.Hash, i int) []ledger.Hash {
	q := append([]ledger.Hash(nil), p...)
	q[i][0] ^= 1
	return q
}

func (b *builder) inclusionCases(chain []ledger.Entry) []InclusionCase {
	var out []InclusionCase
	add := func(name string, leaf []byte, index, size uint64, path []ledger.Hash, root ledger.Hash, ok bool) {
		c := InclusionCase{Name: name, LeafHex: hx(leaf), Index: index, Size: size,
			PathHex: pathHex(path), Root: hx(root[:]), Valid: ok}
		if !ok {
			c.Error = ledger.CodeBadProof
		}
		out = append(out, c)
	}
	valid := func(prefix string, leaves [][]byte, index int) {
		path, err := ledger.InclusionProof(leaves, index)
		if err != nil {
			panic(err)
		}
		add(fmt.Sprintf("%s_%d_of_%d", prefix, index, len(leaves)), leaves[index], uint64(index),
			uint64(len(leaves)), path, ledger.MerkleRoot(leaves), true)
	}

	for n := 1; n <= 9; n++ {
		for i := 0; i < n; i++ {
			valid("leaf", proofLeaves(n), i)
		}
	}
	for _, i := range []int{0, 16, 32} {
		valid("leaf", proofLeaves(33), i)
	}
	for _, i := range []int{0, 1, 63, 64, 98, 99} {
		valid("leaf", proofLeaves(100), i)
	}
	entries := make([][]byte, len(chain))
	for i := range chain {
		entries[i] = chain[i].Encode()
	}
	for i := range entries {
		valid("main_chain_entry", entries, i)
	}

	// Invalid cases, each built from a valid 7-leaf proof for leaf 2 (path length 3),
	// or from the 8-leaf proof for leaf 5 where a longer path is needed.
	l7 := proofLeaves(7)
	root7 := ledger.MerkleRoot(l7)
	p7, _ := ledger.InclusionProof(l7, 2)
	l8 := proofLeaves(8)
	root8 := ledger.MerkleRoot(l8)
	p8, _ := ledger.InclusionProof(l8, 5)

	add("wrong_leaf_data", []byte("leaf-3"), 2, 7, p7, root7, false)
	add("wrong_index_same_path", l7[2], 3, 7, p7, root7, false)
	add("index_equals_size", l7[2], 7, 7, p7, root7, false)
	add("index_far_beyond_size", l7[2], 1<<40, 7, p7, root7, false)
	add("size_zero", l7[2], 0, 0, nil, ledger.MerkleRoot(nil), false)
	add("size_one_with_nonempty_path", l7[0], 0, 1, p7[:1], ledger.MerkleRoot(l7[:1]), false)
	add("path_too_long_extra_hash", l7[2], 2, 7, append(append([]ledger.Hash(nil), p7...), ledger.BlobHash([]byte("extra"))), root7, false)
	add("path_too_short_last_hash_dropped", l7[2], 2, 7, p7[:len(p7)-1], root7, false)
	add("path_too_short_first_hash_dropped", l7[2], 2, 7, p7[1:], root7, false)
	add("path_empty_in_tree_of_7", l7[2], 2, 7, nil, root7, false)
	add("path_first_hash_bit_flipped", l7[2], 2, 7, flip(p7, 0), root7, false)
	add("path_last_hash_bit_flipped", l7[2], 2, 7, flip(p7, len(p7)-1), root7, false)
	sw := append([]ledger.Hash(nil), p7...)
	sw[0], sw[1] = sw[1], sw[0]
	add("path_two_hashes_swapped", l7[2], 2, 7, sw, root7, false)
	rr := root7
	rr[31] ^= 1
	add("root_bit_flipped", l7[2], 2, 7, p7, rr, false)
	add("root_of_a_different_tree", l7[2], 2, 7, p7, root8, false)
	add("size_matches_path_length_but_not_tree", l8[5], 5, 8, p8, root7, false)
	// A path is only checked against the size it is claimed for, so any size with
	// the same traversal shape verifies and the rest do not (SPEC 5.1).
	l6 := proofLeaves(6)
	p6, _ := ledger.InclusionProof(l6, 0)
	root6 := ledger.MerkleRoot(l6)
	add("path_shape_fits_a_larger_size_7", l6[0], 0, 7, p6, root6, true)
	add("path_shape_fits_a_larger_size_8", l6[0], 0, 8, p6, root6, true)
	add("path_too_long_for_size_4", l6[0], 0, 4, p6, root6, false)
	add("path_too_short_for_size_9", l6[0], 0, 9, p6, root6, false)

	// Sizes and indexes are unsigned 64-bit. The first two are the traps for a
	// verifier that truncates to 32 bits: cut down, they match the valid 7-leaf proof.
	add("index_and_size_overflow_32_bits", l7[2], 1<<32+2, 1<<32+7, p7, root7, false)
	add("index_max_uint64", l7[2], math.MaxUint64, 7, p7, root7, false)
	add("size_2_pow_63_with_short_path", l7[0], 0, 1<<63, p7, root7, false)
	add("size_and_index_near_max_uint64", l7[2], math.MaxUint64-1, math.MaxUint64, p7, root7, false)
	add("leaf_hash_given_as_leaf_data", rfcLeafHash(l7[2]), 2, 7, p7, root7, false)
	return out
}

func (b *builder) consistencyCases(chain []ledger.Entry) []ConsistencyCase {
	var out []ConsistencyCase
	add := func(name string, first, second uint64, fr, sr ledger.Hash, proof []ledger.Hash, ok bool) {
		c := ConsistencyCase{Name: name, First: first, Second: second,
			FirstRoot: hx(fr[:]), SecondRoot: hx(sr[:]), ProofHex: pathHex(proof), Valid: ok}
		if !ok {
			c.Error = ledger.CodeBadProof
		}
		out = append(out, c)
	}
	valid := func(prefix string, leaves [][]byte, m int) {
		proof, err := ledger.ConsistencyProof(leaves, m)
		if err != nil {
			panic(err)
		}
		add(fmt.Sprintf("%s_%d_to_%d", prefix, m, len(leaves)), uint64(m), uint64(len(leaves)),
			ledger.MerkleRoot(leaves[:m]), ledger.MerkleRoot(leaves), proof, true)
	}

	for n := 1; n <= 9; n++ {
		for m := 1; m <= n; m++ {
			valid("tree", proofLeaves(n), m)
		}
	}
	for _, m := range []int{1, 16, 17, 31, 32} {
		valid("tree", proofLeaves(33), m)
	}
	for _, m := range []int{1, 2, 3, 31, 32, 33, 64, 65, 99} {
		valid("tree", proofLeaves(100), m)
	}
	entries := make([][]byte, len(chain))
	for i := range chain {
		entries[i] = chain[i].Encode()
	}
	for m := 1; m <= len(entries); m++ {
		valid("main_chain", entries, m)
	}

	// Invalid cases are built from 3 -> 7 (proof length 4), 4 -> 7 and 5 -> 8.
	l7, l8 := proofLeaves(7), proofLeaves(8)
	r3, r4, r5 := ledger.MerkleRoot(l7[:3]), ledger.MerkleRoot(l7[:4]), ledger.MerkleRoot(l8[:5])
	r7, r8 := ledger.MerkleRoot(l7), ledger.MerkleRoot(l8)
	p37, _ := ledger.ConsistencyProof(l7, 3)
	p47, _ := ledger.ConsistencyProof(l7, 4)
	fork := proofLeaves(7)
	fork[1] = []byte("forked-leaf")
	forkRoot := ledger.MerkleRoot(fork)
	forkPrefix := ledger.MerkleRoot(fork[:3])

	add("first_size_zero", 0, 7, ledger.MerkleRoot(nil), r7, p37, false)
	add("first_larger_than_second", 8, 7, r8, r7, p37, false)
	add("equal_sizes_with_nonempty_proof", 7, 7, r7, r7, p37[:1], false)
	add("equal_sizes_different_roots", 7, 7, r7, forkRoot, nil, false)
	add("empty_proof_for_non_power_of_two_first", 3, 7, r3, r7, nil, false)
	add("empty_proof_for_power_of_two_first", 4, 7, r4, r7, nil, false)
	add("proof_too_short_last_hash_dropped", 3, 7, r3, r7, p37[:len(p37)-1], false)
	add("proof_too_short_first_hash_dropped", 3, 7, r3, r7, p37[1:], false)
	add("proof_too_long_extra_hash", 3, 7, r3, r7, append(append([]ledger.Hash(nil), p37...), ledger.BlobHash([]byte("extra"))), false)
	add("proof_too_long_for_power_of_two_first", 4, 7, r4, r7, append(append([]ledger.Hash(nil), p47...), ledger.BlobHash([]byte("extra"))), false)
	add("proof_first_hash_bit_flipped", 3, 7, r3, r7, flip(p37, 0), false)
	add("proof_last_hash_bit_flipped", 3, 7, r3, r7, flip(p37, len(p37)-1), false)
	sw := append([]ledger.Hash(nil), p37...)
	sw[0], sw[1] = sw[1], sw[0]
	add("proof_two_hashes_swapped", 3, 7, r3, r7, sw, false)
	fr := r3
	fr[0] ^= 1
	add("first_root_bit_flipped", 3, 7, fr, r7, p37, false)
	sr := r7
	sr[0] ^= 1
	add("second_root_bit_flipped", 3, 7, r3, sr, p37, false)
	add("roots_swapped", 3, 7, r7, r3, p37, false)
	add("second_root_of_a_forked_log", 3, 7, r3, forkRoot, p37, false)
	add("first_root_of_a_forked_log", 3, 7, forkPrefix, r7, p37, false)
	add("power_of_two_first_root_of_a_forked_log", 4, 7, ledger.MerkleRoot(fork[:4]), r7, p47, false)
	add("first_size_wrong_for_proof", 4, 7, r4, r7, p37, false)
	add("second_size_wrong_for_proof", 3, 8, r3, r8, p37, false)
	add("proof_for_another_pair_of_sizes", 5, 8, r5, r8, p37, false)
	// Sizes are unsigned 64-bit; see the inclusion cases.
	add("sizes_overflow_32_bits", 1<<32+4, 1<<32+7, r4, r7, p47, false)
	add("equal_sizes_max_uint64", math.MaxUint64, math.MaxUint64, r7, r7, nil, true)
	add("first_larger_than_second_near_max_uint64", math.MaxUint64, math.MaxUint64-1, r7, r7, nil, false)
	add("first_size_1_second_size_2_pow_63_empty_proof", 1, 1<<63, ledger.MerkleRoot(l7[:1]), r7, nil, false)
	add("first_2_pow_63_second_max_uint64_empty_proof", 1<<63, math.MaxUint64, r4, r7, nil, false)
	add("valid_proof_with_sizes_reversed", 7, 3, r7, r3, p37, false)
	return out
}

// rfcLeafHash is SHA-256(0x00 || data), spelled out so a vector can hand a
// verifier a leaf hash where it expects leaf data.
func rfcLeafHash(data []byte) []byte {
	h := sha256.Sum256(append([]byte{0}, data...))
	return h[:]
}
