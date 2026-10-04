package vectorgen

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/cockyapple/cairn/ledger"
)

// Everything below is RFC 9162 section 2.1 written from the tree definition and
// the RFC's text, using only crypto/sha256. It calls nothing from ledger, so a
// vector that passes here can be passed by a verifier written from the spec alone.

func rawNode(l, r []byte) []byte {
	h := sha256.Sum256(append(append([]byte{1}, l...), r...))
	return h[:]
}

func rawLeaf(d []byte) []byte {
	h := sha256.Sum256(append([]byte{0}, d...))
	return h[:]
}

// rawSplit is the largest power of two strictly less than n (n >= 2). The test
// is written as k <= (n-1)/2 so that k*2 cannot wrap for n near 2^64.
func rawSplit(n uint64) uint64 {
	k := uint64(1)
	for k <= (n-1)/2 {
		k *= 2
	}
	return k
}

// rawInclusionRec rebuilds the root from the top of the tree down. The last hash
// of a path is the sibling at the top level, and the path must be used up exactly
// when the recursion reaches a single leaf.
func rawInclusionRec(leaf []byte, index, size uint64, path [][]byte) ([]byte, bool) {
	if size == 1 {
		return leaf, len(path) == 0
	}
	if len(path) == 0 {
		return nil, false
	}
	k := rawSplit(size)
	sib := path[len(path)-1]
	if index < k {
		sub, ok := rawInclusionRec(leaf, index, k, path[:len(path)-1])
		return rawNode(sub, sib), ok
	}
	sub, ok := rawInclusionRec(leaf, index-k, size-k, path[:len(path)-1])
	return rawNode(sib, sub), ok
}

func rawInclusion(leafData []byte, index, size uint64, path [][]byte, root []byte) bool {
	if size == 0 || index >= size {
		return false
	}
	got, ok := rawInclusionRec(rawLeaf(leafData), index, size, path)
	return ok && bytes.Equal(got, root)
}

// rawInclusionRFC is the iterative algorithm of RFC 9162 section 2.1.3.2.
func rawInclusionRFC(leafData []byte, index, size uint64, path [][]byte, root []byte) bool {
	if size == 0 || index >= size {
		return false
	}
	fn, sn := index, size-1
	r := rawLeaf(leafData)
	for _, p := range path {
		if sn == 0 {
			return false
		}
		if fn%2 == 1 || fn == sn {
			r = rawNode(p, r)
			for fn%2 == 0 && fn != 0 {
				fn, sn = fn/2, sn/2
			}
		} else {
			r = rawNode(r, p)
		}
		fn, sn = fn/2, sn/2
	}
	return sn == 0 && bytes.Equal(r, root)
}

// rawConsistencyRec returns the old and new roots a proof implies for the
// subtree it is looking at. In the "complete" case the old subtree is the first
// tree itself, whose root the verifier already holds.
func rawConsistencyRec(m, n uint64, proof [][]byte, complete bool, firstRoot []byte) (oldRoot, newRoot []byte, ok bool) {
	if m == n {
		if complete {
			return firstRoot, firstRoot, len(proof) == 0
		}
		if len(proof) != 1 {
			return nil, nil, false
		}
		return proof[0], proof[0], true
	}
	if len(proof) == 0 {
		return nil, nil, false
	}
	k := rawSplit(n)
	sib := proof[len(proof)-1]
	rest := proof[:len(proof)-1]
	if m <= k {
		o, w, ok := rawConsistencyRec(m, k, rest, complete, firstRoot)
		return o, rawNode(w, sib), ok
	}
	o, w, ok := rawConsistencyRec(m-k, n-k, rest, false, firstRoot)
	return rawNode(sib, o), rawNode(sib, w), ok
}

func rawConsistency(first, second uint64, firstRoot, secondRoot []byte, proof [][]byte) bool {
	if first < 1 || first > second {
		return false
	}
	o, w, ok := rawConsistencyRec(first, second, proof, true, firstRoot)
	return ok && bytes.Equal(o, firstRoot) && bytes.Equal(w, secondRoot)
}

// rawConsistencyRFC is the iterative algorithm of RFC 9162 section 2.1.4.2.
func rawConsistencyRFC(first, second uint64, firstRoot, secondRoot []byte, proof [][]byte) bool {
	if first < 1 || first > second {
		return false
	}
	if first == second {
		return len(proof) == 0 && bytes.Equal(firstRoot, secondRoot)
	}
	if first&(first-1) == 0 {
		proof = append([][]byte{firstRoot}, proof...)
	}
	if len(proof) == 0 {
		return false
	}
	fn, sn := first-1, second-1
	for fn%2 == 1 {
		fn, sn = fn/2, sn/2
	}
	fr, sr := proof[0], proof[0]
	for _, c := range proof[1:] {
		if sn == 0 {
			return false
		}
		if fn%2 == 1 || fn == sn {
			fr, sr = rawNode(c, fr), rawNode(c, sr)
			for fn%2 == 0 && fn != 0 {
				fn, sn = fn/2, sn/2
			}
		} else {
			sr = rawNode(sr, c)
		}
		fn, sn = fn/2, sn/2
	}
	return sn == 0 && bytes.Equal(fr, firstRoot) && bytes.Equal(sr, secondRoot)
}

func hexList(t *testing.T, in []string) [][]byte {
	t.Helper()
	out := make([][]byte, len(in))
	for i, s := range in {
		out[i] = mustHex(t, s)
		if len(out[i]) != 32 {
			t.Fatalf("a path element is %d bytes, want 32", len(out[i]))
		}
	}
	return out
}

func toHashes(b [][]byte) []ledger.Hash {
	out := make([]ledger.Hash, len(b))
	for i := range b {
		copy(out[i][:], b[i])
	}
	return out
}

func toHash(b []byte) (h ledger.Hash) {
	copy(h[:], b)
	return
}

func TestInclusionVectors(t *testing.T) {
	f := load(t)
	var valid, invalid int
	names := map[string]bool{}
	for _, c := range f.Inclusion {
		if names[c.Name] {
			t.Errorf("duplicate case name %s", c.Name)
		}
		names[c.Name] = true
		leaf, root, path := mustHex(t, c.LeafHex), mustHex(t, c.Root), hexList(t, c.PathHex)
		if len(root) != 32 {
			t.Fatalf("%s: root is %d bytes, want 32", c.Name, len(root))
		}
		if got := rawInclusion(leaf, c.Index, c.Size, path, root); got != c.Valid {
			t.Errorf("%s: recursive raw check says %v, vector says %v", c.Name, got, c.Valid)
		}
		if got := rawInclusionRFC(leaf, c.Index, c.Size, path, root); got != c.Valid {
			t.Errorf("%s: RFC raw check says %v, vector says %v", c.Name, got, c.Valid)
		}
		err := ledger.VerifyInclusion(leaf, c.Index, c.Size, toHashes(path), toHash(root))
		if (err == nil) != c.Valid {
			t.Errorf("%s: ledger.VerifyInclusion err=%v, valid=%v", c.Name, err, c.Valid)
		}
		if c.Valid {
			valid++
			if c.Error != "" {
				t.Errorf("%s: a valid case carries an error code", c.Name)
			}
		} else {
			invalid++
			if c.Error != ledger.CodeBadProof || ledger.ErrCode(err) != c.Error {
				t.Errorf("%s: want code %q, vector says %q, ledger says %q", c.Name, ledger.CodeBadProof, c.Error, ledger.ErrCode(err))
			}
		}
		if strings.HasPrefix(c.Name, "main_chain_entry_") && c.Valid && c.Size == uint64(len(f.MainChain)) && c.Root != f.MainRoot {
			t.Errorf("%s: root is not the main chain root", c.Name)
		}
	}
	if valid < 60 || invalid < 20 {
		t.Fatalf("too few cases: %d valid, %d invalid", valid, invalid)
	}
}

func TestConsistencyVectors(t *testing.T) {
	f := load(t)
	var valid, invalid int
	names := map[string]bool{}
	for _, c := range f.Consistency {
		if names[c.Name] {
			t.Errorf("duplicate case name %s", c.Name)
		}
		names[c.Name] = true
		fr, sr, proof := mustHex(t, c.FirstRoot), mustHex(t, c.SecondRoot), hexList(t, c.ProofHex)
		if len(fr) != 32 || len(sr) != 32 {
			t.Fatalf("%s: roots are %d and %d bytes, want 32", c.Name, len(fr), len(sr))
		}
		if got := rawConsistency(c.First, c.Second, fr, sr, proof); got != c.Valid {
			t.Errorf("%s: recursive raw check says %v, vector says %v", c.Name, got, c.Valid)
		}
		if got := rawConsistencyRFC(c.First, c.Second, fr, sr, proof); got != c.Valid {
			t.Errorf("%s: RFC raw check says %v, vector says %v", c.Name, got, c.Valid)
		}
		err := ledger.VerifyConsistency(c.First, c.Second, toHash(fr), toHash(sr), toHashes(proof))
		if (err == nil) != c.Valid {
			t.Errorf("%s: ledger.VerifyConsistency err=%v, valid=%v", c.Name, err, c.Valid)
		}
		if c.Valid {
			valid++
			if c.Error != "" {
				t.Errorf("%s: a valid case carries an error code", c.Name)
			}
		} else {
			invalid++
			if c.Error != ledger.CodeBadProof || ledger.ErrCode(err) != c.Error {
				t.Errorf("%s: want code %q, vector says %q, ledger says %q", c.Name, ledger.CodeBadProof, c.Error, ledger.ErrCode(err))
			}
		}
		if strings.HasPrefix(c.Name, "main_chain_") && c.Valid && c.Second == uint64(len(f.MainChain)) && c.SecondRoot != f.MainRoot {
			t.Errorf("%s: second root is not the main chain root", c.Name)
		}
	}
	if valid < 60 || invalid < 26 {
		t.Fatalf("too few cases: %d valid, %d invalid", valid, invalid)
	}
}

// Tree roots in the proof vectors for 1 to 9 leaves are the ones in "merkle".
func TestProofVectorRootsMatchMerkleVectors(t *testing.T) {
	f := load(t)
	want := map[string]string{}
	for n, m := range f.Merkle {
		want[itoa(n)] = m.Root
	}
	var seen int
	for _, c := range f.Inclusion {
		if !strings.HasPrefix(c.Name, "leaf_") || !c.Valid || c.Size > 9 {
			continue
		}
		seen++
		if want[itoa(int(c.Size))] != c.Root {
			t.Errorf("%s: root differs from the merkle vector for %d leaves", c.Name, c.Size)
		}
	}
	if seen != 45 {
		t.Fatalf("expected 45 small-tree inclusion cases, saw %d", seen)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for ; n > 0; n /= 10 {
		d = append([]byte{byte('0' + n%10)}, d...)
	}
	return string(d)
}
