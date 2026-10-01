package ledger

import (
	"encoding/hex"
	"fmt"
	"testing"
)

func testLeaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("leaf-%d", i))
	}
	return out
}

// Published RFC 6962 / Certificate Transparency reference leaves and roots.
func TestMerkleRootMatchesReferenceVectors(t *testing.T) {
	var leaves [][]byte
	for _, h := range []string{"", "00", "10", "2021", "3031", "40414243", "5051525354555657", "606162636465666768696a6b6c6d6e6f"} {
		b, _ := hex.DecodeString(h)
		leaves = append(leaves, b)
	}
	want := map[int]string{
		1: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		2: "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
		8: "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
	}
	for n, w := range want {
		r := MerkleRoot(leaves[:n])
		if got := hex.EncodeToString(r[:]); got != w {
			t.Errorf("root over %d leaves = %s, want %s", n, got, w)
		}
	}
}

func TestInclusionProofsExhaustive(t *testing.T) {
	for n := 1; n <= 70; n++ {
		leaves := testLeaves(n)
		root := MerkleRoot(leaves)
		for m := 0; m < n; m++ {
			p, err := InclusionProof(leaves, m)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyInclusion(leaves[m], uint64(m), uint64(n), p, root); err != nil {
				t.Fatalf("n=%d m=%d: %v", n, m, err)
			}
			// Every way to break it must be rejected.
			if VerifyInclusion([]byte("other"), uint64(m), uint64(n), p, root) == nil {
				t.Fatalf("n=%d m=%d: wrong leaf accepted", n, m)
			}
			if m+1 < n && VerifyInclusion(leaves[m], uint64(m+1), uint64(n), p, root) == nil {
				t.Fatalf("n=%d m=%d: wrong index accepted", n, m)
			}
			// The tree size is not bound by the path itself (leaf 0 has the same
			// path shape in sizes 3 and 4); it is authenticated by the signed checkpoint.
			for i := range p {
				q := append([]Hash(nil), p...)
				q[i][0] ^= 1
				if VerifyInclusion(leaves[m], uint64(m), uint64(n), q, root) == nil {
					t.Fatalf("n=%d m=%d: flipped path hash %d accepted", n, m, i)
				}
			}
			if len(p) > 0 && VerifyInclusion(leaves[m], uint64(m), uint64(n), p[:len(p)-1], root) == nil {
				t.Fatalf("n=%d m=%d: truncated path accepted", n, m)
			}
			if VerifyInclusion(leaves[m], uint64(m), uint64(n), append(append([]Hash(nil), p...), Hash{}), root) == nil {
				t.Fatalf("n=%d m=%d: extended path accepted", n, m)
			}
		}
	}
}

func TestConsistencyProofsExhaustive(t *testing.T) {
	for n := 1; n <= 70; n++ {
		leaves := testLeaves(n)
		second := MerkleRoot(leaves)
		for m := 1; m <= n; m++ {
			first := MerkleRoot(leaves[:m])
			p, err := ConsistencyProof(leaves, m)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyConsistency(uint64(m), uint64(n), first, second, p); err != nil {
				t.Fatalf("m=%d n=%d: %v", m, n, err)
			}
			bad := first
			bad[0] ^= 1
			if VerifyConsistency(uint64(m), uint64(n), bad, second, p) == nil {
				t.Fatalf("m=%d n=%d: wrong first root accepted", m, n)
			}
			bad = second
			bad[0] ^= 1
			if VerifyConsistency(uint64(m), uint64(n), first, bad, p) == nil {
				t.Fatalf("m=%d n=%d: wrong second root accepted", m, n)
			}
			for i := range p {
				q := append([]Hash(nil), p...)
				q[i][0] ^= 1
				if VerifyConsistency(uint64(m), uint64(n), first, second, q) == nil {
					t.Fatalf("m=%d n=%d: flipped proof hash %d accepted", m, n, i)
				}
			}
			if m < n {
				if VerifyConsistency(uint64(m), uint64(n), first, second, append(append([]Hash(nil), p...), Hash{})) == nil {
					t.Fatalf("m=%d n=%d: extended proof accepted", m, n)
				}
				if len(p) > 0 && VerifyConsistency(uint64(m), uint64(n), first, second, p[:len(p)-1]) == nil {
					t.Fatalf("m=%d n=%d: truncated proof accepted", m, n)
				}
			}
		}
	}
}

// A forked history of the same length must not be provable as an extension.
func TestConsistencyRejectsFork(t *testing.T) {
	a := testLeaves(20)
	b := testLeaves(20)
	b[3] = []byte("rewritten")
	p, _ := ConsistencyProof(a, 10)
	if VerifyConsistency(10, 20, MerkleRoot(b[:10]), MerkleRoot(a), p) == nil {
		t.Fatal("rewritten prefix accepted as consistent")
	}
	if VerifyConsistency(10, 20, MerkleRoot(a[:10]), MerkleRoot(b), p) == nil {
		t.Fatal("forked tree accepted as extension")
	}
}

func TestProofArgumentErrors(t *testing.T) {
	l := testLeaves(5)
	if _, err := InclusionProof(l, 5); ErrCode(err) != CodeBadProof {
		t.Fatal("out-of-range index")
	}
	if _, err := InclusionProof(l, -1); ErrCode(err) != CodeBadProof {
		t.Fatal("negative index")
	}
	if _, err := ConsistencyProof(l, 0); ErrCode(err) != CodeBadProof {
		t.Fatal("zero old size")
	}
	if _, err := ConsistencyProof(l, 6); ErrCode(err) != CodeBadProof {
		t.Fatal("old size beyond tree")
	}
	var z Hash
	for _, c := range [][2]uint64{{0, 5}, {6, 5}} {
		if ErrCode(VerifyConsistency(c[0], c[1], z, z, nil)) != CodeBadProof {
			t.Fatalf("sizes %v accepted", c)
		}
	}
	if ErrCode(VerifyInclusion(nil, 0, 0, nil, z)) != CodeBadProof {
		t.Fatal("empty tree inclusion accepted")
	}
}
