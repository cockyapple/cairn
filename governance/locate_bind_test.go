package governance

import (
	"testing"
	"time"

	"github.com/cockyapple/cairn/ledger"
)

func TestLocateIgnoresABlobThatDoesNotMatchItsHash(t *testing.T) {
	a := ledger.Action{ActionType: "x", ArgsHash: ledger.BlobHash([]byte("args"))}
	pb := a.Encode()
	e := ledger.Entry{Height: 3, Kind: ledger.KindAction, PayloadHash: ledger.BlobHash(pb)}
	entries := []ledger.Entry{e}
	if got := Locate(entries, map[ledger.Hash][]byte{e.PayloadHash: pb}, a.ArgsHash); len(got) != 1 {
		t.Fatalf("honest map: %v", got)
	}
	b := ledger.Action{ActionType: "y", ArgsHash: a.ArgsHash}
	other := b.Encode()
	if got := Locate(entries, map[ledger.Hash][]byte{e.PayloadHash: other}, a.ArgsHash); len(got) != 0 {
		t.Fatalf("a substituted payload blob was believed: %v", got)
	}
}

func TestNowSecondsNeverDisablesOrWrapsTheClockCheck(t *testing.T) {
	if NowSeconds(time.Unix(-5, 0)) != 1 || NowSeconds(time.Unix(0, 0)) != 1 {
		t.Fatal("a pre-1970 clock must read as 1")
	}
	if NowSeconds(time.Unix(1_700_000_000, 0)) != 1_700_000_000 {
		t.Fatal("a normal clock changed")
	}
}

func TestWithdrawDerivedHandlesALongChainAndAWideFan(t *testing.T) {
	const n = 50000
	r := &replayer{grants: map[[32]byte]*grantRec{}}
	key := func(i int) (k [32]byte) { k[0], k[1], k[2] = byte(i), byte(i>>8), byte(i>>16); k[3] = 1; return }
	root := key(0)
	r.grants[root] = &grantRec{}
	prev := root
	for i := 1; i <= n; i++ { // a chain n deep
		p := prev
		r.grants[key(i)] = &grantRec{parent: &p}
		prev = key(i)
	}
	for i := n + 1; i <= 2*n; i++ { // and n children directly under the root
		p := root
		r.grants[key(i)] = &grantRec{parent: &p}
	}
	unrelated := [32]byte{9, 9, 9}
	r.grants[unrelated] = &grantRec{}
	start := time.Now()
	r.withdrawDerived(root)
	if len(r.grants) != 1 || r.grants[unrelated] == nil {
		t.Fatalf("%d grants left", len(r.grants))
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v", d)
	}
}
