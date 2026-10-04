package governance

import (
	"testing"

	"github.com/cockyapple/cairn/ledger"
)

func TestLocateReportsEveryPlaceACommitmentAppears(t *testing.T) {
	blobs := MapBlobs{}
	add := func(b []byte) ledger.Hash { h := ledger.BlobHash(b); blobs[h] = b; return h }
	commit := ledger.BlobHash([]byte("the commitment"))
	other := ledger.BlobHash([]byte("another"))
	action := func(a ledger.Action) ledger.Entry {
		return ledger.Entry{Kind: ledger.KindAction, PayloadHash: add(a.Encode())}
	}
	use := add(Use{Host: "h", Cost: 1, Commit: &commit}.Encode())
	plainUse := add(Use{Host: "h", Cost: 1, Args: commit[:]}.Encode())
	otherUse := add(Use{Host: "h", Cost: 1, Commit: &other}.Encode())
	entries := []ledger.Entry{
		{Kind: ledger.KindGenesis},
		action(ledger.Action{ActionType: "a", ArgsHash: commit}),
		action(ledger.Action{ActionType: "a", ArgsHash: use}),
		action(ledger.Action{ActionType: "a", ArgsHash: other, ResultHash: commit}),
		action(ledger.Action{ActionType: "a", ArgsHash: plainUse}),
		action(ledger.Action{ActionType: "a", ArgsHash: otherUse, ResultHash: other}),
		{Kind: ledger.KindAction, PayloadHash: other},                                               // blob missing
		{Kind: ledger.KindProposal, PayloadHash: add(actionBytes(ledger.Action{ArgsHash: commit}))}, // not an action
	}
	for i := range entries {
		entries[i].Height = uint64(i)
	}
	want := []Location{{1, "args"}, {2, "use"}, {3, "result"}}
	got := Locate(entries, blobs, commit)
	if len(got) != len(want) {
		t.Fatalf("%+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%+v", got)
		}
	}
	if got := Locate(entries, blobs, ledger.BlobHash([]byte("nothing"))); len(got) != 0 {
		t.Fatalf("%+v", got)
	}
}

func actionBytes(a ledger.Action) []byte { return a.Encode() }
