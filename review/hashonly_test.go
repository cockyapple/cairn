package review_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
	"github.com/cockyapple/cairn/review"
)

func TestIntentPublishedKeepsTheBlobOnlyWhenTheLogTakesTheEntry(t *testing.T) {
	val, sec, r1, r2, prop, a1 := key("val"), key("sec"), key("r1"), key("r2"), key("prop"), key("agent1")
	trust := ledger.TrustConfig{Keys: []ledger.Key{
		{Role: ledger.RoleValidator, Public: pub(val)}, {Role: ledger.RoleSecurityReviewer, Public: pub(sec)},
		{Role: ledger.RoleReviewer, Public: pub(r1)}, {Role: ledger.RoleReviewer, Public: pub(r2)},
		{Role: ledger.RoleProposer, Public: pub(prop)}, {Role: ledger.RoleAgent, Public: pub(a1)},
	}}
	var now uint64 = 1_000_000
	l, err := review.New(val, ledger.BlobHash([]byte("c")), trust, func() uint64 { now++; return now })
	if err != nil {
		t.Fatal(err)
	}
	g := governance.Grant{Tools: []string{"shell"}, Hosts: []string{"example.org"}, Budget: 100, NotAfter: 1 << 40}
	p, err := l.ProposeGrant(prop, ledger.T3, pub(a1), g, []byte("agent"))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []ed25519.PrivateKey{sec, r1, r2} {
		if _, err := l.Vote(k, p, ledger.VerdictApprove, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.Activate(val, p); err != nil {
		t.Fatal(err)
	}
	now += 8 * 24 * 3600

	c := ledger.BlobHash([]byte("withheld"))
	over := governance.Use{Host: "example.org", Cost: 1000, Commit: &c}.Encode()
	if _, _, err := l.IntentPublished(a1, "shell", over); governance.ErrCode(err) != governance.CodeBudgetExceeded {
		t.Fatalf("%v", err)
	}
	if _, ok := l.Blobs[ledger.BlobHash(over)]; ok {
		t.Fatal("a refused intent left its blob behind")
	}
	ok := governance.Use{Host: "example.org", Cost: 10, Commit: &c}.Encode()
	_, h, err := l.IntentPublished(a1, "shell", ok)
	if err != nil || h != ledger.BlobHash(ok) {
		t.Fatalf("%x %v", h, err)
	}
	if _, in := l.Blobs[h]; !in {
		t.Fatal("an accepted intent's blob is not published")
	}
}
