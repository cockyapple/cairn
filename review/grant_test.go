package review_test

import (
	"crypto/ed25519"
	"testing"

	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
	"github.com/cockyapple/cairn/review"
)

func TestGrantAndDelegationThroughTheReviewLog(t *testing.T) {
	val, sec, r1, r2, prop := key("val"), key("sec"), key("r1"), key("r2"), key("prop")
	a1, a2 := key("agent1"), key("agent2")
	trust := ledger.TrustConfig{Keys: []ledger.Key{
		{Role: ledger.RoleValidator, Public: pub(val)}, {Role: ledger.RoleSecurityReviewer, Public: pub(sec)},
		{Role: ledger.RoleReviewer, Public: pub(r1)}, {Role: ledger.RoleReviewer, Public: pub(r2)},
		{Role: ledger.RoleProposer, Public: pub(prop)},
		{Role: ledger.RoleAgent, Public: pub(a1)}, {Role: ledger.RoleAgent, Public: pub(a2)},
	}}
	var now uint64 = 1_000_000
	l, err := review.New(val, ledger.BlobHash([]byte("c")), trust, func() uint64 { now++; return now })
	if err != nil {
		t.Fatal(err)
	}
	root := governance.Grant{Tools: []string{"fs.read", "http.get"}, Hosts: []string{"example.org"}, Budget: 100, NotAfter: 1 << 40}
	p, err := l.ProposeGrant(prop, ledger.T3, pub(a1), root, []byte("first agent"))
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

	narrow := governance.Grant{Tools: []string{"fs.read"}, Hosts: []string{"example.org"}, Budget: 10, NotAfter: 1 << 39}
	if _, err := l.Delegate(a1, pub(a2), narrow); governance.ErrCode(err) != governance.CodeBadDelegation {
		t.Fatalf("a delegation inside the activation delay must be refused: %v", err)
	}
	now += 8 * 24 * 3600
	if _, err := l.Delegate(a1, pub(a2), root); governance.ErrCode(err) != governance.CodeNotNarrower {
		t.Fatalf("an identical grant: %v", err)
	}
	if _, err := l.Delegate(a1, pub(a2), narrow); err != nil {
		t.Fatal(err)
	}
	st := l.State()
	if len(st.Grants) != 2 || st.Grants[1].Agent != pub(a2) || st.Grants[1].DelegatedBy == nil {
		t.Fatalf("%+v", st.Grants)
	}
	if len(st.OpenIntents) != 0 {
		t.Fatalf("Delegate must close its own intent: %+v", st.OpenIntents)
	}
	if err := ledger.VerifyChain(l.Entries); err != nil {
		t.Fatal(err)
	}
}
