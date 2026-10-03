package governance

import (
	"testing"

	"github.com/cockyapple/cairn/ledger"
)

func (w *world) revoke(who, target string) ledger.Hash {
	return w.put(ledger.KindRevoke, who, (&ledger.Revoke{Key: pubOf(target), ReasonHash: ledger.Hash{9}}).Encode())
}

func TestRevokedAgentCanNoLongerAct(t *testing.T) {
	w := newWorld(t)
	w.action("agent", "tool_call", 1, 0, ledger.Hash{})
	w.revoke("sec", "agent")
	st, err := w.replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Revocations) != 1 || st.Revocations[0].Role != ledger.RoleAgent || st.Revocations[0].By != pubOf("sec") {
		t.Fatalf("%+v", st.Revocations)
	}
	if len(st.OpenIntents) != 1 {
		t.Fatal("the open intent of a revoked agent must stay visible")
	}
	w.action("agent", "tool_call", 1, 4, w.entries[1].Hash())
	if _, err := w.replay(); ErrCode(err) != CodeRevokedKey {
		t.Fatalf("completion by a revoked agent: %v", err)
	}
}

func TestRevokeAllowedWhileFrozenAndByValidator(t *testing.T) {
	w := newWorld(t)
	w.freeze("val", ledger.FreezeActivations)
	w.revoke("val", "prop")
	if _, err := w.replay(); err != nil {
		t.Fatal(err)
	}
}

func TestRevokedProposerCannotGetAProposalActivated(t *testing.T) {
	w := newWorld(t)
	p, votes, pt := w.approved(ledger.T2, "tools/allow")
	w.revoke("sec", "prop")
	w.activate("val", p, pt+3*day, votes...)
	if _, err := w.replay(); ErrCode(err) != CodeRevokedKey {
		t.Fatalf("activation of a revoked proposer's change: %v", err)
	}
}

func TestActivationBeforeRevocationStands(t *testing.T) {
	w := newWorld(t)
	p, votes, pt := w.approved(ledger.T1, "tools/allow")
	w.activate("val", p, pt+day, votes...)
	w.revoke("sec", "prop")
	st, err := w.replay()
	if err != nil || len(st.Activations) != 1 {
		t.Fatalf("%v %+v", err, st)
	}
}

func TestRevokeRules(t *testing.T) {
	cases := []struct {
		name string
		do   func(w *world)
		code string
	}{
		{"a reviewer cannot be revoked by one signer", func(w *world) { w.revoke("sec", "rev1") }, CodeBadRevocation},
		{"a validator cannot be revoked by one signer", func(w *world) { w.revoke("val", "val") }, CodeBadRevocation},
		{"a witness cannot be revoked by one signer", func(w *world) { w.revoke("sec", "wit") }, CodeBadRevocation},
		{"a security reviewer cannot be revoked by one signer", func(w *world) { w.revoke("val", "sec") }, CodeBadRevocation},
		{"a key with no role cannot be revoked", func(w *world) { w.revoke("sec", "stranger") }, CodeBadRevocation},
		{"revoking twice", func(w *world) { w.revoke("sec", "agent"); w.revoke("val", "agent") }, CodeBadRevocation},
		{"a reviewer cannot revoke", func(w *world) { w.revoke("rev1", "agent") }, CodeUnauthorizedAuthor},
		{"an agent cannot revoke", func(w *world) { w.revoke("agent", "agent2") }, CodeUnauthorizedAuthor},
		{"a proposer cannot revoke", func(w *world) { w.revoke("prop", "agent") }, CodeUnauthorizedAuthor},
		{"a revoked key cannot propose", func(w *world) { w.revoke("sec", "prop"); w.propose("prop", ledger.T1, "x/y") }, CodeRevokedKey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			c.do(w)
			if _, err := w.replay(); ErrCode(err) != c.code {
				t.Fatalf("want %s, got %v", c.code, err)
			}
		})
	}
}

// rotate walks a T4 VALIDATORS change to the point of the entry itself.
func (w *world) rotate(tc ledger.TrustConfig) {
	w.blobs[ledger.BlobHash(tc.Encode())] = tc.Encode()
	pr := ledger.Proposal{Tier: ledger.T4, Target: "cairn/validators", DiffHash: ledger.BlobHash(tc.Encode())}
	ph := w.put(ledger.KindProposal, "prop", pr.Encode())
	pt := w.timeOfLast()
	v1 := w.vote("sec", ph, ledger.VerdictApprove)
	v2 := w.vote("rev1", ph, ledger.VerdictApprove)
	v3 := w.vote("rev2", ph, ledger.VerdictApprove)
	w.activate("val", ph, pt+14*day, v1, v2, v3)
	w.now = pt + 14*day
	w.put(ledger.KindValidators, "val", tc.Encode())
}

func withoutKey(tc ledger.TrustConfig, name string) ledger.TrustConfig {
	var keys []ledger.Key
	for _, k := range tc.Keys {
		if k.Public != pubOf(name) {
			keys = append(keys, k)
		}
	}
	tc.Keys = keys
	return tc
}

func TestRevocationSurvivesANewEpoch(t *testing.T) {
	w := newWorld(t)
	w.revoke("sec", "agent")
	w.rotate(withoutKey(trustConfig(1), "agent"))
	if _, err := w.replay(); err != nil {
		t.Fatal(err)
	}
	w.action("agent", "tool_call", 1, 0, ledger.Hash{})
	if _, err := w.replay(); ErrCode(err) != CodeRevokedKey {
		t.Fatalf("a revoked key must stay revoked after a rotation: %v", err)
	}
}

func TestRotationCannotReadmitARevokedKey(t *testing.T) {
	w := newWorld(t)
	w.revoke("sec", "agent")
	w.rotate(trustConfig(1)) // still lists the revoked agent
	if _, err := w.replay(); ErrCode(err) != CodeRevokedKey {
		t.Fatalf("a new epoch listing a revoked key must be refused: %v", err)
	}
}

func TestReplayWithoutBlobResolverFailsCleanly(t *testing.T) {
	w := newWorld(t)
	_, err := Replay(w.entries, nil, Options{})
	if ErrCode(err) != CodeBadBlob {
		t.Fatalf("nil resolver: %v", err)
	}
}
