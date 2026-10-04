package gatekeeper_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/cockyapple/cairn/gatekeeper"
	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
)

func (e *genv) opened(t *testing.T, commit ledger.Hash) string {
	t.Helper()
	o, err := e.g.Opening(commit)
	if err != nil {
		t.Fatalf("no opening for %x: %v", commit[:4], err)
	}
	p, err := governance.CheckOpening(commit, o)
	if err != nil {
		t.Fatal(err)
	}
	return string(p)
}

// nothingPublished fails if any published blob contains secret.
func (e *genv) nothingPublished(t *testing.T, secrets ...string) {
	t.Helper()
	for h, b := range e.l.Blobs {
		for _, s := range secrets {
			if bytes.Contains(b, []byte(s)) {
				t.Fatalf("blob %x publishes %q", h[:4], s)
			}
		}
	}
}

func TestHashOnlyAgentPutsOnlyCommitmentsOnTheLog(t *testing.T) {
	e := grantSetup(t, testGrant(), false, &gatekeeper.Agent{Allow: []string{"shell"}, HashOnly: true})
	if _, err := e.g.Do(context.Background(), "actor", "shell", []byte("rm -rf secret-target")); err != nil {
		t.Fatal(err)
	}
	intent, done := e.lastAction(t, 1), e.lastAction(t, 0)
	if intent.ActionType != "shell" || intent.ArgsHash != done.ArgsHash {
		t.Fatalf("%+v / %+v", intent, done)
	}
	if _, ok := e.l.Blobs[intent.ArgsHash]; ok {
		t.Fatal("the args blob was published")
	}
	if _, ok := e.l.Blobs[done.ResultHash]; ok {
		t.Fatal("the result blob was published")
	}
	if got := e.opened(t, intent.ArgsHash); got != "rm -rf secret-target" {
		t.Fatalf("args opening: %q", got)
	}
	if got := e.opened(t, done.ResultHash); got != "ok\ndone" {
		t.Fatalf("result opening: %q", got)
	}
	e.nothingPublished(t, "secret-target", "done")
	if st := e.replays(t); len(st.OpenIntents) != 0 {
		t.Fatalf("%+v", st.OpenIntents)
	}
}

func TestHashOnlyCommitmentsAreSalted(t *testing.T) {
	e := grantSetup(t, testGrant(), false, &gatekeeper.Agent{Allow: []string{"shell"}, HashOnly: true})
	for i := 0; i < 2; i++ {
		if _, err := e.g.Do(context.Background(), "actor", "shell", []byte("same")); err != nil {
			t.Fatal(err)
		}
	}
	a, b := e.lastAction(t, 3), e.lastAction(t, 1)
	if a.ArgsHash == b.ArgsHash {
		t.Fatal("equal args gave equal commitments, so a guess could be confirmed")
	}
	if a.ArgsHash == ledger.BlobHash([]byte("same")) {
		t.Fatal("the commitment is the bare hash of the args")
	}
}

func TestHashOnlyBoundAgentPublishesHostAndCostButNotArgs(t *testing.T) {
	e := grantSetup(t, testGrant(), true, &gatekeeper.Agent{Allow: []string{"shell", "fetch"}, HashOnly: true})
	ctx := context.Background()
	if _, err := e.g.DoUse(ctx, "actor", "shell", []byte("tell nobody"), "a.example", 60); err != nil {
		t.Fatal(err)
	}
	intent, done := e.lastAction(t, 1), e.lastAction(t, 0)
	if intent.ArgsHash != done.ArgsHash {
		t.Fatal("the completion does not repeat the intent's args hash")
	}
	u, err := governance.DecodeUse(e.l.Blobs[intent.ArgsHash])
	if err != nil || u.Host != "a.example" || u.Cost != 60 || u.Commit == nil || u.Args != nil {
		t.Fatalf("%+v %v", u, err)
	}
	if _, ok := e.l.Blobs[*u.Commit]; ok {
		t.Fatal("the committed args were published")
	}
	if got := e.opened(t, *u.Commit); got != "tell nobody" {
		t.Fatalf("%q", got)
	}
	if got := e.spent(t); got != 60 {
		t.Fatalf("spent %d", got)
	}
	e.nothingPublished(t, "tell nobody")

	// The grant still binds a hash-only agent.
	_, err = e.g.DoUse(ctx, "actor", "shell", []byte("x"), "a.example", 60)
	if gatekeeper.ErrCode(err) != gatekeeper.CodeOutOfGrant || !strings.Contains(err.Error(), governance.CodeBudgetExceeded) {
		t.Fatalf("%v", err)
	}
	if got := e.spent(t); got != 60 {
		t.Fatalf("a refused action charged: spent %d", got)
	}
	e.replays(t)
}

func TestHashOnlyRefusalIsRecordedAsCommitments(t *testing.T) {
	e := grantSetup(t, testGrant(), true, &gatekeeper.Agent{Allow: []string{"shell", "refund"}, HashOnly: true})
	_, err := e.g.DoUse(context.Background(), "actor", "refund", []byte("secret-amount"), "", 0)
	if gatekeeper.ErrCode(err) != gatekeeper.CodeOutOfGrant {
		t.Fatalf("%v", err)
	}
	intent, done := e.lastAction(t, 1), e.lastAction(t, 0)
	if intent.ActionType != governance.ActionEvent || done.ActionType != governance.ActionEvent {
		t.Fatalf("%+v / %+v", intent, done)
	}
	if got := e.opened(t, done.ResultHash); !strings.HasPrefix(got, "refused\n"+gatekeeper.CodeOutOfGrant) {
		t.Fatalf("%q", got)
	}
	want := string(governance.EventArgs("refund", []byte("secret-amount")))
	if got := e.opened(t, intent.ArgsHash); got != want {
		t.Fatalf("%q", got)
	}
	e.nothingPublished(t, "secret-amount", "refused")
	e.replays(t)
}

func TestHashOnlyAgentThatBecomesBoundIsRetriedInTheBoundForm(t *testing.T) {
	e := grantSetup(t, testGrant(), false, &gatekeeper.Agent{Allow: []string{"shell"}, HashOnly: true})
	if _, err := e.g.Do(context.Background(), "actor", "shell", []byte("before")); err != nil {
		t.Fatal(err)
	}
	e.now += 8 * day
	if _, err := e.g.DoUse(context.Background(), "actor", "shell", []byte("after"), "a.example", 5); err != nil {
		t.Fatal(err)
	}
	if !e.replays(t).Bound(pub(e.actor)) {
		t.Fatal("the agent is not bound")
	}
	if got := e.spent(t); got != 5 {
		t.Fatalf("spent %d", got)
	}
	e.nothingPublished(t, "before", "after")
}

func TestHashOnlyRejectedIntentLeavesNoUseBlob(t *testing.T) {
	e := grantSetup(t, testGrant(), true, &gatekeeper.Agent{Allow: []string{"shell"}, HashOnly: true})
	// Over the budget: the log refuses the intent, and the refusal itself is
	// recorded as commitments, so the attempt's use blob must not be published.
	_, err := e.g.DoUse(context.Background(), "actor", "shell", []byte("x"), "a.example", 500)
	if gatekeeper.ErrCode(err) != gatekeeper.CodeOutOfGrant {
		t.Fatalf("%v", err)
	}
	for h, b := range e.l.Blobs {
		if u, err := governance.DecodeUse(b); err == nil && u.Cost == 500 {
			t.Fatalf("the rejected attempt's use blob %x is published", h[:4])
		}
	}
}

func TestIntentIsCompletedInTheModeItWasWritten(t *testing.T) {
	for _, hashOnly := range []bool{true, false} {
		a := &gatekeeper.Agent{Allow: []string{"shell"}, HashOnly: hashOnly}
		e := grantSetup(t, testGrant(), false, a)
		e.g.Handle("shell", func(_ context.Context, args []byte) ([]byte, error) {
			a.HashOnly = !a.HashOnly // flipped while the action is open
			return []byte("flipped"), nil
		})
		if _, err := e.g.Do(context.Background(), "actor", "shell", []byte("secret-args")); err != nil {
			t.Fatalf("hashOnly=%v: %v", hashOnly, err)
		}
		intent, done := e.lastAction(t, 1), e.lastAction(t, 0)
		if intent.ArgsHash != done.ArgsHash {
			t.Fatalf("hashOnly=%v: completion does not repeat the intent", hashOnly)
		}
		_, published := e.l.Blobs[done.ResultHash]
		if published == hashOnly {
			t.Fatalf("hashOnly=%v: result published=%v", hashOnly, published)
		}
		if hashOnly {
			e.nothingPublished(t, "secret-args", "flipped")
		}
		e.replays(t)
	}
}
