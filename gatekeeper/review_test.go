package gatekeeper_test

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cockyapple/cairn/gatekeeper"
	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
	"github.com/cockyapple/cairn/loader"
)

type outcome struct {
	res []byte
	err error
}

func reviewSetup(t *testing.T) (*env, *gatekeeper.Gatekeeper, *int32) {
	t.Helper()
	e := newEnv(t)
	g := gatekeeper.New(e.l)
	err := g.AddAgent(&gatekeeper.Agent{Name: "actor", Key: e.actor, Allow: []string{"refund", "lookup"}, Review: []string{"refund"}})
	if err != nil {
		t.Fatal(err)
	}
	var runs int32
	g.Handle("refund", func(context.Context, []byte) ([]byte, error) {
		atomic.AddInt32(&runs, 1)
		return []byte("refunded"), nil
	})
	g.Handle("lookup", func(context.Context, []byte) ([]byte, error) { return []byte("found"), nil })
	return e, g, &runs
}

func startDo(g *gatekeeper.Gatekeeper, ctx context.Context, action string) chan outcome {
	ch := make(chan outcome, 1)
	go func() {
		r, err := g.Do(ctx, "actor", action, []byte("order 4471"))
		ch <- outcome{r, err}
	}()
	return ch
}

func waitPending(t *testing.T, g *gatekeeper.Gatekeeper) gatekeeper.Pending {
	t.Helper()
	for i := 0; i < 2000; i++ {
		if p := g.PendingReviews(); len(p) == 1 {
			return p[0]
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no action became pending")
	return gatekeeper.Pending{}
}

func (e *env) resultAt(t *testing.T, i int) string {
	t.Helper()
	return string(e.l.Blobs[blobOf(t, e, i)])
}

func TestReviewedActionWaitsOpenThenRunsOnApproval(t *testing.T) {
	e, g, runs := reviewSetup(t)
	done := startDo(g, context.Background(), "refund")
	p := waitPending(t, g)
	if p.Agent != "actor" || p.ActionType != "refund" || string(p.Args) != "order 4471" {
		t.Fatalf("%+v", p)
	}
	if atomic.LoadInt32(runs) != 0 {
		t.Fatal("the handler ran before any decision")
	}
	if st := e.replays(t); len(st.OpenIntents) != 1 {
		t.Fatalf("the intent must stay open while the action waits: %+v", st)
	}
	d := gatekeeper.SignDecision(e.rev, p.Intent, true)
	if err := g.Decide(d); err != nil {
		t.Fatal(err)
	}
	out := <-done
	if out.err != nil || string(out.res) != "refunded" || atomic.LoadInt32(runs) != 1 {
		t.Fatalf("%v %q runs=%d", out.err, out.res, *runs)
	}
	got := e.lastResult(t)
	want := "review:approve " + hexOf(d.Reviewer[:]) + " " + hexOf(d.Sig[:]) + "\nok\nrefunded"
	if got != want {
		t.Fatalf("the completion must carry the signed approval:\n got %q\nwant %q", got, want)
	}
	if st := e.replays(t); len(st.OpenIntents) != 0 || st.Completed != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestRejectedActionNeverRuns(t *testing.T) {
	e, g, runs := reviewSetup(t)
	done := startDo(g, context.Background(), "refund")
	p := waitPending(t, g)
	if err := g.Decide(gatekeeper.SignDecision(e.rev, p.Intent, false)); err != nil {
		t.Fatal(err)
	}
	out := <-done
	if gatekeeper.ErrCode(out.err) != gatekeeper.CodeReviewRejected || atomic.LoadInt32(runs) != 0 {
		t.Fatalf("%v runs=%d", out.err, *runs)
	}
	if !strings.HasPrefix(e.lastResult(t), "review:reject ") || !strings.Contains(e.lastResult(t), "refused\nreview_rejected") {
		t.Fatalf("%q", e.lastResult(t))
	}
	e.replays(t)
}

func TestOnlyAReviewerCanDecideAndOnlyOnce(t *testing.T) {
	e, g, _ := reviewSetup(t)
	done := startDo(g, context.Background(), "refund")
	p := waitPending(t, g)
	for name, k := range map[string][]byte{"the agent itself": e.actor, "a proposer": e.prop, "a stranger": key("stranger")} {
		if err := g.Decide(gatekeeper.SignDecision(k, p.Intent, true)); !errors.Is(err, gatekeeper.ErrNotReviewer) {
			t.Fatalf("%s must not be able to approve: %v", name, err)
		}
	}
	bad := gatekeeper.SignDecision(e.rev, p.Intent, true)
	bad.Sig[0] ^= 1
	if err := g.Decide(bad); !errors.Is(err, gatekeeper.ErrBadDecision) {
		t.Fatalf("a forged signature must be refused: %v", err)
	}
	flipped := gatekeeper.SignDecision(e.rev, p.Intent, false)
	flipped.Approve = true
	if err := g.Decide(flipped); !errors.Is(err, gatekeeper.ErrBadDecision) {
		t.Fatalf("a rejection relabelled as approval must be refused: %v", err)
	}
	if len(g.PendingReviews()) != 1 {
		t.Fatal("refused decisions must leave the action waiting")
	}
	if err := g.Decide(gatekeeper.SignDecision(e.rev, p.Intent, true)); err != nil {
		t.Fatal(err)
	}
	<-done
	if err := g.Decide(gatekeeper.SignDecision(e.rev, p.Intent, true)); !errors.Is(err, gatekeeper.ErrNoSuchReview) {
		t.Fatalf("a decision must be accepted once: %v", err)
	}
}

func TestDecisionCannotBeMovedToAnotherAction(t *testing.T) {
	e, g, _ := reviewSetup(t)
	done := startDo(g, context.Background(), "refund")
	p := waitPending(t, g)
	other := p.Intent
	other[0] ^= 1
	if err := g.Decide(gatekeeper.SignDecision(e.rev, other, true)); !errors.Is(err, gatekeeper.ErrNoSuchReview) {
		t.Fatalf("%v", err)
	}
	g.Decide(gatekeeper.SignDecision(e.rev, p.Intent, false))
	<-done
}

func TestReviewTimesOutAndClosesTheIntent(t *testing.T) {
	e, g, runs := reviewSetup(t)
	g.ReviewTimeout = 30 * time.Millisecond
	_, err := g.Do(context.Background(), "actor", "refund", []byte("x"))
	if gatekeeper.ErrCode(err) != gatekeeper.CodeReviewTimeout || atomic.LoadInt32(runs) != 0 {
		t.Fatalf("%v runs=%d", err, *runs)
	}
	if len(g.PendingReviews()) != 0 {
		t.Fatal("a timed-out action must leave the pending list")
	}
	if st := e.replays(t); len(st.OpenIntents) != 0 {
		t.Fatalf("the intent must be closed: %+v", st)
	}
	if _, err := g.Do(context.Background(), "actor", "lookup", nil); err != nil {
		t.Fatalf("the agent must be usable after a timeout: %v", err)
	}
}

func TestReviewEndsWhenTheContextDoes(t *testing.T) {
	_, g, runs := reviewSetup(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := startDo(g, ctx, "refund")
	waitPending(t, g)
	cancel()
	if out := <-done; gatekeeper.ErrCode(out.err) != gatekeeper.CodeReviewTimeout || atomic.LoadInt32(runs) != 0 {
		t.Fatalf("%v", out.err)
	}
}

func TestUnreviewedActionsAreNotHeld(t *testing.T) {
	_, g, _ := reviewSetup(t)
	if _, err := g.Do(context.Background(), "actor", "lookup", nil); err != nil {
		t.Fatal(err)
	}
}

func TestReviewTypeMustBeAllowed(t *testing.T) {
	e := newEnv(t)
	g := gatekeeper.New(e.l)
	if g.AddAgent(&gatekeeper.Agent{Name: "a", Key: e.actor, Allow: []string{"x"}, Review: []string{"y"}}) == nil {
		t.Fatal("a review type outside Allow can never run and must be rejected")
	}
}

// The wait can last hours. If the configuration stopped being the one in force
// meanwhile, an approval must not let the action run.
func TestApprovalDoesNotOutliveTheConfiguration(t *testing.T) {
	e := newEnv(t)
	cfg := []byte("answer politely")
	p1, _ := e.l.Propose(e.prop, ledger.T1, "prompt/actor", cfg, []byte("baseline"), nil)
	e.l.Vote(e.rev, p1, ledger.VerdictApprove, nil)
	if _, err := e.l.Activate(e.val, p1); err != nil {
		t.Fatal(err)
	}
	var broken atomic.Bool
	g := gatekeeper.New(e.l)
	g.View = func() (*loader.Gate, uint64, error) {
		if broken.Load() {
			return nil, 0, errors.New("log unreachable")
		}
		sc := e.l.Checkpoint(e.val, e.wit)
		gate, err := loader.Open(e.l.Entries, e.l.Blobs, &sc, governance.Options{})
		return gate, e.now + 30*24*3600, err
	}
	ran := false
	g.Handle("refund", func(context.Context, []byte) ([]byte, error) { ran = true; return nil, nil })
	if err := g.AddAgent(&gatekeeper.Agent{Name: "actor", Key: e.actor, Allow: []string{"refund"}, Review: []string{"refund"}, ConfigTarget: "prompt/actor", ConfigArtifact: cfg}); err != nil {
		t.Fatal(err)
	}
	done := startDo(g, context.Background(), "refund")
	p := waitPending(t, g)
	broken.Store(true)
	if err := g.Decide(gatekeeper.SignDecision(e.rev, p.Intent, true)); err != nil {
		t.Fatal(err)
	}
	out := <-done
	if gatekeeper.ErrCode(out.err) != gatekeeper.CodeConfigUnusable || ran {
		t.Fatalf("%v ran=%v", out.err, ran)
	}
	if !strings.HasPrefix(e.lastResult(t), "review:approve ") {
		t.Fatalf("the approval that was given must still be on the log: %q", e.lastResult(t))
	}
}
func hexOf(b []byte) string { return hex.EncodeToString(b) }
