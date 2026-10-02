package gatekeeper_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"errors"
	"github.com/cockyapple/cairn/gatekeeper"
	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func limited(t *testing.T, limit int) (*env, *gatekeeper.Gatekeeper, *clock) {
	t.Helper()
	e := newEnv(t)
	g := gatekeeper.New(e.l)
	c := &clock{t: time.Unix(1_000_000, 0)}
	g.Now = c.now
	err := g.AddAgent(&gatekeeper.Agent{Name: "actor", Key: e.actor, Allow: []string{"refund"}, RateLimit: limit, RateWindow: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	g.Handle("refund", func(context.Context, []byte) ([]byte, error) { return []byte("done"), nil })
	return e, g, c
}

func TestRateLimitRefusesOverBudgetAndNeverRunsTheHandler(t *testing.T) {
	_, g, _ := limited(t, 2)
	ran := 0
	g.Handle("refund", func(context.Context, []byte) ([]byte, error) { ran++; return nil, nil })
	for i := 0; i < 2; i++ {
		if _, err := g.Do(context.Background(), "actor", "refund", nil); err != nil {
			t.Fatal(err)
		}
	}
	_, err := g.Do(context.Background(), "actor", "refund", nil)
	if gatekeeper.ErrCode(err) != gatekeeper.CodeRateLimited || ran != 2 {
		t.Fatalf("want rate_limited with 2 runs, got %v after %d runs", err, ran)
	}
}

func TestRateLimitLogsOneRefusalPerWindowThenTheCount(t *testing.T) {
	e, g, c := limited(t, 1)
	do := func() error { _, err := g.Do(context.Background(), "actor", "refund", nil); return err }
	if err := do(); err != nil {
		t.Fatal(err)
	}
	base := len(e.l.Entries)
	for i := 0; i < 50; i++ {
		if gatekeeper.ErrCode(do()) != gatekeeper.CodeRateLimited {
			t.Fatal("expected rate_limited")
		}
	}
	if got := len(e.l.Entries) - base; got != 2 {
		t.Fatalf("50 over-budget requests wrote %d entries, want 2 (one intent and one completion)", got)
	}
	c.t = c.t.Add(time.Minute)
	if err := do(); err != nil {
		t.Fatalf("a new window must admit again: %v", err)
	}
	if !strings.Contains(string(e.l.Blobs[blobOf(t, e, len(e.l.Entries)-3)]), "49 further") {
		t.Fatal("the suppressed count was not logged when the window rolled over")
	}
	e.replays(t)
}

func TestRateLimitCountsRefusedRequestsToo(t *testing.T) {
	_, g, _ := limited(t, 2)
	for i := 0; i < 2; i++ {
		if gatekeeper.ErrCode(func() error { _, e := g.Do(context.Background(), "actor", "delete_all", nil); return e }()) != gatekeeper.CodeNotPermitted {
			t.Fatal("expected not_permitted")
		}
	}
	if _, err := g.Do(context.Background(), "actor", "refund", nil); gatekeeper.ErrCode(err) != gatekeeper.CodeRateLimited {
		t.Fatalf("denied requests must spend the budget: %v", err)
	}
}

func TestRateLimitZeroMeansUncapped(t *testing.T) {
	_, g, _ := limited(t, 0)
	for i := 0; i < 20; i++ {
		if _, err := g.Do(context.Background(), "actor", "refund", nil); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRateLimitRejectsNegativeConfig(t *testing.T) {
	e := newEnv(t)
	g := gatekeeper.New(e.l)
	if g.AddAgent(&gatekeeper.Agent{Name: "actor", Key: e.actor, RateLimit: -1}) == nil {
		t.Fatal("a negative limit must be rejected")
	}
}

func TestRateLimitAppliesToBusSends(t *testing.T) {
	e := newEnv(t)
	g := gatekeeper.New(e.l)
	c := &clock{t: time.Unix(1_000_000, 0)}
	g.Now = c.now
	if err := g.AddAgent(&gatekeeper.Agent{Name: "reader", Key: e.reader, RateLimit: 1}); err != nil {
		t.Fatal(err)
	}
	if err := g.AddAgent(&gatekeeper.Agent{Name: "actor", Key: e.actor}); err != nil {
		t.Fatal(err)
	}
	_ = g.Send(context.Background(), "reader", "actor", "order", []byte("x"))
	if err := g.Send(context.Background(), "reader", "actor", "order", []byte("x")); gatekeeper.ErrCode(err) != gatekeeper.CodeRateLimited {
		t.Fatalf("a second send must be rate limited: %v", err)
	}
}

func blobOf(t *testing.T, e *env, i int) ledger.Hash {
	t.Helper()
	a, err := ledger.DecodeAction(e.l.Blobs[e.l.Entries[i].PayloadHash])
	if err != nil {
		t.Fatal(err)
	}
	return a.ResultHash
}

// failNthClockRead makes the n-th log clock read from now stamp its entry far
// in the future, which the log refuses; every other read is normal.
func failNthClockRead(e *env, n int) {
	e.l.Opt = governance.Options{Now: e.now + 20}
	e.hook = func() {
		n--
		if n == 0 {
			e.now += 1000
		}
	}
}

func TestRateLimitRetriesTheFirstRefusalIfTheLogTookNothing(t *testing.T) {
	e, g, _ := limited(t, 1)
	do := func() error { _, err := g.Do(context.Background(), "actor", "refund", nil); return err }
	if err := do(); err != nil {
		t.Fatal(err)
	}
	base, before := e.now, len(e.l.Entries)
	failNthClockRead(e, 1) // the refusal's intent
	if err := do(); !errors.Is(err, gatekeeper.ErrNotLogged) {
		t.Fatalf("want a logging failure, got %v", err)
	}
	e.hook, e.now = nil, base
	if gatekeeper.ErrCode(do()) != gatekeeper.CodeRateLimited {
		t.Fatal("expected rate_limited")
	}
	if got := len(e.l.Entries) - before; got != 2 {
		t.Fatalf("the first refusal was never logged: %d new entries, want 2", got)
	}
}

func TestRateLimitDoesNotRepeatTheCountWhenOnlyItsCompletionFailed(t *testing.T) {
	e, g, c := limited(t, 1)
	do := func() error { _, err := g.Do(context.Background(), "actor", "refund", nil); return err }
	if err := do(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_ = do() // one logged refusal, two counted
	}
	c.t = c.t.Add(time.Minute)
	base, before := e.now, len(e.l.Entries)
	failNthClockRead(e, 2) // the count's completion; its intent goes through
	if err := do(); err == nil {
		t.Fatal("expected the count's completion to fail")
	}
	e.hook, e.now = nil, base
	c.t = c.t.Add(time.Minute) // the failed attempt spent this window's one request
	if err := do(); err != nil {
		t.Fatalf("the agent stayed stuck after the log recovered: %v", err)
	}
	// intent (kept), its completion (flushed), then the real action's intent and completion.
	if got := len(e.l.Entries) - before; got != 4 {
		t.Fatalf("%d new entries, want 4: the count was written twice", got)
	}
	e.replays(t)
}

func TestRateLimitWindowSurvivesAClockThatGoesBackwards(t *testing.T) {
	_, g, c := limited(t, 1)
	do := func() error { _, err := g.Do(context.Background(), "actor", "refund", nil); return err }
	c.t = c.t.Add(time.Hour)
	if err := do(); err != nil {
		t.Fatal(err)
	}
	c.t = c.t.Add(-30 * time.Minute)
	if err := do(); err != nil {
		t.Fatalf("a clock that stepped back must start a fresh window, not extend the old one: %v", err)
	}
}
