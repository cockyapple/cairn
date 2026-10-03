package gatekeeper_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"github.com/cockyapple/cairn/gatekeeper"
	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
	"github.com/cockyapple/cairn/review"
)

const day = 24 * 3600

type genv struct {
	l                             *review.Log
	val, sec, r1, r2, prop, actor ed25519.PrivateKey
	free                          ed25519.PrivateKey
	now                           uint64
	hook                          func()
	g                             *gatekeeper.Gatekeeper
	ran                           []string
}

// grantSetup builds a log with two agents and gives "actor" a root grant that
// takes effect after its activation delay, which it waits out only when wait is set.
func grantSetup(t *testing.T, gr governance.Grant, wait bool, agent *gatekeeper.Agent) *genv {
	t.Helper()
	e := &genv{val: key("gval"), sec: key("gsec"), r1: key("gr1"), r2: key("gr2"), prop: key("gprop"), actor: key("gactor"), free: key("gfree"), now: 1_000_000}
	trust := ledger.TrustConfig{Keys: []ledger.Key{
		{Role: ledger.RoleValidator, Public: pub(e.val)}, {Role: ledger.RoleSecurityReviewer, Public: pub(e.sec)},
		{Role: ledger.RoleReviewer, Public: pub(e.r1)}, {Role: ledger.RoleReviewer, Public: pub(e.r2)},
		{Role: ledger.RoleProposer, Public: pub(e.prop)},
		{Role: ledger.RoleAgent, Public: pub(e.actor)}, {Role: ledger.RoleAgent, Public: pub(e.free)},
	}}
	l, err := review.New(e.val, ledger.BlobHash([]byte("c")), trust, func() uint64 {
		e.now++
		if e.hook != nil {
			e.hook()
		}
		return e.now
	})
	if err != nil {
		t.Fatal(err)
	}
	e.l = l
	p, err := l.ProposeGrant(e.prop, ledger.T3, pub(e.actor), gr, []byte("test"))
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []ed25519.PrivateKey{e.sec, e.r1, e.r2} {
		if _, err := l.Vote(k, p, ledger.VerdictApprove, nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := l.Activate(e.val, p); err != nil {
		t.Fatal(err)
	}
	if wait {
		e.now += 8 * day
	}
	e.g = gatekeeper.New(l)
	agent.Name, agent.Key = "actor", e.actor
	if err := e.g.AddAgent(agent); err != nil {
		t.Fatal(err)
	}
	if err := e.g.AddAgent(&gatekeeper.Agent{Name: "free", Key: e.free, Allow: []string{"shell", "fetch"}}); err != nil {
		t.Fatal(err)
	}
	for _, typ := range []string{"shell", "fetch", "refund", "bus.send:order"} {
		typ := typ
		e.g.Handle(typ, func(_ context.Context, a []byte) ([]byte, error) {
			e.ran = append(e.ran, typ+":"+string(a))
			return []byte("done"), nil
		})
	}
	return e
}

func (e *genv) replays(t *testing.T) *governance.State {
	t.Helper()
	st, err := governance.Replay(e.l.Entries, e.l.Blobs, governance.Options{})
	if err != nil {
		t.Fatalf("log does not replay: %v", err)
	}
	return st
}

func (e *genv) lastAction(t *testing.T, kindOffset int) ledger.Action {
	t.Helper()
	ent := e.l.Entries[len(e.l.Entries)-1-kindOffset]
	a, err := ledger.DecodeAction(e.l.Blobs[ent.PayloadHash])
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (e *genv) spent(t *testing.T) uint64 {
	t.Helper()
	for _, gi := range e.replays(t).Grants {
		if gi.Agent == pub(e.actor) {
			return gi.Spent
		}
	}
	t.Fatal("no grant in force for the actor")
	return 0
}

func testGrant() governance.Grant {
	return governance.Grant{Tools: []string{"bus.send:order", "fetch", "shell"}, Hosts: []string{"a.example"}, Budget: 100, NotAfter: governance.NoExpiry}
}

func TestAgentWithoutAGrantIsLoggedPlain(t *testing.T) {
	e := grantSetup(t, testGrant(), true, &gatekeeper.Agent{Allow: []string{"shell"}})
	if _, err := e.g.Do(context.Background(), "free", "shell", []byte("ls")); err != nil {
		t.Fatal(err)
	}
	a := e.lastAction(t, 1)
	if a.ActionType != "shell" || string(e.l.Blobs[a.ArgsHash]) != "ls" {
		t.Fatalf("an unbound agent must be recorded as before: %+v", a)
	}
	e.replays(t)
}

func TestBoundAgentActsInsideItsGrantAndIsCharged(t *testing.T) {
	e := grantSetup(t, testGrant(), true, &gatekeeper.Agent{Allow: []string{"shell", "fetch"}})
	ctx := context.Background()
	if _, err := e.g.DoUse(ctx, "actor", "shell", []byte("ls"), "a.example", 60); err != nil {
		t.Fatal(err)
	}
	intent, done := e.lastAction(t, 1), e.lastAction(t, 0)
	u, err := governance.DecodeUse(e.l.Blobs[intent.ArgsHash])
	if err != nil || u.Host != "a.example" || u.Cost != 60 || string(u.Args) != "ls" || intent.ActionType != "shell" {
		t.Fatalf("the intent must carry the use: %+v %+v %v", intent, u, err)
	}
	if done.ArgsHash != intent.ArgsHash || done.ResultHash == (ledger.Hash{}) {
		t.Fatal("the completion must repeat the intent's arguments")
	}
	if got := e.spent(t); got != 60 {
		t.Fatalf("spent %d", got)
	}
	if _, err := e.g.DoUse(ctx, "actor", "fetch", []byte("x"), "", 40); err != nil {
		t.Fatalf("exactly the rest of the budget: %v", err)
	}
	if got := e.spent(t); got != 100 {
		t.Fatalf("spent %d", got)
	}
	// Do is DoUse with nothing declared; it costs nothing.
	if _, err := e.g.Do(ctx, "actor", "shell", []byte("pwd")); err != nil {
		t.Fatal(err)
	}
	if want := []string{"shell:ls", "fetch:x", "shell:pwd"}; strings.Join(e.ran, ",") != strings.Join(want, ",") {
		t.Fatalf("ran %v", e.ran)
	}
	if st := e.replays(t); len(st.OpenIntents) != 0 {
		t.Fatalf("%+v", st.OpenIntents)
	}
}

func TestActionOutsideTheGrantIsRefusedAndRecorded(t *testing.T) {
	e := grantSetup(t, testGrant(), true, &gatekeeper.Agent{Allow: []string{"shell", "fetch", "refund"}})
	ctx := context.Background()
	cases := []struct {
		name, typ, host string
		cost            uint64
		want            string
	}{
		{"a tool the grant lacks", "refund", "", 0, governance.CodeToolNotGranted},
		{"a host the grant lacks", "shell", "evil.example", 0, governance.CodeHostNotGranted},
		{"more than the budget", "shell", "a.example", 101, governance.CodeBudgetExceeded},
	}
	for _, c := range cases {
		before := len(e.ran)
		_, err := e.g.DoUse(ctx, "actor", c.typ, []byte("x"), c.host, c.cost)
		if gatekeeper.ErrCode(err) != gatekeeper.CodeOutOfGrant || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v", c.name, err)
		}
		if len(e.ran) != before {
			t.Fatalf("%s: the handler ran", c.name)
		}
		intent, done := e.lastAction(t, 1), e.lastAction(t, 0)
		if intent.ActionType != governance.ActionEvent || done.ActionType != governance.ActionEvent || !strings.HasPrefix(e.lastResultOf(done), "refused\n"+gatekeeper.CodeOutOfGrant) {
			t.Fatalf("%s: the refusal must be an event: %+v / %q", c.name, intent, e.lastResultOf(done))
		}
	}
	if got := e.spent(t); got != 0 {
		t.Fatalf("a refused action charged %d", got)
	}
	if st := e.replays(t); len(st.OpenIntents) != 0 {
		t.Fatalf("%+v", st.OpenIntents)
	}
}

func (e *genv) lastResultOf(a ledger.Action) string { return string(e.l.Blobs[a.ResultHash]) }

func TestRefusalsOfABoundAgentDoNotNeedAGrant(t *testing.T) {
	e := grantSetup(t, testGrant(), true, &gatekeeper.Agent{Allow: []string{"shell"}, RateLimit: 1})
	ctx := context.Background()
	if _, err := e.g.Do(ctx, "actor", "shell", nil); err != nil {
		t.Fatal(err)
	}
	// Not in Allow, not in the grant, and over the rate limit: all recorded, none checked.
	for _, typ := range []string{"fs.write", "shell"} {
		if _, err := e.g.Do(ctx, "actor", typ, []byte("x")); gatekeeper.ErrCode(err) == "" {
			t.Fatalf("%s: want a refusal, got %v", typ, err)
		}
	}
	if got := e.spent(t); got != 0 {
		t.Fatalf("spent %d", got)
	}
	if st := e.replays(t); len(st.OpenIntents) != 0 {
		t.Fatalf("%+v", st.OpenIntents)
	}
}

func TestReservedActionTypesAreRefused(t *testing.T) {
	e := grantSetup(t, testGrant(), true, &gatekeeper.Agent{Allow: []string{"cairn/event", "cairn/delegate"}})
	e.g.Handle("cairn/event", func(context.Context, []byte) ([]byte, error) { e.ran = append(e.ran, "ran"); return nil, nil })
	for _, typ := range []string{"cairn/event", "cairn/delegate"} {
		_, err := e.g.DoUse(context.Background(), "actor", typ, []byte("x"), "", 1<<40)
		if gatekeeper.ErrCode(err) != gatekeeper.CodeNotPermitted || len(e.ran) != 0 {
			t.Fatalf("%s: %v ran=%v", typ, err, e.ran)
		}
	}
	e.replays(t)
}

func TestTaintResetOfABoundAgentIsAnEvent(t *testing.T) {
	e := grantSetup(t, testGrant(), true, &gatekeeper.Agent{Allow: []string{"fetch", "shell"}, Untrusted: []string{"fetch"}, Guard: []string{"shell"}})
	ctx := context.Background()
	if _, err := e.g.DoUse(ctx, "actor", "fetch", []byte("u"), "a.example", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := e.g.Do(ctx, "actor", "shell", nil); gatekeeper.ErrCode(err) != gatekeeper.CodeTaintedInput {
		t.Fatalf("%v", err)
	}
	if err := e.g.ResetTaint("actor", "checked by a person"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.g.Do(ctx, "actor", "shell", nil); err != nil {
		t.Fatal(err)
	}
	if got := e.spent(t); got != 1 {
		t.Fatalf("spent %d", got)
	}
	e.replays(t)
}

func TestBusSendOfABoundAgentNeedsItsToolInTheGrant(t *testing.T) {
	e := grantSetup(t, testGrant(), true, &gatekeeper.Agent{Allow: []string{"bus.send:order"}})
	if err := e.g.DeclareMessage(&gatekeeper.MessageType{Name: "order", From: []string{"actor"}, To: []string{"free"}, Validate: gatekeeper.Strict()}); err != nil {
		t.Fatal(err)
	}
	if err := e.g.Send(context.Background(), "actor", "free", "order", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	e.replays(t)
}

func TestFirstActionAfterTheGrantTakesEffectIsRecordedAsBound(t *testing.T) {
	e := grantSetup(t, testGrant(), false, &gatekeeper.Agent{Allow: []string{"shell"}})
	ctx := context.Background()
	if _, err := e.g.Do(ctx, "actor", "shell", []byte("early")); err != nil {
		t.Fatalf("before its grant takes effect the agent is not held to it: %v", err)
	}
	e.now += 8 * day
	// No entry has been replayed since the grant took effect, so the state is
	// one step behind the log; the gatekeeper must not be fooled by that.
	if _, err := e.g.DoUse(ctx, "actor", "shell", []byte("late"), "a.example", 7); err != nil {
		t.Fatal(err)
	}
	u, err := governance.DecodeUse(e.l.Blobs[e.lastAction(t, 1).ArgsHash])
	if err != nil || u.Cost != 7 {
		t.Fatalf("%+v %v", u, err)
	}
	if got := e.spent(t); got != 7 {
		t.Fatalf("spent %d", got)
	}
	e.replays(t)
}

func TestExpiredGrantRefusesAction(t *testing.T) {
	gr := testGrant()
	gr.NotAfter = 1_000_000 + 8*day + 100
	e := grantSetup(t, gr, true, &gatekeeper.Agent{Allow: []string{"shell"}})
	ctx := context.Background()
	if _, err := e.g.Do(ctx, "actor", "shell", nil); err != nil {
		t.Fatal(err)
	}
	e.now += 200
	_, err := e.g.Do(ctx, "actor", "shell", nil)
	if gatekeeper.ErrCode(err) != gatekeeper.CodeOutOfGrant || !strings.Contains(err.Error(), governance.CodeGrantExpired) {
		t.Fatalf("%v", err)
	}
	e.replays(t)
}

func TestCompletionOfABoundAgentIsRetriedInTheSameForm(t *testing.T) {
	e := grantSetup(t, testGrant(), true, &gatekeeper.Agent{Allow: []string{"shell"}})
	base := e.now
	e.l.Opt = governance.Options{Now: base + 20}
	runs := 0
	e.g.Handle("shell", func(context.Context, []byte) ([]byte, error) {
		runs++
		if runs == 1 {
			e.now += 1000
		}
		return nil, nil
	})
	ctx := context.Background()
	if _, err := e.g.DoUse(ctx, "actor", "shell", []byte("a"), "a.example", 5); err == nil || !strings.Contains(err.Error(), "could not be logged") {
		t.Fatalf("want a completion failure, got %v", err)
	}
	if _, err := e.g.DoUse(ctx, "actor", "shell", []byte("b"), "a.example", 5); !errors.Is(err, gatekeeper.ErrNotLogged) || runs != 1 {
		t.Fatalf("err=%v runs=%d", err, runs)
	}
	e.now = base + 2
	if _, err := e.g.DoUse(ctx, "actor", "shell", []byte("c"), "a.example", 5); err != nil {
		t.Fatalf("the agent stayed stuck: %v", err)
	}
	if st := e.replays(t); len(st.OpenIntents) != 0 || e.spent(t) != 10 {
		t.Fatalf("open %+v spent %d", st.OpenIntents, e.spent(t))
	}
}

func TestRefusalErrorsWrapTheGovernanceError(t *testing.T) {
	e := grantSetup(t, testGrant(), true, &gatekeeper.Agent{Allow: []string{"refund"}})
	_, err := e.g.DoUse(context.Background(), "actor", "refund", nil, "", 0)
	var r *gatekeeper.Refusal
	if !errors.As(err, &r) || r.Code != gatekeeper.CodeOutOfGrant {
		t.Fatalf("%v", err)
	}
}

func TestReservedTypeRefusalOfAnUnboundAgentIsStillLogged(t *testing.T) {
	e := grantSetup(t, testGrant(), true, &gatekeeper.Agent{Allow: []string{"shell"}})
	for _, typ := range []string{"cairn/delegate", "cairn/event"} {
		_, err := e.g.Do(context.Background(), "free", typ, []byte("x"))
		if gatekeeper.ErrCode(err) != gatekeeper.CodeNotPermitted || errors.Is(err, gatekeeper.ErrNotLogged) {
			t.Fatalf("%s: %v", typ, err)
		}
		if a := e.lastAction(t, 1); a.ActionType != governance.ActionEvent {
			t.Fatalf("the record of a refused %s must be an event, not the reserved type: %+v", typ, a)
		}
	}
	e.replays(t)
}

func TestArgsThatLookLikeAUseCannotDeclareTheActionInTheAgentsPlace(t *testing.T) {
	e := grantSetup(t, testGrant(), false, &gatekeeper.Agent{Allow: []string{"shell"}})
	ctx := context.Background()
	if _, err := e.g.Do(ctx, "actor", "shell", []byte("early")); err != nil {
		t.Fatal(err)
	}
	e.now += 8 * day
	// The state is one step behind, so the agent still looks unbound. Its own
	// args happen to be a valid, permissive use blob; the declaration that counts
	// is the one passed to DoUse.
	crafted := governance.Use{Cost: 0, Args: []byte("p")}.Encode()
	_, err := e.g.DoUse(ctx, "actor", "shell", crafted, "evil.example", 999)
	if gatekeeper.ErrCode(err) != gatekeeper.CodeOutOfGrant || len(e.ran) != 1 {
		t.Fatalf("the declared host and cost must be checked: %v ran=%v", err, e.ran)
	}
	if got := e.spent(t); got != 0 {
		t.Fatalf("spent %d", got)
	}
	e.replays(t)
}

func TestHostThatCannotBeRecordedIsRefusedAndLogged(t *testing.T) {
	e := grantSetup(t, testGrant(), true, &gatekeeper.Agent{Allow: []string{"shell"}})
	for _, who := range []string{"actor", "free"} {
		for _, host := range []string{"\xff", "ok\xc3"} {
			_, err := e.g.DoUse(context.Background(), who, "shell", nil, host, 1)
			if gatekeeper.ErrCode(err) != gatekeeper.CodeNotPermitted || errors.Is(err, gatekeeper.ErrNotLogged) {
				t.Fatalf("%s %d-byte host: %v", who, len(host), err)
			}
		}
	}
	e.replays(t)
	if len(e.ran) != 0 {
		t.Fatal("the action ran")
	}
}
