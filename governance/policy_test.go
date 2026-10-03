package governance

import (
	"testing"

	"github.com/cockyapple/cairn/ledger"
)

// setRequire walks a T4 require-grants proposal to activation, effective
// effectiveIn seconds after it was filed (never less than the T4 delay), and
// returns the time it takes effect. It does not move the clock.
func (w *world) setRequire(on bool, effectiveIn uint64) uint64 {
	pr := ledger.Proposal{Tier: ledger.T4, Target: PolicyTarget, DiffHash: w.blob(RequirePolicy{Require: on}.Encode())}
	h := w.put(ledger.KindProposal, "prop", pr.Encode())
	pt := w.timeOfLast()
	var votes []ledger.Hash
	for _, v := range []string{"sec", "rev1", "rev2"} {
		votes = append(votes, w.vote(v, h, ledger.VerdictApprove))
	}
	w.activate("val", h, pt+effectiveIn, votes...)
	return pt + effectiveIn
}

func (w *world) ungrantedAct(who string) {
	w.put(ledger.KindAction, who, (&ledger.Action{ActionType: "anything", ArgsHash: ledger.Hash{9}, PrevActionHash: w.lastActionOf(who)}).Encode())
}

func TestRequirePolicyEncoding(t *testing.T) {
	for _, on := range []bool{false, true} {
		got, err := DecodeRequirePolicy(RequirePolicy{Require: on}.Encode())
		if err != nil || got.Require != on {
			t.Fatalf("%v -> %+v, %v", on, got, err)
		}
	}
	for name, b := range map[string][]byte{
		"empty":           nil,
		"version only":    {1},
		"flag 2":          {1, 2},
		"flag 255":        {1, 255},
		"unknown version": {2, 1},
		"trailing byte":   {1, 1, 0},
	} {
		if _, err := DecodeRequirePolicy(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRequireGrantsHoldsAnAgentThatNeverHadOne(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	w.ungrantedAct("agent2")
	eff := w.setRequire(true, 14*day)
	w.ungrantedAct("agent2")
	st, err := w.replay()
	if err != nil {
		t.Fatalf("until the policy takes effect an ungranted agent acts freely: %v", err)
	}
	if st.RequireGrants() {
		t.Fatal("reported as in force before its effective time")
	}
	w.now = eff - 1
	w.ungrantedAct("agent2")
	if _, err := w.replay(); err != nil {
		t.Fatalf("one second before the effective time: %v", err)
	}
	w.now = eff
	w.ungrantedAct("agent2")
	if _, err := w.replay(); ErrCode(err) != CodeNoGrant {
		t.Fatalf("at the effective time an ungranted agent is refused: %v", err)
	}
}

func TestRequireGrantsIsReportedOnceInForce(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	eff := w.setRequire(true, 14*day)
	w.now = eff
	w.useIntent("agent", "shell", spend(1))
	st, err := w.replay()
	if err != nil {
		t.Fatal(err)
	}
	if !st.RequireGrants() {
		t.Fatal("not reported")
	}
}

func TestRequireGrantsLeavesGrantedAgentsAndEventsAlone(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	w.now = w.setRequire(true, 14*day)
	w.useIntent("agent", "shell", spend(10))
	w.useDone("agent", "shell", spend(10))
	w.useRaw("agent2", ActionEvent, []byte("a refusal"))
	if _, err := w.replay(); err != nil {
		t.Fatalf("a granted agent acts and anyone may log an event: %v", err)
	}
	w.useIntent("agent", "fs.write", spend(1))
	if _, err := w.replay(); ErrCode(err) != CodeToolNotGranted {
		t.Fatalf("a granted agent is still held to its grant: %v", err)
	}
}

func TestRequireGrantsLetsADelegateAct(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	w.now = w.setRequire(true, 14*day)
	w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Tools = g.Tools[:1] }))
	w.useIntent("agent2", "fs.read", spend(1))
	if _, err := w.replay(); err != nil {
		t.Fatalf("an agent that is handed a grant is no longer ungranted: %v", err)
	}
}

func TestRequireGrantsDoesNotStrandAnIntentOpenBeforeIt(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	w.ungrantedAct("agent2")
	w.now = w.setRequire(true, 14*day)
	w.put(ledger.KindAction, "agent2", (&ledger.Action{ActionType: "anything", ArgsHash: ledger.Hash{9}, ResultHash: ledger.Hash{1}, PrevActionHash: w.lastActionOf("agent2")}).Encode())
	if _, err := w.replay(); err != nil {
		t.Fatalf("a completion is never checked: %v", err)
	}
}

func TestRequireGrantsCanBeSwitchedOff(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	w.now = w.setRequire(true, 14*day)
	off := w.setRequire(false, 14*day)
	w.ungrantedAct("agent2")
	if _, err := w.replay(); ErrCode(err) != CodeNoGrant {
		t.Fatalf("the switch-off is not yet in force: %v", err)
	}
	w.entries = w.entries[:len(w.entries)-1]
	w.now = off
	w.ungrantedAct("agent2")
	st, err := w.replay()
	if err != nil {
		t.Fatalf("after it takes effect the agent may act again: %v", err)
	}
	if st.RequireGrants() {
		t.Fatal("still reported as required")
	}
}

func TestALaterRequirePolicySupersedesAnEarlierOne(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	w.setRequire(true, 30*day)
	w.setRequire(false, 15*day)
	w.now += 31 * day
	w.ungrantedAct("agent2")
	st, err := w.replay()
	if err != nil {
		t.Fatalf("the policy activated last must win even though the other takes effect later: %v", err)
	}
	if st.RequireGrants() {
		t.Fatal("reported as required")
	}
}

func TestRequirePolicyProposalRules(t *testing.T) {
	cases := []struct {
		name string
		do   func(w *world)
		code string
	}{
		{"a well formed T4 proposal", func(w *world) { w.setRequire(true, 14*day) }, ""},
		{"below T4", func(w *world) {
			w.put(ledger.KindProposal, "prop", (&ledger.Proposal{Tier: ledger.T3, Target: PolicyTarget, DiffHash: w.blob(RequirePolicy{Require: true}.Encode())}).Encode())
		}, CodeReservedTarget},
		{"a blob that is not a policy", func(w *world) {
			w.put(ledger.KindProposal, "prop", (&ledger.Proposal{Tier: ledger.T4, Target: PolicyTarget, DiffHash: w.blob([]byte{1, 2})}).Encode())
		}, CodeBadPolicy},
		{"a blob that is not supplied", func(w *world) {
			w.put(ledger.KindProposal, "prop", (&ledger.Proposal{Tier: ledger.T4, Target: PolicyTarget, DiffHash: ledger.Hash{3}}).Encode())
		}, CodeBadBlob},
		{"another target under the policy namespace", func(w *world) {
			w.put(ledger.KindProposal, "prop", (&ledger.Proposal{Tier: ledger.T4, Target: "cairn/policy/other", DiffHash: w.blob(RequirePolicy{}.Encode())}).Encode())
		}, CodeReservedTarget},
		{"a delay shorter than T4 needs", func(w *world) { w.setRequire(true, 13*day) }, CodeDelayTooShort},
		{"during a freeze", func(w *world) {
			w.freeze("val", ledger.FreezeScope(1))
			w.setRequire(true, 14*day)
		}, CodeFrozen},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			c.do(w)
			_, err := w.replay()
			if c.code == "" {
				if err != nil {
					t.Fatalf("want success, got %v", err)
				}
				return
			}
			if ErrCode(err) != c.code {
				t.Fatalf("want %s, got %v", c.code, err)
			}
		})
	}
}
