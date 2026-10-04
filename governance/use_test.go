package governance

import (
	"bytes"
	"math"
	"testing"

	"github.com/cockyapple/cairn/ledger"
)

// useIntent records an intent whose args blob is the canonical Use u.
func (w *world) useIntent(who, typ string, u Use) {
	a := ledger.Action{ActionType: typ, ArgsHash: w.blob(u.Encode()), PrevActionHash: w.lastActionOf(who)}
	w.put(ledger.KindAction, who, a.Encode())
}

// useDone completes the oldest open intent that carries u.
func (w *world) useDone(who, typ string, u Use) {
	a := ledger.Action{ActionType: typ, ArgsHash: ledger.BlobHash(u.Encode()), ResultHash: ledger.Hash{1}, PrevActionHash: w.lastActionOf(who)}
	w.put(ledger.KindAction, who, a.Encode())
}

// useRaw records an intent whose args blob is b, whatever it holds.
func (w *world) useRaw(who, typ string, b []byte) {
	a := ledger.Action{ActionType: typ, ArgsHash: w.blob(b), PrevActionHash: w.lastActionOf(who)}
	w.put(ledger.KindAction, who, a.Encode())
}

func spend(cost uint64) Use { return Use{Host: "a.example", Cost: cost, Args: []byte("x")} }

var commitment = ledger.BlobHash([]byte("withheld args"))

func committed(cost uint64) Use { return Use{Host: "a.example", Cost: cost, Commit: &commitment} }

func TestUseRoundTrips(t *testing.T) {
	for _, u := range []Use{{}, {Host: "a.example", Cost: 7, Args: []byte("hi")}, {Cost: math.MaxUint64, Args: make([]byte, 1000)}} {
		got, err := DecodeUse(u.Encode())
		if err != nil || got.Host != u.Host || got.Cost != u.Cost || string(got.Args) != string(u.Args) {
			t.Fatalf("%+v -> %+v, %v", u, got, err)
		}
	}
	good := Use{Host: "h", Cost: 1, Args: []byte("a")}.Encode()
	for name, b := range map[string][]byte{
		"empty":            nil,
		"truncated":        good[:len(good)-1],
		"trailing byte":    append(append([]byte(nil), good...), 0),
		"unknown version":  append([]byte{3}, good[1:]...),
		"v2 truncated":     {2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3},
		"host not UTF-8":   {1, 0, 0, 0, 1, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		"version only":     {1},
		"oversized length": {1, 0xff, 0xff, 0xff, 0xff},
	} {
		if _, err := DecodeUse(b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestBoundAgentIsHeldToItsGrant(t *testing.T) {
	cases := []struct {
		name string
		do   func(w *world)
		code string
	}{
		{"a granted tool on a granted host within budget", func(w *world) { w.useIntent("agent", "shell", spend(10)) }, ""},
		{"no host at all", func(w *world) { w.useIntent("agent", "fs.read", Use{Cost: 1}) }, ""},
		{"a tool the grant lacks", func(w *world) { w.useIntent("agent", "fs.write", spend(1)) }, CodeToolNotGranted},
		{"a tool whose name only starts like a granted one", func(w *world) { w.useIntent("agent", "shell2", spend(1)) }, CodeToolNotGranted},
		{"a host the grant lacks", func(w *world) { w.useIntent("agent", "shell", Use{Host: "c.example"}) }, CodeHostNotGranted},
		{"a host that only starts like a granted one", func(w *world) { w.useIntent("agent", "shell", Use{Host: "a.example.evil"}) }, CodeHostNotGranted},
		{"the whole budget in one action", func(w *world) { w.useIntent("agent", "shell", spend(1000)) }, ""},
		{"one more than the budget", func(w *world) { w.useIntent("agent", "shell", spend(1001)) }, CodeBudgetExceeded},
		{"a cost that would overflow a sum", func(w *world) { w.useIntent("agent", "shell", spend(math.MaxUint64)) }, CodeBudgetExceeded},
		{"a cost that would overflow a sum after some spending", func(w *world) {
			w.useIntent("agent", "shell", spend(1))
			w.useDone("agent", "shell", spend(1))
			w.useIntent("agent", "shell", spend(math.MaxUint64))
		}, CodeBudgetExceeded},
		{"actions that add up to the budget", func(w *world) {
			w.useIntent("agent", "shell", spend(600))
			w.useDone("agent", "shell", spend(600))
			w.useIntent("agent", "shell", spend(400))
		}, ""},
		{"actions that add up to more than the budget", func(w *world) {
			w.useIntent("agent", "shell", spend(600))
			w.useDone("agent", "shell", spend(600))
			w.useIntent("agent", "shell", spend(401))
		}, CodeBudgetExceeded},
		{"a free action after the budget is gone", func(w *world) {
			w.useIntent("agent", "shell", spend(1000))
			w.useDone("agent", "shell", spend(1000))
			w.useIntent("agent", "shell", spend(0))
		}, ""},
		{"a refused-looking action still spent its reservation", func(w *world) {
			w.useIntent("agent", "shell", spend(1000))
			w.useDone("agent", "shell", spend(1000))
			w.useIntent("agent", "shell", spend(1))
		}, CodeBudgetExceeded},
		{"a committed use within the grant", func(w *world) { w.useIntent("agent", "shell", committed(10)) }, ""},
		{"a committed use on a host the grant lacks", func(w *world) { w.useIntent("agent", "shell", Use{Host: "c.example", Commit: &commitment}) }, CodeHostNotGranted},
		{"a committed use over the budget", func(w *world) { w.useIntent("agent", "shell", committed(1001)) }, CodeBudgetExceeded},
		{"args that are not a use", func(w *world) { w.useRaw("agent", "shell", []byte("hello")) }, CodeBadUse},
		{"a use with a trailing byte", func(w *world) { w.useRaw("agent", "shell", append(spend(1).Encode(), 0)) }, CodeBadUse},
		{"a use blob that is not supplied", func(w *world) {
			a := ledger.Action{ActionType: "shell", ArgsHash: ledger.Hash{7}, PrevActionHash: w.lastActionOf("agent")}
			w.put(ledger.KindAction, "agent", a.Encode())
		}, CodeBadBlob},
		{"the last moment of the grant", func(w *world) { w.now = rootGrant.NotAfter - 1; w.useIntent("agent", "shell", spend(1)) }, ""},
		{"an expired grant", func(w *world) { w.now = rootGrant.NotAfter; w.useIntent("agent", "shell", spend(1)) }, CodeGrantExpired},
		{"an expired grant does not make the agent free again", func(w *world) {
			w.now = rootGrant.NotAfter
			w.useRaw("agent", "shell", []byte("hello"))
		}, CodeGrantExpired},
		{"a completion after the grant expired", func(w *world) {
			w.now = rootGrant.NotAfter - 1
			w.useIntent("agent", "shell", spend(1))
			w.now = rootGrant.NotAfter + 5
			w.useDone("agent", "shell", spend(1))
		}, ""},
		{"an event needs no grant and costs nothing", func(w *world) {
			w.useIntent("agent", "shell", spend(1000))
			w.useDone("agent", "shell", spend(1000))
			w.useRaw("agent", ActionEvent, []byte("anything"))
		}, ""},
		{"an exhausted agent can still delegate", func(w *world) {
			w.useIntent("agent", "shell", spend(1000))
			w.useDone("agent", "shell", spend(1000))
			w.delegate("agent", "agent2", Grant{NotAfter: 8_000_000})
		}, ""},
		{"an agent that was never granted is not bound", func(w *world) {
			w.put(ledger.KindAction, "agent2", (&ledger.Action{ActionType: "anything", ArgsHash: ledger.Hash{9}}).Encode())
		}, ""},
		{"a delegated agent is bound too", func(w *world) {
			w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Tools = g.Tools[:1] }))
			w.useIntent("agent2", "shell", spend(1))
		}, CodeToolNotGranted},
		{"a delegated agent with its own grant acts", func(w *world) {
			w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Tools = g.Tools[:1] }))
			w.useIntent("agent2", "fs.read", spend(1))
		}, ""},
		{"a delegated agent loses its grant when its parent is revoked", func(w *world) {
			w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Budget = 10 }))
			w.revoke("sec", "agent")
			w.useIntent("agent2", "shell", spend(1))
		}, CodeNoGrant},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			w.grantFor("agent", rootGrant)
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

func TestUnlimitedBudgetNeverRunsOut(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", narrower(func(g *Grant) { g.Budget = Unlimited }))
	for i := 0; i < 3; i++ {
		w.useIntent("agent", "shell", spend(math.MaxUint64))
		w.useDone("agent", "shell", spend(math.MaxUint64))
	}
	st, err := w.replay()
	if err != nil {
		t.Fatal(err)
	}
	if st.Grants[0].Spent != 0 {
		t.Fatalf("an unlimited grant keeps no count: %d", st.Grants[0].Spent)
	}
}

func TestBudgetIsSharedDownTheDelegationChain(t *testing.T) {
	setup := func(t *testing.T) *world {
		w := newWorld(t)
		w.grantFor("agent", rootGrant) // 1000
		w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Budget = 600 }))
		w.delegate("agent", "agent3", narrower(func(g *Grant) { g.Budget = 600 }))
		return w
	}
	t.Run("a child's spending comes out of its parent's budget", func(t *testing.T) {
		w := setup(t)
		w.useIntent("agent2", "shell", spend(600))
		w.useDone("agent2", "shell", spend(600))
		w.useIntent("agent", "shell", spend(400))
		st, err := w.replay()
		if err != nil {
			t.Fatal(err)
		}
		spent := map[[32]byte]uint64{}
		for _, g := range st.Grants {
			spent[g.Agent] = g.Spent
		}
		if spent[pubOf("agent")] != 1000 || spent[pubOf("agent2")] != 600 || spent[pubOf("agent3")] != 0 {
			t.Fatalf("spent: %v", spent)
		}
	})
	t.Run("the parent cannot overspend what its child used", func(t *testing.T) {
		w := setup(t)
		w.useIntent("agent2", "shell", spend(600))
		w.useDone("agent2", "shell", spend(600))
		w.useIntent("agent", "shell", spend(401))
		if _, err := w.replay(); ErrCode(err) != CodeBudgetExceeded {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("two children cannot together exceed the parent", func(t *testing.T) {
		w := setup(t)
		w.useIntent("agent2", "shell", spend(600))
		w.useDone("agent2", "shell", spend(600))
		w.useIntent("agent3", "shell", spend(401))
		if _, err := w.replay(); ErrCode(err) != CodeBudgetExceeded {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("two children within the parent's remainder are fine", func(t *testing.T) {
		w := setup(t)
		w.useIntent("agent2", "shell", spend(600))
		w.useDone("agent2", "shell", spend(600))
		w.useIntent("agent3", "shell", spend(400))
		if _, err := w.replay(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("a child cannot exceed its own budget although its parent has room", func(t *testing.T) {
		w := setup(t)
		w.useIntent("agent2", "shell", spend(601))
		if _, err := w.replay(); ErrCode(err) != CodeBudgetExceeded {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a grandchild is charged to every grant above it", func(t *testing.T) {
		w := newWorld(t)
		w.grantFor("agent", rootGrant)
		w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Budget = 600 }))
		w.delegate("agent2", "agent3", narrower(func(g *Grant) { g.Budget = 500 }))
		w.useIntent("agent3", "shell", spend(500))
		w.useDone("agent3", "shell", spend(500))
		w.useIntent("agent2", "shell", spend(101))
		if _, err := w.replay(); ErrCode(err) != CodeBudgetExceeded {
			t.Fatalf("middle grant: %v", err)
		}
		w = newWorld(t)
		w.grantFor("agent", rootGrant)
		w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Budget = 600 }))
		w.delegate("agent2", "agent3", narrower(func(g *Grant) { g.Budget = 500 }))
		w.useIntent("agent3", "shell", spend(500))
		w.useDone("agent3", "shell", spend(500))
		w.useIntent("agent", "shell", spend(501))
		if _, err := w.replay(); ErrCode(err) != CodeBudgetExceeded {
			t.Fatalf("root grant: %v", err)
		}
	})
	t.Run("a spent descendant under an exhausted ancestor is blocked", func(t *testing.T) {
		w := setup(t)
		w.useIntent("agent", "shell", spend(1000))
		w.useIntent("agent2", "shell", spend(1))
		if _, err := w.replay(); ErrCode(err) != CodeBudgetExceeded {
			t.Fatalf("got %v", err)
		}
	})
}

func TestANewRootGrantStartsANewBudget(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	w.useIntent("agent", "shell", spend(1000))
	w.useDone("agent", "shell", spend(1000))
	w.grantFor("agent", narrower(func(g *Grant) { g.Budget = 900 }))
	w.useIntent("agent", "shell", spend(900))
	st, err := w.replay()
	if err != nil {
		t.Fatal(err)
	}
	if st.Grants[0].Spent != 900 {
		t.Fatalf("spent %d", st.Grants[0].Spent)
	}
	w.useDone("agent", "shell", spend(900))
	w.useIntent("agent", "shell", spend(1))
	if _, err := w.replay(); ErrCode(err) != CodeBudgetExceeded {
		t.Fatalf("got %v", err)
	}
}

func TestAnAgentIsBoundOnlyOnceItsGrantIsEffective(t *testing.T) {
	w := newWorld(t)
	if w.replayState(t).Bound(pubOf("agent")) {
		t.Fatal("bound before any grant")
	}
	h, pt := w.proposeGrant(ledger.T3, "agent", mustEnc(t, rootGrant))
	var votes []ledger.Hash
	for _, v := range []string{"sec", "rev1", "rev2"} {
		votes = append(votes, w.vote(v, h, ledger.VerdictApprove))
	}
	w.activate("val", h, pt+7*day, votes...)
	w.put(ledger.KindAction, "agent", (&ledger.Action{ActionType: "anything", ArgsHash: ledger.Hash{1}}).Encode())
	if w.replayState(t).Bound(pubOf("agent")) {
		t.Fatal("bound while the grant is only scheduled")
	}
	w.now = pt + 7*day
	w.put(ledger.KindAction, "agent", (&ledger.Action{ActionType: "x", ArgsHash: ledger.Hash{2}, PrevActionHash: w.lastActionOf("agent")}).Encode())
	if _, err := w.replay(); ErrCode(err) != CodeBadBlob {
		t.Fatalf("the first action after the grant took effect must carry a use: %v", err)
	}
}

func (w *world) replayState(t *testing.T) *State {
	t.Helper()
	st, err := w.replay()
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestDelegationCannotMakeACycle(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Budget = 600 }))
	w.delegate("agent2", "agent3", narrower(func(g *Grant) { g.Budget = 500 }))
	// A replacement root grant that ends at once leaves agent expired while its
	// delegates still hold theirs; handing agent a grant from below would close a loop.
	w.grantFor("agent", Grant{Budget: 1, NotAfter: w.now + 7*day + 20})
	w.now += 7*day + 10
	w.delegate("agent3", "agent", Grant{Budget: 1, NotAfter: 8_000_000})
	if _, err := w.replay(); ErrCode(err) != CodeBadDelegation {
		t.Fatalf("got %v", err)
	}
}

func TestStateReportsBoundAgents(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	w.delegate("agent", "agent2", Grant{NotAfter: 8_000_000})
	st := w.replayState(t)
	if !st.Bound(pubOf("agent")) || !st.Bound(pubOf("agent2")) || st.Bound(pubOf("agent3")) {
		t.Fatal("bound set is wrong")
	}
}

func TestRevokingAParentKeepsAChildsOwnScheduledRootGrant(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Budget = 600 }))
	w.approveGrant("agent2", narrower(func(g *Grant) { g.Budget = 300 }), 7*day)
	w.revoke("sec", "agent")
	w.useIntent("agent2", "shell", spend(1))
	if _, err := w.replay(); ErrCode(err) != CodeNoGrant {
		t.Fatalf("the delegated grant must go with its parent: %v", err)
	}

	w = newWorld(t)
	w.grantFor("agent", rootGrant)
	w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Budget = 600 }))
	w.approveGrant("agent2", narrower(func(g *Grant) { g.Budget = 300 }), 7*day)
	w.revoke("sec", "agent")
	w.now += 8 * day
	w.useIntent("agent2", "shell", spend(300))
	st, err := w.replay()
	if err != nil {
		t.Fatalf("a root grant approved for the child does not come from the revoked parent: %v", err)
	}
	var got *GrantInfo
	for i := range st.Grants {
		if st.Grants[i].Agent == pubOf("agent2") {
			got = &st.Grants[i]
		}
	}
	if got == nil || got.Spent != 300 || len(st.Grants) != 1 {
		t.Fatalf("grants after revoke: %+v", st.Grants)
	}
}

func TestCommittedUseRoundTripsAndIsJudgedByHostAndCost(t *testing.T) {
	c := ledger.BlobHash([]byte("args"))
	u := Use{Host: "a.example", Cost: 7, Commit: &c}
	got, err := DecodeUse(u.Encode())
	if err != nil || got.Host != u.Host || got.Cost != 7 || got.Commit == nil || *got.Commit != c || got.Args != nil {
		t.Fatalf("%+v %v", got, err)
	}
	if u.Encode()[0] != 2 || len(u.Encode()) != 1+4+len("a.example")+8+32 {
		t.Fatalf("encoding: %x", u.Encode())
	}
	if _, err := DecodeUse(append(u.Encode(), 0)); err == nil {
		t.Fatal("trailing byte accepted")
	}
}

func FuzzDecodeUse(f *testing.F) {
	c := ledger.BlobHash([]byte("c"))
	f.Add(Use{Host: "a.example", Cost: 5, Args: []byte("x")}.Encode())
	f.Add(Use{Host: "a.example", Cost: 5, Commit: &c}.Encode())
	f.Add([]byte{})
	f.Add([]byte{2})
	f.Fuzz(func(t *testing.T, b []byte) {
		u, err := DecodeUse(b)
		if err != nil {
			return
		}
		if again := u.Encode(); !bytes.Equal(again, b) {
			t.Fatalf("a decoded use must re-encode to the same bytes: %x != %x", again, b)
		}
	})
}
