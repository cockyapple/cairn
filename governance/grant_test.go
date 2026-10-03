package governance

import (
	"bytes"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/cockyapple/cairn/ledger"
)

var rootGrant = Grant{Tools: []string{"fs.read", "http.get", "shell"}, Hosts: []string{"a.example", "b.example"}, Budget: 1000, NotAfter: 9_000_000}

func (w *world) blob(b []byte) ledger.Hash {
	h := ledger.BlobHash(b)
	w.blobs[h] = b
	return h
}

func mustEnc(t *testing.T, g Grant) []byte {
	t.Helper()
	b, err := g.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// proposeGrant files a grant proposal at tier and returns it with the proposal time.
func (w *world) proposeGrant(tier ledger.Tier, agent string, blob []byte) (ledger.Hash, uint64) {
	pr := ledger.Proposal{Tier: tier, Target: GrantTarget(pubOf(agent)), DiffHash: w.blob(blob)}
	h := w.put(ledger.KindProposal, "prop", pr.Encode())
	return h, w.timeOfLast()
}

// grantFor walks a T3 grant to activation and moves the clock past its delay.
func (w *world) grantFor(agent string, g Grant) {
	h, pt := w.proposeGrant(ledger.T3, agent, mustEnc(w.t, g))
	var votes []ledger.Hash
	for _, v := range []string{"sec", "rev1", "rev2"} {
		votes = append(votes, w.vote(v, h, ledger.VerdictApprove))
	}
	w.activate("val", h, pt+7*day, votes...)
	w.now = pt + 7*day
}

func (w *world) lastActionOf(who string) ledger.Hash {
	var h ledger.Hash
	for i := range w.entries {
		if e := &w.entries[i]; e.Kind == ledger.KindAction && e.Author == pubOf(who) {
			h = e.Hash()
		}
	}
	return h
}

// delegateRaw records a cairn/delegate intent whose args blob is args.
func (w *world) delegateRaw(who string, args []byte) {
	a := ledger.Action{ActionType: ActionDelegate, ArgsHash: w.blob(args), PrevActionHash: w.lastActionOf(who)}
	w.put(ledger.KindAction, who, a.Encode())
}

func (w *world) delegate(who, child string, g Grant) {
	b, err := Delegation{Child: pubOf(child), Grant: g}.Encode()
	if err != nil {
		w.t.Fatal(err)
	}
	w.delegateRaw(who, b)
}

func narrower(f func(*Grant)) Grant {
	g := rootGrant
	g.Tools = append([]string(nil), g.Tools...)
	g.Hosts = append([]string(nil), g.Hosts...)
	f(&g)
	return g
}

func TestDelegationNarrowsAndIsRecorded(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	child := Grant{Tools: []string{"fs.read"}, Hosts: []string{"a.example"}, Budget: 10, NotAfter: 8_000_000}
	w.delegate("agent", "agent2", child)
	st, err := w.replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Grants) != 2 {
		t.Fatalf("%+v", st.Grants)
	}
	root, kid := st.Grants[0], st.Grants[1]
	if root.Agent != pubOf("agent") || root.DelegatedBy != nil || root.Grant.Budget != 1000 {
		t.Fatalf("root grant: %+v", root)
	}
	if kid.Agent != pubOf("agent2") || kid.DelegatedBy == nil || *kid.DelegatedBy != pubOf("agent") || kid.Grant.Budget != 10 {
		t.Fatalf("delegated grant: %+v", kid)
	}
	if len(st.OpenIntents) != 1 {
		t.Fatal("the delegation intent is an ordinary open intent until completed")
	}
}

func TestGrandchildMustNarrowTheChildNotTheRoot(t *testing.T) {
	mid := narrower(func(g *Grant) { g.Tools = g.Tools[:1]; g.Budget = 100 }) // fs.read only
	cases := []struct {
		name string
		g    Grant
		code string
	}{
		{"a tool the root held but the child does not", narrower(func(g *Grant) { g.Tools = []string{"shell"}; g.Budget = 1 }), CodeNotNarrower},
		{"the child's own grant again", mid, CodeNotNarrower},
		{"a budget above the child's but below the root's", narrower(func(g *Grant) { g.Tools = g.Tools[:1]; g.Budget = 500 }), CodeNotNarrower},
		{"a strict narrowing of the child", narrower(func(g *Grant) { g.Tools = g.Tools[:1]; g.Budget = 99 }), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			w.grantFor("agent", rootGrant)
			w.delegate("agent", "agent2", mid)
			w.delegate("agent2", "agent3", c.g)
			_, err := w.replay()
			if c.code == "" && err != nil || c.code != "" && ErrCode(err) != c.code {
				t.Fatalf("want %q, got %v", c.code, err)
			}
		})
	}
}

func TestDelegationRules(t *testing.T) {
	cases := []struct {
		name string
		do   func(w *world)
		code string
	}{
		{"one tool fewer is allowed", func(w *world) { w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Tools = g.Tools[1:] })) }, ""},
		{"one host fewer is allowed", func(w *world) { w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Hosts = g.Hosts[:1] })) }, ""},
		{"a smaller budget is allowed", func(w *world) { w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Budget-- })) }, ""},
		{"an earlier end is allowed", func(w *world) { w.delegate("agent", "agent2", narrower(func(g *Grant) { g.NotAfter-- })) }, ""},
		{"an empty grant is allowed", func(w *world) { w.delegate("agent", "agent2", Grant{}) }, ""},
		{"a tool the parent lacks", func(w *world) {
			w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Tools = []string{"fs.read", "fs.write"} }))
		}, CodeNotNarrower},
		{"a host the parent lacks", func(w *world) {
			w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Hosts = []string{"c.example"} }))
		}, CodeNotNarrower},
		{"a bigger budget", func(w *world) { w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Budget++ })) }, CodeNotNarrower},
		{"a bigger budget even with fewer tools", func(w *world) {
			w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Tools = g.Tools[1:]; g.Budget++ }))
		}, CodeNotNarrower},
		{"a later end even with fewer tools", func(w *world) {
			w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Tools = g.Tools[1:]; g.NotAfter++ }))
		}, CodeNotNarrower},
		{"a later end", func(w *world) { w.delegate("agent", "agent2", narrower(func(g *Grant) { g.NotAfter++ })) }, CodeNotNarrower},
		{"no expiry from an expiring parent", func(w *world) {
			w.delegate("agent", "agent2", narrower(func(g *Grant) { g.NotAfter = NoExpiry }))
		}, CodeNotNarrower},
		{"an identical grant is not strictly narrower", func(w *world) { w.delegate("agent", "agent2", rootGrant) }, CodeNotNarrower},
		{"a smaller grant that also adds something", func(w *world) {
			w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Tools = []string{"shell"}; g.Budget = 1; g.NotAfter = 1; g.Hosts = []string{"z"} }))
		}, CodeNotNarrower},
		{"delegating to yourself", func(w *world) { w.delegate("agent", "agent", Grant{}) }, CodeBadDelegation},
		{"delegating to a key that is not an agent", func(w *world) { w.delegate("agent", "prop", Grant{}) }, CodeBadDelegation},
		{"delegating to a key with no role", func(w *world) { w.delegate("agent", "stranger", Grant{}) }, CodeBadDelegation},
		{"delegating to a key that already holds a grant", func(w *world) {
			w.delegate("agent", "agent2", Grant{NotAfter: 8_000_000})
			w.useRaw("agent", ActionEvent, nil)
			w.delegate("agent", "agent2", Grant{Budget: 1, NotAfter: 8_000_000})
		}, CodeBadDelegation},
		{"delegating to a revoked key", func(w *world) {
			w.revoke("sec", "agent2")
			w.delegate("agent", "agent2", Grant{})
		}, CodeRevokedKey},
		{"an agent with no grant", func(w *world) { w.delegate("agent2", "agent", Grant{}) }, CodeBadDelegation},
		{"a grant that has expired", func(w *world) {
			w.now = rootGrant.NotAfter
			w.delegate("agent", "agent2", Grant{})
		}, CodeBadDelegation},
		{"the last moment of a grant", func(w *world) {
			w.now = rootGrant.NotAfter - 1
			w.delegate("agent", "agent2", Grant{})
		}, ""},
		{"args that are not a delegation", func(w *world) { w.delegateRaw("agent", []byte("hello")) }, CodeBadGrant},
		{"args with trailing bytes", func(w *world) {
			b, _ := Delegation{Child: pubOf("agent2")}.Encode()
			w.delegateRaw("agent", append(b, 0))
		}, CodeBadGrant},
		{"args that are not available", func(w *world) {
			a := ledger.Action{ActionType: ActionDelegate, ArgsHash: ledger.Hash{7}, PrevActionHash: w.lastActionOf("agent")}
			w.put(ledger.KindAction, "agent", a.Encode())
		}, CodeBadBlob},
		{"a lookalike of the delegation type is an ordinary action", func(w *world) {
			w.useIntent("agent", "cairn/delegate2", Use{})
		}, CodeToolNotGranted},
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

func TestDelegationBeforeTheGrantIsEffective(t *testing.T) {
	w := newWorld(t)
	h, pt := w.proposeGrant(ledger.T3, "agent", mustEnc(t, rootGrant))
	var votes []ledger.Hash
	for _, v := range []string{"sec", "rev1", "rev2"} {
		votes = append(votes, w.vote(v, h, ledger.VerdictApprove))
	}
	w.activate("val", h, pt+7*day, votes...)
	w.delegate("agent", "agent2", Grant{})
	if _, err := w.replay(); ErrCode(err) != CodeBadDelegation {
		t.Fatalf("a delegation inside the activation delay: %v", err)
	}
}

func TestGrantProposalRules(t *testing.T) {
	good := mustEnc(t, rootGrant)
	target := func(s string) func(*world) ledger.Hash {
		return func(w *world) ledger.Hash {
			pr := ledger.Proposal{Tier: ledger.T3, Target: s, DiffHash: w.blob(good)}
			return w.put(ledger.KindProposal, "prop", pr.Encode())
		}
	}
	hexKey := GrantTarget(pubOf("agent"))
	cases := []struct {
		name string
		do   func(w *world)
		code string
	}{
		{"a T3 grant is accepted", func(w *world) { w.proposeGrant(ledger.T3, "agent", good) }, ""},
		{"a T4 grant is accepted", func(w *world) { w.proposeGrant(ledger.T4, "agent", good) }, ""},
		{"T2 is too low", func(w *world) { w.proposeGrant(ledger.T2, "agent", good) }, CodeReservedTarget},
		{"T0 is too low", func(w *world) { w.proposeGrant(ledger.T0, "agent", good) }, CodeReservedTarget},
		{"a grant for a non-agent", func(w *world) { w.proposeGrant(ledger.T3, "rev1", good) }, CodeBadGrant},
		{"a grant for an unknown key", func(w *world) { w.proposeGrant(ledger.T3, "stranger", good) }, CodeBadGrant},
		{"a grant for a revoked agent", func(w *world) {
			w.revoke("sec", "agent")
			w.proposeGrant(ledger.T3, "agent", good)
		}, CodeRevokedKey},
		{"uppercase hex", func(w *world) { target(GrantTargetPrefix + strings.ToUpper(hexKey[len(GrantTargetPrefix):]))(w) }, CodeReservedTarget},
		{"a short key", func(w *world) { target(hexKey[:len(hexKey)-2])(w) }, CodeReservedTarget},
		{"a long key", func(w *world) { target(hexKey + "00")(w) }, CodeReservedTarget},
		{"not hex", func(w *world) { target(GrantTargetPrefix + strings.Repeat("g", 64))(w) }, CodeReservedTarget},
		{"no key at all", func(w *world) { target(GrantTargetPrefix)(w) }, CodeReservedTarget},
		{"a grant that is not canonical", func(w *world) {
			b := mustEnc(t, Grant{Tools: []string{"a", "b"}})
			b = bytes.Replace(b, []byte("\x01a\x00\x00\x00\x01b"), []byte("\x01b\x00\x00\x00\x01a"), 1)
			w.proposeGrant(ledger.T3, "agent", b)
		}, CodeBadGrant},
		{"a grant with trailing bytes", func(w *world) { w.proposeGrant(ledger.T3, "agent", append(append([]byte(nil), good...), 0)) }, CodeBadGrant},
		{"a missing grant blob", func(w *world) {
			pr := ledger.Proposal{Tier: ledger.T3, Target: hexKey, DiffHash: ledger.Hash{5}}
			w.put(ledger.KindProposal, "prop", pr.Encode())
		}, CodeBadBlob},
		{"another cairn target stays reserved", func(w *world) { w.propose("prop", ledger.T3, "cairn/grants") }, CodeReservedTarget},
		{"the prefix without a slash stays reserved", func(w *world) { w.propose("prop", ledger.T3, "cairn/grant") }, CodeReservedTarget},
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

func TestAgentRevokedBeforeItsGrantActivates(t *testing.T) {
	w := newWorld(t)
	h, pt := w.proposeGrant(ledger.T3, "agent", mustEnc(t, rootGrant))
	var votes []ledger.Hash
	for _, v := range []string{"sec", "rev1", "rev2"} {
		votes = append(votes, w.vote(v, h, ledger.VerdictApprove))
	}
	w.revoke("sec", "agent")
	w.activate("val", h, pt+7*day, votes...)
	if _, err := w.replay(); ErrCode(err) != CodeRevokedKey {
		t.Fatalf("activating a grant for a revoked agent: %v", err)
	}
}

func TestRevocationWithdrawsTheWholeSubtree(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Budget = 50 }))
	w.delegate("agent2", "agent3", narrower(func(g *Grant) { g.Budget = 5 }))
	if st, err := w.replay(); err != nil || len(st.Grants) != 3 {
		t.Fatalf("%v %+v", err, st)
	}
	w.revoke("sec", "agent")
	st, err := w.replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Grants) != 0 {
		t.Fatalf("revoking the root must withdraw what it delegated: %+v", st.Grants)
	}
}

func TestRevokingAChildLeavesTheParent(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Budget = 5 }))
	w.revoke("sec", "agent2")
	st, err := w.replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Grants) != 1 || st.Grants[0].Agent != pubOf("agent") {
		t.Fatalf("%+v", st.Grants)
	}
}

func TestANewRootGrantReplacesTheOld(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	smaller := narrower(func(g *Grant) { g.Budget = 7 })
	w.grantFor("agent", smaller)
	w.propose("prop", ledger.T0, "limits/spend")
	st, err := w.replay()
	if err != nil || len(st.Grants) != 1 || st.Grants[0].Grant.Budget != 7 {
		t.Fatalf("%v %+v", err, st.Grants)
	}
}

func TestGrantEncoding(t *testing.T) {
	g := Grant{Tools: []string{"a", "b"}, Hosts: []string{"h"}, Budget: 3, NotAfter: 4}
	b := mustEnc(t, g)
	back, err := DecodeGrant(b)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := back.Encode(); !bytes.Equal(again, b) {
		t.Fatal("not canonical")
	}
	bad := []struct {
		name string
		g    Grant
	}{
		{"unsorted tools", Grant{Tools: []string{"b", "a"}}},
		{"duplicate hosts", Grant{Hosts: []string{"a", "a"}}},
		{"an empty name", Grant{Tools: []string{""}}},
		{"a long name", Grant{Tools: []string{strings.Repeat("x", maxGrantString+1)}}},
		{"too many names", Grant{Tools: manyNames(maxGrantItems + 1)}},
	}
	for _, c := range bad {
		if _, err := c.g.Encode(); err == nil {
			t.Errorf("%s: encoded", c.name)
		}
	}
	if _, err := (Grant{Tools: manyNames(maxGrantItems)}).Encode(); err != nil {
		t.Errorf("the maximum count must encode: %v", err)
	}
	if _, err := (Grant{Tools: []string{strings.Repeat("x", maxGrantString)}}).Encode(); err != nil {
		t.Errorf("the maximum name length must encode: %v", err)
	}
	for _, cut := range []int{0, 1, len(b) - 1} {
		if _, err := DecodeGrant(b[:cut]); err == nil {
			t.Errorf("a truncated grant of %d bytes decoded", cut)
		}
	}
	if _, err := DecodeGrant(append(append([]byte(nil), b...), 0)); err == nil {
		t.Error("trailing byte accepted")
	}
	v2 := append([]byte(nil), b...)
	v2[0] = 2
	if _, err := DecodeGrant(v2); err == nil {
		t.Error("unknown version accepted")
	}
}

func manyNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("n%04x", i)
	}
	return out
}

func TestStrictlyWithin(t *testing.T) {
	base := Grant{Tools: []string{"a", "b"}, Hosts: []string{"h"}, Budget: 5, NotAfter: 9}
	if base.StrictlyWithin(base) {
		t.Error("a grant is not strictly within itself")
	}
	if !(Grant{Tools: []string{"a"}, Hosts: []string{"h"}, Budget: 5, NotAfter: 9}).StrictlyWithin(base) {
		t.Error("one tool fewer")
	}
	if (Grant{Tools: []string{"a", "c"}, Hosts: []string{"h"}, Budget: 1, NotAfter: 1}).StrictlyWithin(base) {
		t.Error("an extra tool must disqualify however small the rest is")
	}
	if !(Grant{Budget: Unlimited - 1, NotAfter: NoExpiry}).StrictlyWithin(Grant{Budget: Unlimited, NotAfter: NoExpiry}) {
		t.Error("below unlimited")
	}
}

func TestDelegationEncoding(t *testing.T) {
	d := Delegation{Child: pubOf("agent2"), Grant: rootGrant}
	b, err := d.Encode()
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeDelegation(b)
	if err != nil || back.Child != d.Child || back.Grant.Budget != rootGrant.Budget {
		t.Fatalf("%v %+v", err, back)
	}
	if _, err := DecodeDelegation(b[:31]); err == nil {
		t.Error("short child key accepted")
	}
	if !bytes.Equal(b[:32], d.Child[:]) || !bytes.Equal(b[32:], mustEncF(rootGrant)) {
		t.Error("a delegation is the child key followed by the grant blob, nothing between")
	}
	if _, err := (Delegation{Grant: Grant{Tools: []string{"b", "a"}}}).Encode(); err == nil {
		t.Error("a non-canonical grant encoded")
	}
}

func FuzzDecodeGrant(f *testing.F) {
	f.Add(mustEncF(rootGrant))
	f.Add([]byte{})
	f.Add([]byte{1, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, b []byte) {
		g, err := DecodeGrant(b)
		if err != nil {
			return
		}
		again, err := g.Encode()
		if err != nil || !bytes.Equal(again, b) {
			t.Fatalf("a decoded grant must re-encode to the same bytes: %v", err)
		}
	})
}

func mustEncF(g Grant) []byte { b, _ := g.Encode(); return b }

func TestReplacingARootGrantDoesNotShrinkWhatWasDelegated(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Budget = 500 }))
	w.grantFor("agent", narrower(func(g *Grant) { g.Budget = 10 }))
	w.propose("prop", ledger.T0, "limits/spend")
	st, err := w.replay()
	if err != nil || len(st.Grants) != 2 {
		t.Fatalf("%v %+v", err, st.Grants)
	}
	for _, g := range st.Grants {
		if g.Agent == pubOf("agent2") && g.Grant.Budget != 500 {
			t.Fatalf("%+v", g)
		}
	}
}

func (w *world) approveGrant(agent string, g Grant, effectiveIn uint64) {
	h, pt := w.proposeGrant(ledger.T3, agent, mustEnc(w.t, g))
	var votes []ledger.Hash
	for _, v := range []string{"sec", "rev1", "rev2"} {
		votes = append(votes, w.vote(v, h, ledger.VerdictApprove))
	}
	w.activate("val", h, pt+effectiveIn, votes...)
}

func TestARootGrantReplacesTheOldOnlyWhenItTakesEffect(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	w.approveGrant("agent", narrower(func(g *Grant) { g.Budget = 7 }), 7*day)
	pending := w.now
	w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Budget = 500 }))
	st, err := w.replay()
	if err != nil {
		t.Fatalf("a delegation inside the new grant's delay is judged against the old grant: %v", err)
	}
	for _, g := range st.Grants {
		if g.Agent == pubOf("agent") && g.Grant.Budget != 1000 {
			t.Fatalf("the scheduled grant is already listed as in force: %+v", g)
		}
	}
	w.now = pending + 7*day
	w.delegate("agent", "agent3", narrower(func(g *Grant) { g.Budget = 500 }))
	if _, err := w.replay(); ErrCode(err) != CodeNotNarrower {
		t.Fatalf("once the new grant is effective it is the one that counts: %v", err)
	}
}

func TestALaterActivationSupersedesAnEarlierOne(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	w.approveGrant("agent", narrower(func(g *Grant) { g.Budget = 7 }), 30*day)
	w.approveGrant("agent", narrower(func(g *Grant) { g.Budget = 8 }), 8*day)
	w.now += 31 * day
	w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Budget = 8; g.Tools = g.Tools[:1] }))
	st, err := w.replay()
	if err != nil {
		t.Fatalf("the grant activated last must win even though the other took effect later: %v", err)
	}
	for _, g := range st.Grants {
		if g.Agent == pubOf("agent") && g.Grant.Budget != 8 {
			t.Fatalf("%+v", g)
		}
	}
}

func TestAnExpiredGrantIsNotHeld(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", rootGrant)
	w.delegate("agent", "agent2", narrower(func(g *Grant) { g.NotAfter = w.now + 100 }))
	w.now += 1000
	w.propose("prop", ledger.T0, "limits/spend")
	st, err := w.replay()
	if err != nil || len(st.Grants) != 1 || st.Grants[0].Agent != pubOf("agent") {
		t.Fatalf("an expired grant is not in force: %v %+v", err, st.Grants)
	}
	w.delegate("agent", "agent2", narrower(func(g *Grant) { g.NotAfter = 5_000_000 }))
	if _, err := w.replay(); err != nil {
		t.Fatalf("a key whose grant expired can be given a new one: %v", err)
	}
}

func TestNoExpiryNeverExpires(t *testing.T) {
	w := newWorld(t)
	w.grantFor("agent", narrower(func(g *Grant) { g.NotAfter = NoExpiry }))
	w.now = math.MaxUint64
	w.delegate("agent", "agent2", narrower(func(g *Grant) { g.Budget = 5; g.NotAfter = NoExpiry }))
	if _, err := w.replay(); err != nil {
		t.Fatalf("a grant with no expiry holds at the largest entry time: %v", err)
	}
}

func TestGrantNamesMustBeUTF8(t *testing.T) {
	if _, err := (Grant{Tools: []string{"\xff"}, Budget: 1, NotAfter: NoExpiry}).Encode(); err == nil {
		t.Fatal("Encode accepted a name that Decode would refuse")
	}
}

func TestRevokedAgentNeverGetsItsScheduledGrant(t *testing.T) {
	w := newWorld(t)
	w.approveGrant("agent", rootGrant, 7*day)
	w.revoke("sec", "agent")
	w.now += 8 * day
	w.propose("prop", ledger.T0, "limits/spend")
	st, err := w.replay()
	if err != nil || len(st.Grants) != 0 {
		t.Fatalf("a key revoked before its grant took effect must never hold it: %v %+v", err, st.Grants)
	}
}
