package governance

import (
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"sort"
	"testing"

	"github.com/cockyapple/cairn/ledger"
)

const hour, day = 3600, 24 * 3600

var roles = map[string]ledger.Role{
	"val": ledger.RoleValidator, "wit": ledger.RoleWitness,
	"rev1": ledger.RoleReviewer, "rev2": ledger.RoleReviewer, "rev3": ledger.RoleReviewer,
	"sec": ledger.RoleSecurityReviewer, "prop": ledger.RoleProposer,
	"agent": ledger.RoleAgent, "agent2": ledger.RoleAgent,
}

type world struct {
	t       *testing.T
	keys    map[string]ed25519.PrivateKey
	entries []ledger.Entry
	blobs   MapBlobs
	now     uint64
	n       int
}

func key(name string) ed25519.PrivateKey {
	seed := sha256.Sum256([]byte("cairn-governance-test-" + name))
	return ed25519.NewKeyFromSeed(seed[:])
}

func pubOf(name string) (p [32]byte) { copy(p[:], key(name).Public().(ed25519.PublicKey)); return }

func trustConfig(epoch uint64, extra ...string) ledger.TrustConfig {
	var names []string
	for n := range roles {
		names = append(names, n)
	}
	sort.Strings(names)
	tc := ledger.TrustConfig{Epoch: epoch}
	for _, n := range names {
		tc.Keys = append(tc.Keys, ledger.Key{Role: roles[n], Public: pubOf(n)})
	}
	for _, n := range extra {
		tc.Keys = append(tc.Keys, ledger.Key{Role: ledger.RoleReviewer, Public: pubOf(n)})
	}
	return tc
}

func newWorld(t *testing.T) *world {
	w := &world{t: t, keys: map[string]ed25519.PrivateKey{}, blobs: MapBlobs{}, now: 1_000_000}
	for n := range roles {
		w.keys[n] = key(n)
	}
	w.keys["rev4"], w.keys["stranger"] = key("rev4"), key("stranger")
	g := ledger.Genesis{SpecVersion: 1, ConstitutionHash: ledger.BlobHash([]byte("constitution")), Trust: trustConfig(0)}
	w.put(ledger.KindGenesis, "val", g.Encode())
	return w
}

func (w *world) put(kind ledger.Kind, who string, payload []byte) ledger.Hash {
	e := ledger.Entry{Height: uint64(len(w.entries)), Kind: kind, PayloadHash: ledger.BlobHash(payload), Time: w.now}
	if len(w.entries) > 0 {
		e.PrevHash = w.entries[len(w.entries)-1].Hash()
	}
	e.Sign(w.keys[who])
	w.entries = append(w.entries, e)
	w.blobs[e.PayloadHash] = payload
	w.now++
	return e.Hash()
}

func (w *world) propose(who string, tier ledger.Tier, target string) ledger.Hash {
	w.n++
	p := ledger.Proposal{Tier: tier, Target: target, DiffHash: ledger.BlobHash([]byte(fmt.Sprint("diff", w.n)))}
	return w.put(ledger.KindProposal, who, p.Encode())
}

func (w *world) vote(who string, prop ledger.Hash, v ledger.Verdict) ledger.Hash {
	return w.put(ledger.KindVote, who, (&ledger.Vote{ProposalHash: prop, Verdict: v}).Encode())
}

func (w *world) activate(who string, prop ledger.Hash, effective uint64, votes ...ledger.Hash) ledger.Hash {
	return w.put(ledger.KindActivate, who, (&ledger.Activate{ProposalHash: prop, VoteHashes: votes, EffectiveAfter: effective}).Encode())
}

func (w *world) freeze(who string, s ledger.FreezeScope) ledger.Hash {
	return w.put(ledger.KindFreeze, who, (&ledger.Freeze{Scope: s}).Encode())
}

func (w *world) action(who, typ string, args byte, result byte, prev ledger.Hash) ledger.Hash {
	a := ledger.Action{ActionType: typ, ArgsHash: ledger.Hash{args}, PrevActionHash: prev}
	if result != 0 {
		a.ResultHash = ledger.Hash{result}
	}
	return w.put(ledger.KindAction, who, a.Encode())
}

func (w *world) replay() (*State, error) { return Replay(w.entries, w.blobs, Options{}) }

func (w *world) timeOfLast() uint64 { return w.entries[len(w.entries)-1].Time }

// approved returns a T1..T4 proposal with enough approvals for its tier.
func (w *world) approved(tier ledger.Tier, target string) (ledger.Hash, []ledger.Hash, uint64) {
	p := w.propose("prop", tier, target)
	pt := w.timeOfLast()
	var votes []ledger.Hash
	voters := []string{"sec", "rev1", "rev2"}
	for i := 0; i < approvals[tier].total; i++ {
		votes = append(votes, w.vote(voters[i], p, ledger.VerdictApprove))
	}
	return p, votes, pt
}

func TestLawfulHistoryReplays(t *testing.T) {
	w := newWorld(t)

	// T0 needs no votes and no delay.
	p0 := w.propose("agent", ledger.T0, "limits/spend")
	w.activate("val", p0, w.timeOfLast())

	// T2: two approvals, one from security, 72 h.
	p2, votes, pt := w.approved(ledger.T2, "tools/browser")
	w.activate("val", p2, pt+72*hour, votes...)

	// A frozen log still takes ACTIONs and T0 activations, but not T1.
	w.freeze("sec", ledger.FreezeActivations)
	p0b := w.propose("prop", ledger.T0, "limits/blocklist")
	w.activate("val", p0b, w.timeOfLast())
	w.freeze("val", ledger.FreezeLift)

	// ACTION: intent, completion, chained to the agent's own history.
	a1 := w.action("agent", "tool_call", 1, 0, ledger.Hash{})
	a2 := w.action("agent", "tool_call", 1, 9, a1)
	w.action("agent", "spend", 2, 0, a2)

	st, err := w.replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Activations) != 3 || st.Frozen || st.Completed != 1 || len(st.OpenIntents) != 1 || st.OpenIntents[0].ActionType != "spend" {
		t.Fatalf("unexpected state: %+v", st)
	}
}

func TestOpenIntentIsReported(t *testing.T) {
	w := newWorld(t)
	w.action("agent", "spend", 7, 0, ledger.Hash{})
	st, err := w.replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.OpenIntents) != 1 || st.OpenIntents[0].Agent != pubOf("agent") || st.OpenIntents[0].ActionType != "spend" {
		t.Fatalf("open intent not reported: %+v", st.OpenIntents)
	}
	// Completing it closes it.
	w.action("agent", "spend", 7, 3, st.OpenIntents[0].Hash)
	if st, err = w.replay(); err != nil || len(st.OpenIntents) != 0 {
		t.Fatalf("completion did not close the intent: %v %+v", err, st)
	}
}

func TestValidatorRotation(t *testing.T) {
	w := newWorld(t)
	next := trustConfig(1, "rev4")
	diff := ledger.BlobHash(next.Encode())
	p := ledger.Proposal{Tier: ledger.T4, Target: targetValidators, DiffHash: diff}
	ph := w.put(ledger.KindProposal, "prop", p.Encode())
	pt := w.timeOfLast()
	old := w.propose("prop", ledger.T1, "prompt/system") // issued before the rotation
	votes := []ledger.Hash{
		w.vote("sec", ph, ledger.VerdictApprove),
		w.vote("rev1", ph, ledger.VerdictApprove),
		w.vote("rev2", ph, ledger.VerdictApprove),
	}
	w.activate("val", ph, pt+14*day, votes...)
	w.now = pt + 14*day
	w.put(ledger.KindValidators, "val", next.Encode())
	size := uint64(len(w.entries))

	st, err := w.replay()
	if err != nil {
		t.Fatal(err)
	}
	if st.Trust().Epoch != 1 || len(st.Epochs) != 2 {
		t.Fatalf("epoch not advanced: %+v", st.Epochs)
	}
	if tc, _ := st.TrustForSize(size - 1); tc.Epoch != 0 {
		t.Fatal("a checkpoint before the rotation is judged by the old set")
	}
	if tc, _ := st.TrustForSize(size); tc.Epoch != 1 {
		t.Fatal("a checkpoint covering the rotation is judged by the new set")
	}
	if _, ok := st.TrustForSize(size + 1); ok {
		t.Fatal("size beyond the log must not resolve")
	}

	// The new reviewer can now vote, and the old open proposal is void.
	w.vote("rev4", old, ledger.VerdictApprove)
	if _, err := w.replay(); ErrCode(err) != CodeWrongEpoch {
		t.Fatalf("vote on a pre-rotation proposal: %v", err)
	}
}

func TestViolations(t *testing.T) {
	const T1d = day
	zero := ledger.Hash{}
	cases := []struct {
		name string
		code string
		run  func(w *world)
	}{
		{"agent cannot vote (I1)", CodeUnauthorizedAuthor, func(w *world) {
			p := w.propose("agent", ledger.T1, "prompt/system")
			w.vote("agent", p, ledger.VerdictApprove)
		}},
		{"agent cannot activate its own change (I1)", CodeUnauthorizedAuthor, func(w *world) {
			p := w.propose("agent", ledger.T0, "limits/x")
			w.activate("agent", p, w.timeOfLast())
		}},
		{"reviewer cannot activate", CodeUnauthorizedAuthor, func(w *world) {
			p := w.propose("prop", ledger.T0, "limits/x")
			w.activate("rev1", p, w.timeOfLast())
		}},
		{"proposer cannot act", CodeUnauthorizedAuthor, func(w *world) { w.action("prop", "spend", 1, 0, zero) }},
		{"validator cannot propose", CodeUnauthorizedAuthor, func(w *world) { w.propose("val", ledger.T0, "x") }},
		{"stranger cannot propose", CodeUnauthorizedAuthor, func(w *world) { w.propose("stranger", ledger.T0, "x") }},
		{"only validators lift a freeze", CodeUnauthorizedAuthor, func(w *world) {
			w.freeze("sec", ledger.FreezeActivations)
			w.freeze("sec", ledger.FreezeLift)
		}},
		{"reviewer cannot freeze", CodeUnauthorizedAuthor, func(w *world) { w.freeze("rev1", ledger.FreezeActivations) }},
		{"genesis author must be a validator", CodeUnauthorizedAuthor, func(w *world) {
			w.entries, w.blobs = nil, MapBlobs{}
			g := ledger.Genesis{SpecVersion: 1, Trust: trustConfig(0)}
			w.put(ledger.KindGenesis, "stranger", g.Encode())
		}},
		{"missing blob", CodeBadBlob, func(w *world) {
			w.propose("prop", ledger.T0, "x")
			delete(w.blobs, w.entries[len(w.entries)-1].PayloadHash)
		}},
		{"blob does not match hash", CodeBadBlob, func(w *world) {
			w.propose("prop", ledger.T0, "x")
			w.blobs[w.entries[len(w.entries)-1].PayloadHash] = []byte("something else")
		}},
		{"time goes backwards", CodeTimeRegression, func(w *world) {
			w.propose("prop", ledger.T0, "x")
			w.now -= 100
			w.propose("prop", ledger.T0, "y")
		}},
		{"reserved target below T4", CodeReservedTarget, func(w *world) { w.propose("prop", ledger.T3, targetValidators) }},
		{"reserved namespace", CodeReservedTarget, func(w *world) { w.propose("prop", ledger.T4, "cairn/anything-else") }},
		{"vote for nothing", CodeUnknownProposal, func(w *world) { w.vote("rev1", ledger.Hash{1}, ledger.VerdictApprove) }},
		{"vote for a non-proposal", CodeUnknownProposal, func(w *world) {
			p := w.propose("prop", ledger.T1, "x")
			v := w.vote("rev1", p, ledger.VerdictApprove)
			w.vote("rev2", v, ledger.VerdictApprove)
		}},
		{"activate nothing", CodeUnknownProposal, func(w *world) { w.activate("val", ledger.Hash{2}, w.now) }},
		{"duplicate vote", CodeDuplicateVote, func(w *world) {
			p := w.propose("prop", ledger.T1, "x")
			w.vote("rev1", p, ledger.VerdictApprove)
			w.vote("rev1", p, ledger.VerdictReject)
		}},
		{"double activation", CodeAlreadyActivated, func(w *world) {
			p := w.propose("prop", ledger.T0, "x")
			w.activate("val", p, w.timeOfLast())
			w.activate("val", p, w.timeOfLast())
		}},
		{"vote after activation", CodeAlreadyActivated, func(w *world) {
			p := w.propose("prop", ledger.T0, "x")
			w.activate("val", p, w.timeOfLast())
			w.vote("rev1", p, ledger.VerdictApprove)
		}},
		{"same vote listed twice", CodeBadVoteReference, func(w *world) {
			p := w.propose("prop", ledger.T1, "x")
			pt := w.timeOfLast()
			v := w.vote("rev1", p, ledger.VerdictApprove)
			w.activate("val", p, pt+T1d, v, v)
		}},
		{"vote for another proposal listed", CodeBadVoteReference, func(w *world) {
			p := w.propose("prop", ledger.T1, "x")
			pt := w.timeOfLast()
			q := w.propose("prop", ledger.T1, "y")
			v := w.vote("rev1", q, ledger.VerdictApprove)
			w.activate("val", p, pt+T1d, v)
		}},
		{"invented vote listed", CodeBadVoteReference, func(w *world) {
			p := w.propose("prop", ledger.T1, "x")
			pt := w.timeOfLast()
			w.activate("val", p, pt+T1d, ledger.Hash{3})
		}},
		{"a reject vote vetoes", CodeBlockedByVote, func(w *world) {
			p := w.propose("prop", ledger.T1, "x")
			pt := w.timeOfLast()
			a := w.vote("rev1", p, ledger.VerdictApprove)
			w.vote("rev2", p, ledger.VerdictReject)
			w.activate("val", p, pt+T1d, a)
		}},
		{"an escalate vote blocks", CodeBlockedByVote, func(w *world) {
			p := w.propose("prop", ledger.T1, "x")
			pt := w.timeOfLast()
			a := w.vote("rev1", p, ledger.VerdictApprove)
			w.vote("sec", p, ledger.VerdictEscalate)
			w.activate("val", p, pt+T1d, a)
		}},
		{"T1 with no approvals", CodeInsufficientApprovals, func(w *world) {
			p := w.propose("prop", ledger.T1, "x")
			w.activate("val", p, w.timeOfLast()+T1d)
		}},
		{"T2 without a security reviewer", CodeInsufficientApprovals, func(w *world) {
			p := w.propose("prop", ledger.T2, "x")
			pt := w.timeOfLast()
			a, b := w.vote("rev1", p, ledger.VerdictApprove), w.vote("rev2", p, ledger.VerdictApprove)
			w.activate("val", p, pt+72*hour, a, b)
		}},
		{"T3 with one reviewer short", CodeInsufficientApprovals, func(w *world) {
			p := w.propose("prop", ledger.T3, "x")
			pt := w.timeOfLast()
			a, b := w.vote("sec", p, ledger.VerdictApprove), w.vote("rev1", p, ledger.VerdictApprove)
			w.activate("val", p, pt+7*day, a, b)
		}},
		{"T1 one hour short", CodeDelayTooShort, func(w *world) {
			p := w.propose("prop", ledger.T1, "x")
			pt := w.timeOfLast()
			v := w.vote("rev1", p, ledger.VerdictApprove)
			w.activate("val", p, pt+24*hour-1, v)
		}},
		{"effective before the proposal", CodeDelayTooShort, func(w *world) {
			w.now += 500
			p := w.propose("prop", ledger.T0, "x")
			w.activate("val", p, w.timeOfLast()-1)
		}},
		{"no T1 activation during a freeze", CodeFrozen, func(w *world) {
			w.freeze("val", ledger.FreezeActivations)
			p := w.propose("prop", ledger.T1, "x")
			pt := w.timeOfLast()
			v := w.vote("rev1", p, ledger.VerdictApprove)
			w.activate("val", p, pt+T1d, v)
		}},
		{"lift without a freeze", CodeBadFreezeState, func(w *world) { w.freeze("val", ledger.FreezeLift) }},
		{"freeze twice", CodeBadFreezeState, func(w *world) {
			w.freeze("val", ledger.FreezeActivations)
			w.freeze("sec", ledger.FreezeActivations)
		}},
		{"validators change with no authorisation", CodeBadValidatorsChange, func(w *world) {
			w.put(ledger.KindValidators, "val", func() []byte { tc := trustConfig(1); return tc.Encode() }())
		}},
		{"validators change differs from the approved diff", CodeBadValidatorsChange, func(w *world) {
			p, votes, pt := w.approved(ledger.T4, targetValidators)
			w.activate("val", p, pt+14*day, votes...)
			w.now = pt + 14*day
			other := trustConfig(1)
			w.put(ledger.KindValidators, "val", other.Encode())
		}},
		{"validators change before it is effective", CodeDelayNotElapsed, func(w *world) {
			next := trustConfig(1, "rev4")
			p := ledger.Proposal{Tier: ledger.T4, Target: targetValidators, DiffHash: ledger.BlobHash(next.Encode())}
			ph := w.put(ledger.KindProposal, "prop", p.Encode())
			pt := w.timeOfLast()
			votes := []ledger.Hash{w.vote("sec", ph, ledger.VerdictApprove), w.vote("rev1", ph, ledger.VerdictApprove), w.vote("rev2", ph, ledger.VerdictApprove)}
			w.activate("val", ph, pt+14*day, votes...)
			w.put(ledger.KindValidators, "val", next.Encode())
		}},
		{"validators epoch skips", CodeWrongEpoch, func(w *world) {
			tc := trustConfig(2)
			w.put(ledger.KindValidators, "val", tc.Encode())
		}},
		{"validators change during a freeze", CodeFrozen, func(w *world) {
			next := trustConfig(1, "rev4")
			p := ledger.Proposal{Tier: ledger.T4, Target: targetValidators, DiffHash: ledger.BlobHash(next.Encode())}
			ph := w.put(ledger.KindProposal, "prop", p.Encode())
			pt := w.timeOfLast()
			votes := []ledger.Hash{w.vote("sec", ph, ledger.VerdictApprove), w.vote("rev1", ph, ledger.VerdictApprove), w.vote("rev2", ph, ledger.VerdictApprove)}
			w.activate("val", ph, pt+14*day, votes...)
			w.freeze("val", ledger.FreezeActivations)
			w.now = pt + 14*day
			w.put(ledger.KindValidators, "val", next.Encode())
		}},
		{"action chain skips an entry", CodeBadActionChain, func(w *world) {
			w.action("agent", "spend", 1, 0, zero)
			w.action("agent", "spend", 2, 0, zero)
		}},
		{"action chain is per agent", CodeBadActionChain, func(w *world) {
			a := w.action("agent", "spend", 1, 0, zero)
			w.action("agent2", "spend", 1, 0, a)
		}},
		{"completion with no intent", CodeBadActionCompletion, func(w *world) { w.action("agent", "spend", 1, 5, zero) }},
		{"completion for a different action", CodeBadActionCompletion, func(w *world) {
			a := w.action("agent", "spend", 1, 0, zero)
			w.action("agent", "spend", 2, 5, a)
		}},
		{"completions close the oldest intent first", CodeBadActionCompletion, func(w *world) {
			a := w.action("agent", "spend", 1, 0, zero)
			b := w.action("agent", "spend", 2, 0, a)
			w.action("agent", "spend", 2, 5, b)
		}},
		{"only agent and proposer keys can be revoked", CodeBadRevocation, func(w *world) { w.revoke("sec", "rev1") }},
		{"a revoked key cannot write", CodeRevokedKey, func(w *world) { w.revoke("val", "agent"); w.action("agent", "spend", 1, 0, zero) }},
		{"a malformed payload keeps the ledger code", ledger.CodeBadPayload, func(w *world) {
			w.put(ledger.KindActivate, "val", []byte("short"))
		}},
	}

	covered := map[string]bool{}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			c.run(w)
			_, err := w.replay()
			if got := ErrCode(err); got != c.code {
				t.Fatalf("got %q (%v), want %q", got, err, c.code)
			}
			covered[c.code] = true
		})
	}

	// Constitution mismatch is an option, not an entry.
	w := newWorld(t)
	bad := ledger.Hash{9}
	_, err := Replay(w.entries, w.blobs, Options{ConstitutionHash: &bad})
	if ErrCode(err) != CodeConstitutionMismatch {
		t.Fatalf("constitution mismatch: %v", err)
	}
	covered[CodeConstitutionMismatch] = true
	// tier_too_low and future_entry are options too; TestVerifierTierFloor and
	// TestVerifierClockRejectsFutureEntries assert them.
	covered[CodeTierTooLow], covered[CodeFutureEntry] = true, true
	good := ledger.BlobHash([]byte("constitution"))
	if _, err := Replay(w.entries, w.blobs, Options{ConstitutionHash: &good}); err != nil {
		t.Fatalf("matching constitution rejected: %v", err)
	}

	for _, code := range AllCodes {
		if !covered[code] {
			t.Errorf("error code %q is never exercised by a test", code)
		}
	}
}

// Authenticity is checked before lawfulness, and keeps the ledger's codes.
func TestChainErrorsComeFirst(t *testing.T) {
	w := newWorld(t)
	w.propose("prop", ledger.T0, "x")
	w.entries[1].Signature[0] ^= 1
	if _, err := w.replay(); ErrCode(err) != ledger.CodeBadSignature {
		t.Fatalf("got %v", err)
	}
}

// A T0 activation is the only way through a freeze, so a rollback to a safer
// configuration (a tightening) must stay possible.
func TestFreezeLeavesRollbackAndActionsOpen(t *testing.T) {
	w := newWorld(t)
	w.freeze("val", ledger.FreezeActivations)
	a := w.action("agent", "tool_call", 1, 0, ledger.Hash{})
	w.action("agent", "tool_call", 1, 4, a)
	p := w.propose("agent", ledger.T0, "limits/spend")
	w.activate("val", p, w.timeOfLast())
	st, err := w.replay()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Frozen || len(st.Activations) != 1 {
		t.Fatalf("%+v", st)
	}
}

func TestReplayIsDeterministic(t *testing.T) {
	w := newWorld(t)
	p, v, pt := w.approved(ledger.T3, "perm/x")
	w.activate("val", p, pt+7*day, v...)
	a, err1 := w.replay()
	b, err2 := w.replay()
	if err1 != nil || err2 != nil || fmt.Sprint(a) != fmt.Sprint(b) {
		t.Fatal("replay differs between runs")
	}
}

func TestVerifierTierFloor(t *testing.T) {
	w := newWorld(t)
	w.propose("prop", ledger.T0, "agent/app")
	floor := func(target string) ledger.Tier {
		if target == "agent/app" {
			return ledger.T2
		}
		return ledger.T0
	}
	if _, err := Replay(w.entries, w.blobs, Options{}); err != nil {
		t.Fatalf("no policy: %v", err)
	}
	_, err := Replay(w.entries, w.blobs, Options{MinTier: floor})
	if ErrCode(err) != CodeTierTooLow {
		t.Fatalf("want %s, got %v", CodeTierTooLow, err)
	}
	w2 := newWorld(t)
	w2.propose("prop", ledger.T2, "agent/app")
	if _, err := Replay(w2.entries, w2.blobs, Options{MinTier: floor}); err != nil {
		t.Fatalf("meets the floor: %v", err)
	}
}

func TestVerifierClockRejectsFutureEntries(t *testing.T) {
	w := newWorld(t)
	w.now += 14 * day
	w.propose("prop", ledger.T0, "agent/app")
	if _, err := Replay(w.entries, w.blobs, Options{}); err != nil {
		t.Fatalf("no clock: %v", err)
	}
	real := w.entries[0].Time
	_, err := Replay(w.entries, w.blobs, Options{Now: real + 60, MaxSkew: 300})
	if ErrCode(err) != CodeFutureEntry {
		t.Fatalf("want %s, got %v", CodeFutureEntry, err)
	}
	if _, err := Replay(w.entries, w.blobs, Options{Now: w.now, MaxSkew: 300}); err != nil {
		t.Fatalf("clock caught up: %v", err)
	}
}
