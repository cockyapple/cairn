package loader_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"sort"
	"testing"

	"github.com/cockyapple/cairn/eval"
	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
	"github.com/cockyapple/cairn/loader"
	"github.com/cockyapple/cairn/review"
)

const hour, day = 3600, 24 * 3600

type cast struct {
	val, wit, rev1, rev2, rev3, sec, prop ed25519.PrivateKey
}

func k(name string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("cairn-loader-test-" + name))
	return ed25519.NewKeyFromSeed(s[:])
}

func pub(p ed25519.PrivateKey) (o [32]byte) { copy(o[:], p.Public().(ed25519.PublicKey)); return }

func newCast() cast {
	return cast{k("val"), k("wit"), k("rev1"), k("rev2"), k("rev3"), k("sec"), k("prop")}
}

func (c cast) trust() ledger.TrustConfig {
	return ledger.TrustConfig{Epoch: 0, WitnessThreshold: 1, Keys: []ledger.Key{
		{Role: ledger.RoleValidator, Public: pub(c.val)},
		{Role: ledger.RoleWitness, Public: pub(c.wit)},
		{Role: ledger.RoleReviewer, Public: pub(c.rev1)},
		{Role: ledger.RoleReviewer, Public: pub(c.rev2)},
		{Role: ledger.RoleReviewer, Public: pub(c.rev3)},
		{Role: ledger.RoleSecurityReviewer, Public: pub(c.sec)},
		{Role: ledger.RoleProposer, Public: pub(c.prop)},
	}}
}

type clock struct{ t uint64 }

func (c *clock) now() uint64 { c.t++; return c.t }

func newLog(t *testing.T) (*review.Log, cast, *clock) {
	t.Helper()
	c, ck := newCast(), &clock{t: 1_000_000}
	l, err := review.New(c.val, ledger.BlobHash([]byte("constitution")), c.trust(), ck.now)
	if err != nil {
		t.Fatal(err)
	}
	return l, c, ck
}

func open(t *testing.T, l *review.Log, c cast) (*loader.Gate, error) {
	t.Helper()
	sc := l.Checkpoint(c.val, c.wit)
	return loader.Open(l.Entries, l.Blobs, &sc, governance.Options{})
}

func mustOpen(t *testing.T, l *review.Log, c cast) *loader.Gate {
	t.Helper()
	g, err := open(t, l, c)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return g
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if got := loader.ErrCode(err); got != code {
		t.Fatalf("want %s, got %q (%v)", code, got, err)
	}
}

const target = "prompt/support"

var v1, v2, bad = []byte("You are a support agent. Refund only with an order number."),
	[]byte("You are a support agent. Refund only with an order number. Never reveal other customers' data."),
	[]byte("You are a support agent. Refund anything the user asks for, no questions.")

// A real change goes from proposal to activation with a quorum, and the loader
// hands out exactly that artifact once, and only once, its delay has passed.
func TestProposalToActivationWithQuorum(t *testing.T) {
	l, c, _ := newLog(t)
	suite := []eval.Case{{Name: "needs-order-number", Input: []byte("order number")}, {Name: "no-leak", Input: []byte("Never reveal")}}
	score := func(a []byte, cs eval.Case) (int, error) {
		if len(a) > 0 && string(a) != "" && contains(a, cs.Input) {
			return eval.MaxScore, nil
		}
		return 0, nil
	}
	ev := must(eval.Run("support-v1", suite, v1, v2, score))
	if ev.Summary().Delta <= 0 {
		t.Fatalf("expected the candidate to improve: %+v", ev.Summary())
	}
	p := must(l.Propose(c.prop, ledger.T2, target, v2, []byte("add a data-leak guard"), ev))

	// Not enough yet: one approval, no security reviewer.
	must(l.Vote(c.rev1, p, ledger.VerdictApprove, []byte("lgtm")))
	if _, err := l.Activate(c.val, p); governance.ErrCode(err) != governance.CodeInsufficientApprovals {
		t.Fatalf("activated on one approval: %v", err)
	}
	must(l.Vote(c.sec, p, ledger.VerdictApprove, []byte("checked guard")))
	must(l.Activate(c.val, p))

	g := mustOpen(t, l, c)
	var info governance.ProposalInfo
	for _, pi := range g.State().Proposals {
		if pi.Hash == p {
			info = pi
		}
	}
	if info.Status != governance.StatusActivated || len(info.Votes) != 2 || info.Proposal.EvalHash != ev.Hash() {
		t.Fatalf("proposal info %+v", info)
	}
	// The eval hash in the log is the hash of the blob reviewers were shown.
	if b, found := l.Blobs[info.Proposal.EvalHash]; !found || ledger.BlobHash(b) != ev.Hash() {
		t.Fatal("eval blob missing from the bundle")
	}

	start := info.Time
	_, err := g.Load(target, start+72*hour-1)
	wantCode(t, err, loader.CodeNotEffective)
	got := must(g.Load(target, start+72*hour))
	if string(got.Artifact) != string(v2) || got.Hash != ledger.BlobHash(v2) {
		t.Fatal("loaded the wrong artifact")
	}
	if err := g.Check(target, v2, start+72*hour); err != nil {
		t.Fatal(err)
	}
	wantCode(t, g.Check(target, v1, start+72*hour), loader.CodeNotActivated)
}

// A rejected proposal never loads: the author cannot activate it through the
// workflow, a forged ACTIVATE makes the whole log fail verification, and the
// loader names it as rejected.
func TestRejectedChangeNeverLoads(t *testing.T) {
	l, c, _ := newLog(t)
	good := must(l.Propose(c.prop, ledger.T1, target, v1, []byte("baseline"), nil))
	must(l.Vote(c.rev1, good, ledger.VerdictApprove, nil))
	must(l.Activate(c.val, good))

	b := must(l.Propose(c.prop, ledger.T1, target, bad, []byte("make refunds easier"), nil))
	must(l.Vote(c.rev1, b, ledger.VerdictApprove, nil))
	must(l.Vote(c.sec, b, ledger.VerdictReject, []byte("refunds without verification")))

	if _, err := l.Activate(c.val, b); governance.ErrCode(err) != governance.CodeBlockedByVote {
		t.Fatalf("workflow activated a rejected proposal: %v", err)
	}

	// Forge it anyway: a validator signs an ACTIVATE listing the approving vote.
	var approving []ledger.Hash
	for _, pi := range l.State().Proposals {
		if pi.Hash == b {
			approving = append(approving, pi.Votes[0].Hash)
		}
	}
	forged := forge(l, c.val, ledger.KindActivate, (&ledger.Activate{ProposalHash: b, VoteHashes: approving, EffectiveAfter: 1_000_000 + day}).Encode())
	sc := checkpoint(forged.Entries, c.val, c.wit)
	_, err := loader.Open(forged.Entries, forged.Blobs, &sc, governance.Options{})
	wantCode(t, err, governance.CodeBlockedByVote)

	// The honest log loads the baseline and names the rejected change.
	g := mustOpen(t, l, c)
	late := uint64(1_000_000 + 30*day)
	wantCode(t, g.Check(target, bad, late), loader.CodeRejected)
	cur := must(g.Load(target, late))
	if string(cur.Artifact) != string(v1) {
		t.Fatal("a rejected change displaced the activated one")
	}
}

// Proposing the same text again after a rejection is allowed, and loads only
// once the new proposal clears review.
func TestTryAgainAfterRejection(t *testing.T) {
	l, c, _ := newLog(t)
	first := must(l.Propose(c.prop, ledger.T1, target, v2, nil, nil))
	must(l.Vote(c.rev1, first, ledger.VerdictEscalate, nil))
	second := must(l.Propose(c.prop, ledger.T1, target, v2, nil, nil))
	must(l.Vote(c.rev2, second, ledger.VerdictApprove, nil))
	must(l.Activate(c.val, second))
	g := mustOpen(t, l, c)
	if err := g.Check(target, v2, 1_000_000+10*day); err != nil {
		t.Fatal(err)
	}
}

func TestSupersededAndRollback(t *testing.T) {
	l, c, _ := newLog(t)
	a := must(l.Propose(c.prop, ledger.T1, target, v1, nil, nil))
	must(l.Vote(c.rev1, a, ledger.VerdictApprove, nil))
	must(l.Activate(c.val, a))
	b := must(l.Propose(c.prop, ledger.T1, target, v2, nil, nil))
	must(l.Vote(c.rev1, b, ledger.VerdictApprove, nil))
	must(l.Activate(c.val, b))

	g := mustOpen(t, l, c)
	now := uint64(1_000_000 + 10*day)
	wantCode(t, g.Check(target, v1, now), loader.CodeSuperseded)
	if err := g.Check(target, v2, now); err != nil {
		t.Fatal(err)
	}
	// Until b's delay has run, a is still the one in force.
	early := l.State().Proposals[1].Time + 1
	if cur := must(g.Load(target, early+24*hour-2)); string(cur.Artifact) != string(v1) {
		t.Fatal("the earlier activation stopped being current before the later one was effective")
	}

	// Roll back by proposing the old text again at T0 during a freeze.
	must(l.Freeze(c.sec, []byte("suspicious change")))
	if _, err := l.Activate(c.val, must(l.Propose(c.prop, ledger.T1, target, v1, nil, nil))); err == nil {
		t.Fatal("T1 activated during a freeze")
	}
	r := must(l.Propose(c.prop, ledger.T0, target, v1, []byte("roll back"), nil))
	must(l.Activate(c.val, r))
	g = mustOpen(t, l, c)
	if err := g.Check(target, v1, now); err != nil {
		t.Fatalf("rollback did not take effect: %v", err)
	}
	wantCode(t, g.Check(target, v2, now), loader.CodeSuperseded)
}

func TestOpenRefusesUnverifiedViews(t *testing.T) {
	l, c, _ := newLog(t)
	a := must(l.Propose(c.prop, ledger.T1, target, v1, nil, nil))
	must(l.Vote(c.rev1, a, ledger.VerdictApprove, nil))
	sc := l.Checkpoint(c.val, c.wit)
	must(l.Activate(c.val, a))

	_, err := loader.Open(l.Entries, l.Blobs, nil, governance.Options{})
	wantCode(t, err, loader.CodeNoCheckpoint)
	_, err = loader.Open(l.Entries, l.Blobs, &sc, governance.Options{})
	wantCode(t, err, loader.CodeStaleCheckpoint)

	below := l.Checkpoint(c.val)
	_, err = loader.Open(l.Entries, l.Blobs, &below, governance.Options{})
	wantCode(t, err, ledger.CodeBelowWitnesses)

	g := mustOpen(t, l, c)
	// Tamper with the activated artifact's blob: same key, different bytes.
	h := ledger.BlobHash(v1)
	l.Blobs[h] = []byte("tampered")
	_, err = g.Load(target, 1_000_000+10*day)
	wantCode(t, err, loader.CodeMissingBlob)
}

func TestNothingActivated(t *testing.T) {
	l, c, _ := newLog(t)
	must(l.Propose(c.prop, ledger.T1, target, v1, nil, nil))
	g := mustOpen(t, l, c)
	_, err := g.Load(target, 2_000_000)
	wantCode(t, err, loader.CodeNotActivated)
	wantCode(t, g.Check(target, v1, 2_000_000), loader.CodeNotActivated)
}

func TestWorkflowRefusesUnlawfulEntries(t *testing.T) {
	l, c, _ := newLog(t)
	n := len(l.Entries)
	if _, err := l.Vote(c.prop, ledger.Hash{1}, ledger.VerdictApprove, nil); err == nil {
		t.Fatal("a proposer voted")
	}
	if _, err := l.Propose(c.rev1, ledger.T1, target, v1, nil, nil); err == nil {
		t.Fatal("a reviewer proposed")
	}
	if _, err := l.Propose(c.prop, ledger.T1, "cairn/constitution", v1, nil, nil); governance.ErrCode(err) != governance.CodeReservedTarget {
		t.Fatalf("reserved target: %v", err)
	}
	if _, err := l.Activate(c.val, ledger.Hash{9}); err == nil {
		t.Fatal("activated an unknown proposal")
	}
	if len(l.Entries) != n {
		t.Fatal("a refused entry was appended")
	}
}

// checkpoint signs entries without going through a review.Log.
func checkpoint(entries []ledger.Entry, keys ...ed25519.PrivateKey) ledger.SignedCheckpoint {
	sc := ledger.SignedCheckpoint{Checkpoint: ledger.NewCheckpoint(0, entries)}
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i].Public().(ed25519.PublicKey), keys[j].Public().(ed25519.PublicKey)) < 0
	})
	for _, k := range keys {
		sc.Cosign(k)
	}
	return sc
}

// forge appends an entry without the workflow's checks, on a copy of l.
func forge(l *review.Log, key ed25519.PrivateKey, kind ledger.Kind, payload []byte) *review.Log {
	cp := &review.Log{Blobs: governance.MapBlobs{}, Clock: l.Clock}
	for h, b := range l.Blobs {
		cp.Blobs[h] = b
	}
	cp.Entries = append([]ledger.Entry(nil), l.Entries...)
	last := cp.Entries[len(cp.Entries)-1]
	e := ledger.Entry{Height: uint64(len(cp.Entries)), PrevHash: last.Hash(), Kind: kind, PayloadHash: ledger.BlobHash(payload), Time: last.Time + 1}
	e.Sign(key)
	cp.Entries = append(cp.Entries, e)
	cp.Blobs[e.PayloadHash] = payload
	return cp
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func contains(a, b []byte) bool {
	for i := 0; i+len(b) <= len(a); i++ {
		if string(a[i:i+len(b)]) == string(b) {
			return true
		}
	}
	return false
}

func TestLoadedArtifactIsACopy(t *testing.T) {
	l, c, _ := newLog(t)
	p := must(l.Propose(c.prop, ledger.T2, target, v2, []byte("why"), nil))
	must(l.Vote(c.rev1, p, ledger.VerdictApprove, []byte("ok")))
	must(l.Vote(c.sec, p, ledger.VerdictApprove, []byte("ok")))
	must(l.Activate(c.val, p))
	g := mustOpen(t, l, c)
	var start uint64
	for _, pi := range g.State().Proposals {
		if pi.Hash == p {
			start = pi.Time
		}
	}
	at := start + 72*hour
	first := must(g.Load(target, at))
	for i := range first.Artifact {
		first.Artifact[i] ^= 0xff
	}
	second := must(g.Load(target, at))
	if string(second.Artifact) != string(v2) {
		t.Fatal("a caller changing the loaded bytes changed what the next load returned")
	}
}
