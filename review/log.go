// Package review is the authoring side of the review workflow: it builds
// PROPOSAL, VOTE, ACTIVATE and FREEZE entries, signs them, and refuses to
// append any entry the governance rules would reject. It is a client library
// and a local log; it is not the append-only log server.
package review

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"sort"

	"github.com/cockyapple/cairn/eval"
	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
)

// maxVotesListed is the most votes one ACTIVATE entry can carry (SPEC section 3).
const maxVotesListed = 256

// Log is an in-memory log plus the blobs its entries point to. Every append
// replays the whole log, so the cost grows with its length; that is acceptable
// for a local workflow tool and keeps the rules in one place.
type Log struct {
	Entries []ledger.Entry
	Blobs   governance.MapBlobs
	Opt     governance.Options
	// Clock supplies entry times (unix seconds). Entry times never go backwards
	// whatever the clock does, because the replay rejects a regression.
	Clock func() uint64

	st *governance.State
}

// New starts a log with a GENESIS entry signed by one of the validators in trust.
func New(genesisKey ed25519.PrivateKey, constitution ledger.Hash, trust ledger.TrustConfig, clock func() uint64) (*Log, error) {
	l := &Log{Blobs: governance.MapBlobs{}, Clock: clock}
	g := ledger.Genesis{SpecVersion: ledger.SpecVersion, ConstitutionHash: constitution, Trust: trust}
	if _, err := l.append(ledger.KindGenesis, genesisKey, g.Encode()); err != nil {
		return nil, err
	}
	return l, nil
}

// Resume wraps an existing, already verified log so more entries can be added.
func Resume(entries []ledger.Entry, blobs governance.MapBlobs, opt governance.Options, clock func() uint64) (*Log, error) {
	st, err := governance.Replay(entries, blobs, opt)
	if err != nil {
		return nil, err
	}
	return &Log{Entries: entries, Blobs: blobs, Opt: opt, Clock: clock, st: st}, nil
}

func (l *Log) State() *governance.State { return l.st }

func (l *Log) append(kind ledger.Kind, key ed25519.PrivateKey, payload []byte) (ledger.Hash, error) {
	e := ledger.Entry{Height: uint64(len(l.Entries)), Kind: kind, PayloadHash: ledger.BlobHash(payload)}
	if l.Clock != nil {
		e.Time = l.Clock()
	}
	if n := len(l.Entries); n > 0 {
		e.PrevHash = l.Entries[n-1].Hash()
		if e.Time < l.Entries[n-1].Time {
			e.Time = l.Entries[n-1].Time
		}
	}
	e.Sign(key)

	cand := make([]ledger.Entry, len(l.Entries)+1)
	copy(cand, l.Entries)
	cand[len(l.Entries)] = e
	_, had := l.Blobs[e.PayloadHash]
	l.Blobs[e.PayloadHash] = payload
	st, err := governance.Replay(cand, l.Blobs, l.Opt)
	if err != nil {
		if !had {
			delete(l.Blobs, e.PayloadHash)
		}
		return ledger.Hash{}, err
	}
	l.Entries, l.st = cand, st
	return e.Hash(), nil
}

func (l *Log) store(b []byte) ledger.Hash {
	c := bytes.Clone(b)
	h := ledger.BlobHash(c)
	l.Blobs[h] = c
	return h
}

// Propose records a change: artifact is the complete new content for target
// (the proposal's diff_hash commits to it), rationale explains it, and ev, when
// given, is the eval result whose hash is recorded as eval_hash.
func (l *Log) Propose(key ed25519.PrivateKey, tier ledger.Tier, target string, artifact, rationale []byte, ev *eval.Result) (ledger.Hash, error) {
	p := ledger.Proposal{Tier: tier, Target: target, DiffHash: l.store(artifact), RationaleHash: l.store(rationale)}
	if ev != nil {
		p.EvalHash = l.store(ev.Encode())
	}
	return l.append(ledger.KindProposal, key, p.Encode())
}

func (l *Log) Vote(key ed25519.PrivateKey, proposal ledger.Hash, verdict ledger.Verdict, comment []byte) (ledger.Hash, error) {
	v := ledger.Vote{ProposalHash: proposal, Verdict: verdict, CommentHash: l.store(comment)}
	return l.append(ledger.KindVote, key, v.Encode())
}

var ErrUnknownProposal = errors.New("review: no such proposal in the log")

// Activate lists every approving vote the proposal has and sets effective_after
// to the earliest time its tier allows. The governance rules decide whether
// that is enough; an insufficient set fails with insufficient_approvals.
func (l *Log) Activate(key ed25519.PrivateKey, proposal ledger.Hash) (ledger.Hash, error) {
	for _, p := range l.st.Proposals {
		if p.Hash != proposal {
			continue
		}
		var votes []ledger.Hash
		for _, v := range p.Votes {
			if v.Verdict == ledger.VerdictApprove && len(votes) < maxVotesListed {
				votes = append(votes, v.Hash)
			}
		}
		a := ledger.Activate{ProposalHash: proposal, VoteHashes: votes, EffectiveAfter: p.Time + governance.MinDelay(p.Proposal.Tier)}
		return l.append(ledger.KindActivate, key, a.Encode())
	}
	return ledger.Hash{}, ErrUnknownProposal
}

func (l *Log) Freeze(key ed25519.PrivateKey, reason []byte) (ledger.Hash, error) {
	f := ledger.Freeze{Scope: ledger.FreezeActivations, ReasonHash: l.store(reason)}
	return l.append(ledger.KindFreeze, key, f.Encode())
}

func (l *Log) Revoke(key ed25519.PrivateKey, target [32]byte, reason []byte) (ledger.Hash, error) {
	v := ledger.Revoke{Key: target, ReasonHash: l.store(reason)}
	return l.append(ledger.KindRevoke, key, v.Encode())
}

func (l *Log) LiftFreeze(key ed25519.PrivateKey, reason []byte) (ledger.Hash, error) {
	f := ledger.Freeze{Scope: ledger.FreezeLift, ReasonHash: l.store(reason)}
	return l.append(ledger.KindFreeze, key, f.Encode())
}

// Checkpoint signs the current head with the given keys, in the ascending
// public-key order the canonical encoding requires.
func (l *Log) Checkpoint(keys ...ed25519.PrivateKey) ledger.SignedCheckpoint {
	sc := ledger.SignedCheckpoint{Checkpoint: ledger.NewCheckpoint(l.st.Trust().Epoch, l.Entries)}
	sorted := append([]ed25519.PrivateKey(nil), keys...)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i].Public().(ed25519.PublicKey), sorted[j].Public().(ed25519.PublicKey)) < 0
	})
	for _, k := range sorted {
		sc.Cosign(k)
	}
	return sc
}
