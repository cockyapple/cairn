package review

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cockyapple/cairn/ledger"
)

// Decision is a reviewer's answer. Anything other than an explicit verdict is
// an error, never a vote.
type Decision struct {
	Verdict ledger.Verdict
	Comment string
}

// Reviewer is anything that can judge a proposal: a model, a person at a
// terminal, a script, a bridge to a community poll. What it is allowed to do is
// set by the role its key holds in the trust configuration, not by its type.
type Reviewer interface {
	Name() string
	Review(ctx context.Context, m *Material) (Decision, error)
}

// ReviewerFunc adapts a function.
type ReviewerFunc struct {
	Label string
	Fn    func(ctx context.Context, m *Material) (Decision, error)
}

func (f ReviewerFunc) Name() string { return f.Label }
func (f ReviewerFunc) Review(ctx context.Context, m *Material) (Decision, error) {
	return f.Fn(ctx, m)
}

// Member binds a reviewer to the key that signs its votes.
type Member struct {
	Reviewer Reviewer
	Key      ed25519.PrivateKey
}

// Outcome is what happened to one member.
type Outcome struct {
	Reviewer string
	Decision Decision
	Vote     ledger.Hash // zero when no vote was recorded
	Err      error
}

var ErrAlreadyVoted = errors.New("review: this key has already voted on the proposal")

// Council asks its members about a proposal and records the votes. It decides
// nothing: whether the votes are enough is the governance rules' call, made when
// someone tries to activate.
type Council struct {
	Members []Member
	// Timeout bounds each member. Zero means five minutes.
	Timeout time.Duration
}

func clone(m *Material) *Material {
	c := *m
	c.Previous = bytes.Clone(m.Previous)
	c.Artifact = bytes.Clone(m.Artifact)
	c.Rationale = bytes.Clone(m.Rationale)
	return &c
}

func safeReview(ctx context.Context, r Reviewer, m *Material) (d Decision, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("review: reviewer panicked: %v", p)
		}
	}()
	return r.Review(ctx, m)
}

// Run puts the proposal to every member that has not voted, concurrently, then
// appends the resulting votes in member order. A member that errors, times out
// or returns something other than approve, reject or escalate casts no vote:
// silence never counts as approval.
func (c *Council) Run(ctx context.Context, l *Log, proposal ledger.Hash) ([]Outcome, error) {
	m, err := Gather(l.State(), l.Blobs, proposal)
	if err != nil {
		return nil, err
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	out := make([]Outcome, len(c.Members))
	var wg sync.WaitGroup
	for i, mem := range c.Members {
		out[i].Reviewer = mem.Reviewer.Name()
		var pub [32]byte
		copy(pub[:], mem.Key.Public().(ed25519.PublicKey))
		voted := false
		for _, v := range m.Info.Votes {
			voted = voted || v.Author == pub
		}
		if voted {
			out[i].Err = ErrAlreadyVoted
			continue
		}
		wg.Add(1)
		go func(i int, mem Member) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			d, err := safeReview(cctx, mem.Reviewer, clone(m))
			switch {
			case err != nil:
				out[i].Err = err
			case d.Verdict < ledger.VerdictApprove || d.Verdict > ledger.VerdictEscalate:
				out[i].Err = errors.New("review: reviewer returned no valid verdict")
			default:
				out[i].Decision = d
			}
		}(i, mem)
	}
	wg.Wait()
	for i, mem := range c.Members {
		if out[i].Err != nil {
			continue
		}
		h, err := l.Vote(mem.Key, proposal, out[i].Decision.Verdict, []byte(out[i].Decision.Comment))
		if err != nil {
			out[i].Err = err
			continue
		}
		out[i].Vote = h
	}
	return out, nil
}
