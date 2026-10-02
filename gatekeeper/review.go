package gatekeeper

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/cockyapple/cairn/ledger"
)

const (
	CodeReviewRejected = "review_rejected"
	CodeReviewTimeout  = "review_timeout"

	// DefaultReviewTimeout is how long an agent waits for a human decision
	// when Gatekeeper.ReviewTimeout is zero.
	DefaultReviewTimeout = 24 * time.Hour

	decisionDomain = "cairn/review-decision/v1\x00"
)

var (
	ErrNoSuchReview = errors.New("gatekeeper: no action is waiting on that review")
	ErrNotReviewer  = errors.New("gatekeeper: the signer does not hold a reviewer role in the epoch in force")
	ErrBadDecision  = errors.New("gatekeeper: the decision signature is invalid")
)

// Decision is a reviewer's signed answer about one open intent. The signature
// covers the intent's entry hash, which commits to the agent, the action type,
// the arguments and the agent's place in its own chain, so a decision cannot be
// moved to another action.
type Decision struct {
	Intent   ledger.Hash
	Approve  bool
	Reviewer [32]byte
	Sig      [64]byte
}

func decisionInput(intent ledger.Hash, approve bool) []byte {
	v := byte(0)
	if approve {
		v = 1
	}
	b := append([]byte(decisionDomain), intent[:]...)
	return append(b, v)
}

// SignDecision signs a decision with a reviewer's key. The reviewer does this on
// their own machine; the gatekeeper never holds the key.
func SignDecision(key ed25519.PrivateKey, intent ledger.Hash, approve bool) Decision {
	d := Decision{Intent: intent, Approve: approve}
	copy(d.Reviewer[:], key.Public().(ed25519.PublicKey))
	copy(d.Sig[:], ed25519.Sign(key, decisionInput(intent, approve)))
	return d
}

// Verify checks the signature only. Whether the signer may review is a
// separate question, answered against the log's trust configuration.
func (d *Decision) Verify() bool {
	return ed25519.Verify(ed25519.PublicKey(d.Reviewer[:]), decisionInput(d.Intent, d.Approve), d.Sig[:])
}

// header is the first line of a reviewed action's completion blob, so the log
// itself carries who decided and the signature that proves it.
func (d *Decision) header() []byte {
	verdict := "reject"
	if d.Approve {
		verdict = "approve"
	}
	return []byte(fmt.Sprintf("review:%s %s %s\n", verdict, hex.EncodeToString(d.Reviewer[:]), hex.EncodeToString(d.Sig[:])))
}

// Pending describes an action waiting for a human decision.
type Pending struct {
	Intent     ledger.Hash
	Agent      string
	ActionType string
	Args       []byte
}

type waiting struct {
	Pending
	ch chan Decision
}

// PendingReviews lists the actions waiting for a decision, in a stable order.
func (g *Gatekeeper) PendingReviews() []Pending {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]Pending, 0, len(g.waiting))
	for _, w := range g.waiting {
		p := w.Pending
		p.Args = append([]byte(nil), p.Args...)
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return string(out[i].Intent[:]) < string(out[j].Intent[:]) })
	return out
}

// Decide delivers a reviewer's signed decision to the action waiting on it. The
// signer must hold the reviewer or security reviewer role in the epoch the log
// is in now. A decision is accepted once; later ones find nothing waiting.
func (g *Gatekeeper) Decide(d Decision) error {
	if !d.Verify() {
		return ErrBadDecision
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	w, ok := g.waiting[d.Intent]
	if !ok {
		return ErrNoSuchReview
	}
	st := g.log.State()
	role, known := st.Epochs[len(st.Epochs)-1].Trust.RoleOf(d.Reviewer)
	if !known || (role != ledger.RoleReviewer && role != ledger.RoleSecurityReviewer) {
		return ErrNotReviewer
	}
	delete(g.waiting, d.Intent)
	w.ch <- d
	return nil
}

// awaitReview parks an action whose intent is on the log until a reviewer
// decides, the context ends, or the timeout passes. A nil refusal means approved.
func (g *Gatekeeper) awaitReview(ctx context.Context, a *Agent, intent ledger.Hash, actionType string, args []byte) (Decision, *Refusal) {
	w := &waiting{Pending: Pending{Intent: intent, Agent: a.Name, ActionType: actionType, Args: args}, ch: make(chan Decision, 1)}
	g.mu.Lock()
	g.waiting[intent] = w
	g.mu.Unlock()
	timeout := g.ReviewTimeout
	if timeout == 0 {
		timeout = DefaultReviewTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case d := <-w.ch:
		if !d.Approve {
			return d, &Refusal{CodeReviewRejected, "a reviewer rejected this action"}
		}
		return d, nil
	case <-ctx.Done():
	case <-timer.C:
	}
	g.mu.Lock()
	_, stillWaiting := g.waiting[intent]
	delete(g.waiting, intent)
	g.mu.Unlock()
	if !stillWaiting {
		// Decide won the race after the timer fired; honour the decision.
		d := <-w.ch
		if !d.Approve {
			return d, &Refusal{CodeReviewRejected, "a reviewer rejected this action"}
		}
		return d, nil
	}
	return Decision{}, &Refusal{CodeReviewTimeout, "no reviewer decided in time"}
}
