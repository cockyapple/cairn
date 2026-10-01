// Package loader is the only way a governed agent should obtain configuration:
// it returns an artifact only if the log, checkpoint and governance rules all
// verify and an ACTIVATE entry has made that exact artifact current for the
// target. A rejected, unreviewed, not-yet-effective or superseded artifact is
// refused with a stable code.
//
// The loader decides from the log alone plus a clock the caller trusts.
// Entry times are claims (SPEC section 10.5), so `now` must not come from the
// log, and a checkpoint proves only that the log was this long at signing
// time, not that no later entry exists: freshness is the caller's concern.
package loader

import (
	"errors"
	"fmt"

	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
)

const (
	CodeNoCheckpoint    = "no_checkpoint"
	CodeStaleCheckpoint = "stale_checkpoint"
	CodeNotActivated    = "not_activated"
	CodeRejected        = "rejected"
	CodeNotEffective    = "not_effective"
	CodeSuperseded      = "superseded"
	CodeMissingBlob     = "missing_blob"
)

type Error struct{ Code, Detail string }

func (e *Error) Error() string { return e.Code + ": " + e.Detail }

func fail(code, detail string) error { return &Error{Code: code, Detail: detail} }

// ErrCode returns the stable code of a loader or verification error.
func ErrCode(err error) string {
	var le *Error
	if errors.As(err, &le) {
		return le.Code
	}
	return governance.ErrCode(err)
}

// Loaded is an artifact the log has made current for a target.
type Loaded struct {
	Target         string
	Artifact       []byte
	Hash           ledger.Hash
	ProposalHash   ledger.Hash
	ActivatedAt    uint64 // height of the ACTIVATE entry
	EffectiveAfter uint64
}

// Gate answers load requests from one verified view of the log.
type Gate struct {
	st    *governance.State
	blobs governance.Blobs
}

// Open verifies the chain, every governance rule and the checkpoint, which must
// cover the whole log and meet the quorum and witness threshold in force.
func Open(entries []ledger.Entry, blobs governance.Blobs, sc *ledger.SignedCheckpoint, opt governance.Options) (*Gate, error) {
	if sc == nil {
		return nil, fail(CodeNoCheckpoint, "a signed checkpoint is required")
	}
	if sc.Size != uint64(len(entries)) {
		return nil, fail(CodeStaleCheckpoint, "the checkpoint does not cover the whole log")
	}
	st, err := governance.Replay(entries, blobs, opt)
	if err != nil {
		return nil, err
	}
	trust, ok := st.TrustForSize(sc.Size)
	if !ok {
		return nil, fail(CodeStaleCheckpoint, "the checkpoint does not match the log")
	}
	if err := ledger.VerifyCheckpoint(sc, entries, &trust); err != nil {
		return nil, err
	}
	return &Gate{st: st, blobs: blobs}, nil
}

func (g *Gate) State() *governance.State { return g.st }

// current finds the activation in force for target at time now: among
// activations already effective, the one activated last.
func (g *Gate) current(target string, now uint64) (governance.Activation, bool, bool) {
	var best governance.Activation
	found, pending := false, false
	for _, a := range g.st.Activations {
		if a.Proposal.Target != target {
			continue
		}
		if a.EffectiveAfter > now {
			pending = true
			continue
		}
		if !found || a.ActivatedAt > best.ActivatedAt {
			best, found = a, true
		}
	}
	return best, found, pending
}

// Load returns the artifact in force for target at time now.
func (g *Gate) Load(target string, now uint64) (*Loaded, error) {
	a, found, pending := g.current(target, now)
	if !found {
		if pending {
			return nil, fail(CodeNotEffective, "every activation for this target is still inside its delay")
		}
		return nil, fail(CodeNotActivated, "no activated change exists for this target")
	}
	b, ok := g.blobs.Get(a.Proposal.DiffHash)
	if !ok || ledger.BlobHash(b) != a.Proposal.DiffHash {
		return nil, fail(CodeMissingBlob, "the activated artifact is not available or does not match its hash")
	}
	return &Loaded{
		Target: target, Artifact: b, Hash: a.Proposal.DiffHash, ProposalHash: a.ProposalHash,
		ActivatedAt: a.ActivatedAt, EffectiveAfter: a.EffectiveAfter,
	}, nil
}

// Check says whether artifact is exactly what the log has made current for
// target. When it is not, the error says why: rejected, never activated,
// activated but not yet effective, or replaced by a later change.
func (g *Gate) Check(target string, artifact []byte, now uint64) error {
	h := ledger.BlobHash(artifact)
	if cur, found, _ := g.current(target, now); found && cur.Proposal.DiffHash == h {
		return nil
	}
	var rejected, pending, superseded bool
	for _, a := range g.st.Activations {
		if a.Proposal.Target != target || a.Proposal.DiffHash != h {
			continue
		}
		if a.EffectiveAfter > now {
			pending = true
		} else {
			superseded = true
		}
	}
	switch {
	case superseded:
		return fail(CodeSuperseded, "this artifact was activated but a later change replaced it")
	case pending:
		return fail(CodeNotEffective, "this artifact is activated but its delay has not elapsed")
	}
	for _, p := range g.st.Proposals {
		if p.Proposal.Target == target && p.Proposal.DiffHash == h && p.Status == governance.StatusRejected {
			rejected = true
		}
	}
	if rejected {
		return fail(CodeRejected, "a reviewer rejected or escalated a proposal for this artifact")
	}
	return fail(CodeNotActivated, fmt.Sprintf("no activation covers this artifact for target %q", target))
}
