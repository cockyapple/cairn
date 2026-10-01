package review

import (
	"fmt"

	"github.com/cockyapple/cairn/eval"
	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
)

// Material is everything a reviewer is shown about one proposal.
type Material struct {
	Info        governance.ProposalInfo
	Previous    []byte // the artifact this one replaces, when HasPrevious
	HasPrevious bool
	Artifact    []byte
	Rationale   []byte
	Eval        *eval.Result // nil when the proposal carries no eval
}

func blob(blobs governance.Blobs, h ledger.Hash, what string) ([]byte, error) {
	b, ok := blobs.Get(h)
	if !ok || ledger.BlobHash(b) != h {
		return nil, fmt.Errorf("review: %s blob is missing or does not match its hash", what)
	}
	return b, nil
}

// Gather collects the material for a proposal. The previous artifact is the one
// most recently activated for the same target before this proposal's own
// activation (or before now, when it has none). Each blob is checked against its hash.
func Gather(st *governance.State, blobs governance.Blobs, proposal ledger.Hash) (*Material, error) {
	var info *governance.ProposalInfo
	for i := range st.Proposals {
		if st.Proposals[i].Hash == proposal {
			info = &st.Proposals[i]
		}
	}
	if info == nil {
		return nil, ErrUnknownProposal
	}
	m := &Material{Info: *info}
	var err error
	if m.Artifact, err = blob(blobs, info.Proposal.DiffHash, "artifact"); err != nil {
		return nil, err
	}
	if m.Rationale, err = blob(blobs, info.Proposal.RationaleHash, "rationale"); err != nil {
		return nil, err
	}
	if info.Proposal.EvalHash != (ledger.Hash{}) {
		raw, err := blob(blobs, info.Proposal.EvalHash, "eval")
		if err != nil {
			return nil, err
		}
		if m.Eval, err = eval.Decode(raw); err != nil {
			return nil, err
		}
	}
	var prev *governance.Activation
	for i := range st.Activations {
		a := &st.Activations[i]
		if a.Proposal.Target != info.Proposal.Target || a.ProposalHash == proposal {
			continue
		}
		if info.Status == governance.StatusActivated && a.ActivatedAt >= info.ActivatedAt {
			continue
		}
		if prev == nil || a.ActivatedAt > prev.ActivatedAt {
			prev = a
		}
	}
	if prev != nil {
		if m.Previous, err = blob(blobs, prev.Proposal.DiffHash, "previous artifact"); err != nil {
			return nil, err
		}
		m.HasPrevious = true
	}
	return m, nil
}
