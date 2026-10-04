package governance

import (
	"fmt"

	"github.com/cockyapple/cairn/wire"
)

const (
	// PolicyTarget is the proposal target that switches the require-grants rule.
	// Switching it on needs tier T3 or T4; switching it off needs T4.
	PolicyTarget = "cairn/policy/require-grants"

	policyVersion = 1
)

// RequirePolicy is the blob of a PolicyTarget proposal: whether every agent
// must hold a grant to act.
//
//	u8 version (1) | u8 require (0 or 1)
type RequirePolicy struct{ Require bool }

func (p RequirePolicy) Encode() []byte {
	var w wire.Writer
	w.U8(policyVersion)
	if p.Require {
		w.U8(1)
	} else {
		w.U8(0)
	}
	return w.Out()
}

// DecodeRequirePolicy parses a policy blob. It accepts only the canonical encoding.
func DecodeRequirePolicy(b []byte) (RequirePolicy, error) {
	var p RequirePolicy
	r := wire.NewReader(b)
	if v := r.U8(); r.Err() == nil && v != policyVersion {
		return p, fmt.Errorf("unsupported policy version %d", v)
	}
	switch f := r.U8(); {
	case r.Err() != nil:
	case f == 1:
		p.Require = true
	case f != 0:
		return RequirePolicy{}, fmt.Errorf("require must be 0 or 1")
	}
	if err := r.Done(); err != nil {
		return RequirePolicy{}, err
	}
	return p, nil
}

type policyRec struct {
	require   bool
	effective uint64
}

// RequireGrants reports whether the log requires every agent to hold a grant,
// as of the last entry.
func (s *State) RequireGrants() bool { return s.requireGrants }

// promotePolicy applies the latest activated policy whose effective_after has
// come, and drops every one activated before it.
func (r *replayer) promotePolicy(t uint64) {
	best := -1
	for i, p := range r.policySched {
		if t >= p.effective {
			best = i
		}
	}
	if best < 0 {
		return
	}
	r.requireGrants = r.policySched[best].require
	r.policySched = r.policySched[best+1:]
}
