package governance

import (
	"fmt"
	"slices"

	"github.com/cockyapple/cairn/ledger"
	"github.com/cockyapple/cairn/wire"
)

const (
	// ActionEvent is the ACTION type for things a gatekeeper records that are
	// not requests to act: refusals, rate-limit notices, taint resets. It uses no
	// grant and spends no budget. Its args are Event bytes; the replay does not
	// parse them.
	ActionEvent = "cairn/event"

	useVersion          = 1
	useVersionCommitted = 2
)

// Use is what an agent that holds a grant declares about one action, so the log
// can hold it to the grant: the host it will touch ("" for none), the budget it
// reserves, and the arguments it was given. The ACTION's args_hash is the hash of
// the canonical Use blob:
//
//	u8 version (1) | string host | u64 cost | bytes args
//
// Version 2 replaces the arguments with a commitment to them, so the blob can be
// published while the arguments are withheld (see NewOpening):
//
//	u8 version (2) | string host | u64 cost | [32] args_commitment
//
// The replay reads only the host and the cost, so both versions are judged alike.
type Use struct {
	Host string
	Cost uint64
	Args []byte
	// Commit, when set, makes this a version 2 blob and Args is ignored.
	Commit *ledger.Hash
}

func (u Use) Encode() []byte {
	var w wire.Writer
	if u.Commit != nil {
		w.U8(useVersionCommitted)
		w.String(u.Host)
		w.U64(u.Cost)
		w.Fixed(u.Commit[:])
		return w.Out()
	}
	w.U8(useVersion)
	w.String(u.Host)
	w.U64(u.Cost)
	w.Bytes(u.Args)
	return w.Out()
}

// DecodeUse parses a Use blob. It accepts only the canonical encoding.
func DecodeUse(b []byte) (Use, error) {
	var u Use
	r := wire.NewReader(b)
	v := r.U8()
	if r.Err() == nil && v != useVersion && v != useVersionCommitted {
		return u, fmt.Errorf("unsupported use version %d", v)
	}
	u.Host = r.String()
	u.Cost = r.U64()
	if v == useVersionCommitted {
		var c ledger.Hash
		copy(c[:], r.Fixed(32))
		u.Commit = &c
	} else {
		u.Args = r.Bytes()
	}
	if err := r.Done(); err != nil {
		return Use{}, err
	}
	return u, nil
}

// EventArgs returns the args of a cairn/event ACTION: the type the gatekeeper
// would have recorded and the arguments that went with it.
func EventArgs(actionType string, args []byte) []byte {
	var w wire.Writer
	w.String(actionType)
	w.Bytes(args)
	return w.Out()
}

// Bound reports whether k has ever held a grant. A bound agent acts only within
// the grant it holds: once granted, losing the grant leaves it with nothing, not
// with everything.
func (s *State) Bound(k [32]byte) bool { return s.bound[k] }

// authorize holds an ACTION intent to its author's grant. An agent that has
// never held a grant is not bound and passes; delegation and events pass; every
// other intent of a bound agent must carry a Use blob that fits the grant, and
// its cost is charged to the grant and to every grant above it.
func (r *replayer) authorize(e *ledger.Entry, a ledger.Action) error {
	if a.ActionType == ActionDelegate || a.ActionType == ActionEvent {
		return nil
	}
	if !r.bound[e.Author] {
		if r.requireGrants {
			return fail(e.Height, CodeNoGrant, "the log requires every agent to hold a grant and this agent never has")
		}
		return nil
	}
	rec := r.grants[e.Author]
	switch {
	case rec == nil:
		return fail(e.Height, CodeNoGrant, "the agent's grant was withdrawn and it holds none")
	case expired(rec.g, e.Time):
		return fail(e.Height, CodeGrantExpired, "the agent's grant has expired")
	}
	b, err := r.blob(e.Height, a.ArgsHash, "use")
	if err != nil {
		return err
	}
	u, err := DecodeUse(b)
	if err != nil {
		return fail(e.Height, CodeBadUse, err.Error())
	}
	if !slices.Contains(rec.g.Tools, a.ActionType) {
		return fail(e.Height, CodeToolNotGranted, "the grant does not include this action type")
	}
	if u.Host != "" && !slices.Contains(rec.g.Hosts, u.Host) {
		return fail(e.Height, CodeHostNotGranted, "the grant does not include this host")
	}
	var chain []*grantRec
	for g := rec; g != nil; {
		chain = append(chain, g)
		if g.parent == nil {
			break
		}
		g = r.grants[*g.parent]
	}
	for _, g := range chain {
		if g.g.Budget != Unlimited && u.Cost > g.g.Budget-g.spent {
			return fail(e.Height, CodeBudgetExceeded, "the action's cost exceeds the budget left in the grant or one above it")
		}
	}
	for _, g := range chain {
		if g.g.Budget != Unlimited {
			g.spent += u.Cost
		}
	}
	return nil
}
