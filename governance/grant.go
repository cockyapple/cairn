package governance

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/cockyapple/cairn/ledger"
	"github.com/cockyapple/cairn/wire"
)

const (
	// GrantTargetPrefix starts the proposal target that sets an agent's grant:
	// "cairn/grant/" followed by the agent's public key in 64 lowercase hex digits.
	GrantTargetPrefix = "cairn/grant/"
	// ActionDelegate is the ACTION type that hands a narrower grant to another agent.
	ActionDelegate = "cairn/delegate"

	grantVersion   = 1
	maxGrantItems  = 256
	maxGrantString = 256

	// NoExpiry as Grant.NotAfter means the grant does not expire. Unlimited as
	// Grant.Budget means the grant sets no budget ceiling.
	NoExpiry  = math.MaxUint64
	Unlimited = math.MaxUint64
)

// Grant is what an agent may do: which tools, which hosts, how much budget,
// until when. Tools and hosts are exact names; there are no wildcards, so
// "subset" is plain set inclusion. Budget is in the deployment's own unit.
// The grant is valid for entry times strictly before NotAfter.
type Grant struct {
	Tools    []string // strictly ascending byte order, no duplicates, none empty
	Hosts    []string // same
	Budget   uint64
	NotAfter uint64 // unix seconds
}

var ErrBadGrant = errors.New("governance: malformed grant")

func validNames(names []string) error {
	if len(names) > maxGrantItems {
		return fmt.Errorf("%w: more than %d entries", ErrBadGrant, maxGrantItems)
	}
	for i, n := range names {
		if n == "" || len(n) > maxGrantString {
			return fmt.Errorf("%w: a name is empty or longer than %d bytes", ErrBadGrant, maxGrantString)
		}
		if i > 0 && names[i-1] >= n {
			return fmt.Errorf("%w: names must be strictly ascending", ErrBadGrant)
		}
	}
	return nil
}

// Encode returns the canonical bytes of g, or an error if g is not canonical.
func (g Grant) Encode() ([]byte, error) {
	if err := validNames(g.Tools); err != nil {
		return nil, err
	}
	if err := validNames(g.Hosts); err != nil {
		return nil, err
	}
	var w wire.Writer
	w.U8(grantVersion)
	for _, list := range [][]string{g.Tools, g.Hosts} {
		w.U32(uint32(len(list)))
		for _, n := range list {
			w.String(n)
		}
	}
	w.U64(g.Budget)
	w.U64(g.NotAfter)
	return w.Out(), nil
}

func readNames(r *wire.Reader) []string {
	n := r.Count(maxGrantItems)
	var out []string
	for i := 0; i < n && r.Err() == nil; i++ {
		out = append(out, r.String())
	}
	return out
}

func decodeGrant(r *wire.Reader) (Grant, error) {
	var g Grant
	if v := r.U8(); r.Err() == nil && v != grantVersion {
		return g, fmt.Errorf("%w: unsupported version %d", ErrBadGrant, v)
	}
	g.Tools = readNames(r)
	g.Hosts = readNames(r)
	g.Budget = r.U64()
	g.NotAfter = r.U64()
	if err := r.Err(); err != nil {
		return Grant{}, fmt.Errorf("%w: %v", ErrBadGrant, err)
	}
	if err := validNames(g.Tools); err != nil {
		return Grant{}, err
	}
	if err := validNames(g.Hosts); err != nil {
		return Grant{}, err
	}
	return g, nil
}

// DecodeGrant parses a grant. It accepts only the canonical encoding.
func DecodeGrant(b []byte) (Grant, error) {
	r := wire.NewReader(b)
	g, err := decodeGrant(r)
	if err != nil {
		return Grant{}, err
	}
	if err := r.Done(); err != nil {
		return Grant{}, fmt.Errorf("%w: %v", ErrBadGrant, err)
	}
	return g, nil
}

func subset(sub, super []string) bool {
	have := make(map[string]bool, len(super))
	for _, s := range super {
		have[s] = true
	}
	for _, s := range sub {
		if !have[s] {
			return false
		}
	}
	return true
}

// StrictlyWithin reports whether g is a strict subset of parent: nothing in g
// exceeds parent in any dimension, and g differs from parent in at least one.
func (g Grant) StrictlyWithin(parent Grant) bool {
	if !subset(g.Tools, parent.Tools) || !subset(g.Hosts, parent.Hosts) ||
		g.Budget > parent.Budget || g.NotAfter > parent.NotAfter {
		return false
	}
	return len(g.Tools) < len(parent.Tools) || len(g.Hosts) < len(parent.Hosts) ||
		g.Budget < parent.Budget || g.NotAfter < parent.NotAfter
}

// Delegation is the argument blob of a cairn/delegate ACTION: the key receiving
// the grant and the grant itself.
type Delegation struct {
	Child [32]byte
	Grant Grant
}

func (d Delegation) Encode() ([]byte, error) {
	g, err := d.Grant.Encode()
	if err != nil {
		return nil, err
	}
	return append(append([]byte(nil), d.Child[:]...), g...), nil
}

func DecodeDelegation(b []byte) (Delegation, error) {
	var d Delegation
	if len(b) < 32 {
		return Delegation{}, fmt.Errorf("%w: delegation shorter than a key", ErrBadGrant)
	}
	copy(d.Child[:], b[:32])
	g, err := DecodeGrant(b[32:])
	if err != nil {
		return Delegation{}, err
	}
	d.Grant = g
	return d, nil
}

// GrantTarget returns the proposal target that sets agent's grant.
func GrantTarget(agent [32]byte) string { return GrantTargetPrefix + hex.EncodeToString(agent[:]) }

func parseGrantTarget(target string) ([32]byte, bool) {
	var k [32]byte
	h := strings.TrimPrefix(target, GrantTargetPrefix)
	if len(h) != 64 || h != strings.ToLower(h) {
		return k, false
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return k, false
	}
	copy(k[:], b)
	return k, true
}

// GrantInfo is an agent's grant as it stands after the last entry.
type GrantInfo struct {
	Agent  [32]byte
	Grant  Grant
	Height uint64 // the ACTIVATE entry (root grant) or the delegating intent
	// EffectiveAfter is when the grant starts to count: the proposal's
	// effective_after for a root grant, the intent's time for a delegation.
	EffectiveAfter uint64
	DelegatedBy    *[32]byte // nil for a root grant
}

type grantRec struct {
	g         Grant
	height    uint64
	effective uint64
	parent    *[32]byte
}

// withdraw removes the grant held by k and every grant derived from it.
func (r *replayer) withdraw(k [32]byte) {
	delete(r.grants, k)
	for c, g := range r.grants {
		if g.parent != nil && *g.parent == k {
			r.withdraw(c)
		}
	}
}

// grantProposal checks a proposal that targets cairn/grant/<key> and returns
// the key and the grant it would set.
func (r *replayer) grantProposal(e *ledger.Entry, p ledger.Proposal) ([32]byte, Grant, error) {
	var none Grant
	key, ok := parseGrantTarget(p.Target)
	if !ok {
		return key, none, fail(e.Height, CodeBadGrant, "the target must be cairn/grant/ followed by 64 lowercase hex digits")
	}
	if p.Tier < ledger.T3 {
		return key, none, fail(e.Height, CodeReservedTarget, "a grant can only change at tier T3 or above")
	}
	if r.revoked[key] {
		return key, none, fail(e.Height, CodeRevokedKey, "the key this grant is for has been revoked")
	}
	if role, held := r.trust().RoleOf(key); !held || role != ledger.RoleAgent {
		return key, none, fail(e.Height, CodeBadGrant, "the key this grant is for is not an agent in the epoch in force")
	}
	b, err := r.blob(e.Height, p.DiffHash, "grant")
	if err != nil {
		return key, none, err
	}
	g, err := DecodeGrant(b)
	if err != nil {
		return key, none, fail(e.Height, CodeBadGrant, err.Error())
	}
	return key, g, nil
}

// delegate enforces I11 on a cairn/delegate intent.
func (r *replayer) delegate(e *ledger.Entry, a ledger.Action) error {
	b, err := r.blob(e.Height, a.ArgsHash, "delegation")
	if err != nil {
		return err
	}
	d, err := DecodeDelegation(b)
	if err != nil {
		return fail(e.Height, CodeBadGrant, err.Error())
	}
	parent := r.grants[e.Author]
	switch {
	case parent == nil:
		return fail(e.Height, CodeBadDelegation, "the delegating key holds no grant")
	case e.Time < parent.effective:
		return fail(e.Height, CodeBadDelegation, "the delegating key's grant is not yet in effect")
	case e.Time >= parent.g.NotAfter:
		return fail(e.Height, CodeBadDelegation, "the delegating key's grant has expired")
	case d.Child == e.Author:
		return fail(e.Height, CodeBadDelegation, "a key cannot delegate to itself")
	case r.revoked[d.Child]:
		return fail(e.Height, CodeRevokedKey, "the receiving key has been revoked")
	}
	if role, held := r.trust().RoleOf(d.Child); !held || role != ledger.RoleAgent {
		return fail(e.Height, CodeBadDelegation, "the receiving key is not an agent in the epoch in force")
	}
	if r.grants[d.Child] != nil {
		return fail(e.Height, CodeBadDelegation, "the receiving key already holds a grant")
	}
	if !d.Grant.StrictlyWithin(parent.g) {
		return fail(e.Height, CodeNotNarrower, "a delegation must be a strict subset of the delegating key's own grant")
	}
	by := e.Author
	r.grants[d.Child] = &grantRec{g: d.Grant, height: e.Height, effective: e.Time, parent: &by}
	return nil
}

func (r *replayer) grantInfos() []GrantInfo {
	var out []GrantInfo
	for k, g := range r.grants {
		out = append(out, GrantInfo{Agent: k, Grant: g.g, Height: g.height, EffectiveAfter: g.effective, DelegatedBy: g.parent})
	}
	sortGrantInfos(out)
	return out
}

func sortGrantInfos(s []GrantInfo) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0; j-- {
			a, b := s[j-1], s[j]
			if a.Height < b.Height || (a.Height == b.Height && bytes.Compare(a.Agent[:], b.Agent[:]) < 0) {
				break
			}
			s[j-1], s[j] = b, a
		}
	}
}
