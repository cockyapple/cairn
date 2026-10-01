// Package governance replays a verified ledger and checks that every entry was
// lawful: written by a key holding the right role, with the approvals, delay
// and freeze rules of SPEC section 10 respected. It builds on the ledger
// package and uses only the standard library.
package governance

import (
	"fmt"
	"sort"
	"strings"

	"github.com/cockyapple/cairn/ledger"
)

// Blobs resolves a payload hash to the payload bytes.
type Blobs interface {
	Get(h ledger.Hash) ([]byte, bool)
}

type MapBlobs map[ledger.Hash][]byte

func (m MapBlobs) Get(h ledger.Hash) ([]byte, bool) { b, ok := m[h]; return b, ok }

type Options struct {
	// ConstitutionHash, when set, must equal the hash recorded in GENESIS.
	ConstitutionHash *ledger.Hash
}

type Activation struct {
	ProposalHash   ledger.Hash
	Proposal       ledger.Proposal
	ProposedBy     [32]byte
	Epoch          uint64
	ActivatedAt    uint64 // height of the ACTIVATE entry
	EffectiveAfter uint64
}

// OpenIntent is an ACTION intent that has no completion yet.
type OpenIntent struct {
	Agent      [32]byte
	Height     uint64
	Hash       ledger.Hash
	ActionType string
	ArgsHash   ledger.Hash
	Time       uint64
}

type EpochSpan struct {
	From  uint64 // height of the entry that established this configuration
	Trust ledger.TrustConfig
}

// State is the result of a successful replay.
type State struct {
	Entries     int
	Epochs      []EpochSpan
	Frozen      bool
	Activations []Activation
	OpenIntents []OpenIntent
	Completed   int
}

// Trust returns the configuration in force after the last entry.
func (s *State) Trust() ledger.TrustConfig { return s.Epochs[len(s.Epochs)-1].Trust }

// TrustForSize returns the configuration in force once the first size entries
// have been applied, which is the one a checkpoint of that size is judged by.
func (s *State) TrustForSize(size uint64) (ledger.TrustConfig, bool) {
	if size == 0 || size > uint64(s.Entries) {
		return ledger.TrustConfig{}, false
	}
	t := s.Epochs[0].Trust
	for _, e := range s.Epochs {
		if e.From <= size-1 {
			t = e.Trust
		}
	}
	return t, true
}

// Approvals needed per tier, and how many of them must come from security
// reviewers. Fixed by the spec so every verifier agrees.
var approvals = [5]struct{ total, security int }{{0, 0}, {1, 0}, {2, 1}, {3, 1}, {3, 1}}

// Minimum delay in seconds per tier (constitution section 3).
var delays = [5]uint64{0, 24 * 3600, 72 * 3600, 7 * 24 * 3600, 14 * 24 * 3600}

const (
	targetValidators   = "cairn/validators"
	targetConstitution = "cairn/constitution"
	targetGatekeeper   = "cairn/gatekeeper"
)

type proposalRec struct {
	hash      ledger.Hash
	author    [32]byte
	time      uint64
	epoch     uint64
	p         ledger.Proposal
	activated bool
	effective uint64
	blocked   bool
	voters    map[[32]byte]bool
}

type voteRec struct {
	proposal ledger.Hash
	author   [32]byte
	verdict  ledger.Verdict
}

type agentRec struct {
	last ledger.Hash
	open []OpenIntent
}

type replayer struct {
	st        State
	blobs     Blobs
	proposals map[ledger.Hash]*proposalRec
	votes     map[ledger.Hash]voteRec
	agents    map[[32]byte]*agentRec
	pending   []*proposalRec // activated validators-set changes not yet applied
}

// Replay verifies the chain (authenticity) and then every governance rule
// (lawfulness). It stops at the first violation.
func Replay(entries []ledger.Entry, blobs Blobs, opt Options) (*State, error) {
	if err := ledger.VerifyChain(entries); err != nil {
		return nil, err
	}
	r := &replayer{
		blobs:     blobs,
		proposals: map[ledger.Hash]*proposalRec{},
		votes:     map[ledger.Hash]voteRec{},
		agents:    map[[32]byte]*agentRec{},
	}
	for i := range entries {
		e := &entries[i]
		if i > 0 && e.Time < entries[i-1].Time {
			return nil, fail(e.Height, CodeTimeRegression, "entry time is earlier than the previous entry")
		}
		var err error
		if i == 0 {
			err = r.genesis(e, opt)
		} else {
			err = r.apply(e)
		}
		if err != nil {
			return nil, err
		}
		r.st.Entries = i + 1
	}
	for _, ag := range r.agents {
		r.st.OpenIntents = append(r.st.OpenIntents, ag.open...)
	}
	sort.Slice(r.st.OpenIntents, func(i, j int) bool { return r.st.OpenIntents[i].Height < r.st.OpenIntents[j].Height })
	return &r.st, nil
}

func (r *replayer) trust() *ledger.TrustConfig { return &r.st.Epochs[len(r.st.Epochs)-1].Trust }

func (r *replayer) epoch() uint64 { return r.trust().Epoch }

func (r *replayer) payload(e *ledger.Entry) ([]byte, error) {
	b, ok := r.blobs.Get(e.PayloadHash)
	if !ok {
		return nil, fail(e.Height, CodeBadBlob, "payload blob is not available")
	}
	if ledger.BlobHash(b) != e.PayloadHash {
		return nil, fail(e.Height, CodeBadBlob, "payload blob does not match its hash")
	}
	return b, nil
}

func (r *replayer) require(e *ledger.Entry, roles ...ledger.Role) error {
	have, ok := r.trust().RoleOf(e.Author)
	if ok {
		for _, want := range roles {
			if have == want {
				return nil
			}
		}
	}
	return fail(e.Height, CodeUnauthorizedAuthor, fmt.Sprintf("%s may not be written by this key", e.Kind))
}

func (r *replayer) genesis(e *ledger.Entry, opt Options) error {
	b, err := r.payload(e)
	if err != nil {
		return err
	}
	g, err := ledger.DecodeGenesis(b)
	if err != nil {
		return decodeFail(e.Height, err)
	}
	if opt.ConstitutionHash != nil && g.ConstitutionHash != *opt.ConstitutionHash {
		return fail(e.Height, CodeConstitutionMismatch, "genesis records a different constitution")
	}
	r.st.Epochs = []EpochSpan{{From: 0, Trust: g.Trust}}
	return r.require(e, ledger.RoleValidator)
}

func (r *replayer) apply(e *ledger.Entry) error {
	b, err := r.payload(e)
	if err != nil {
		return err
	}
	switch e.Kind {
	case ledger.KindProposal:
		return r.proposal(e, b)
	case ledger.KindVote:
		return r.vote(e, b)
	case ledger.KindActivate:
		return r.activate(e, b)
	case ledger.KindAction:
		return r.action(e, b)
	case ledger.KindValidators:
		return r.validators(e, b)
	case ledger.KindFreeze:
		return r.freeze(e, b)
	}
	return fail(e.Height, CodeUnauthorizedAuthor, "unhandled entry kind")
}

func (r *replayer) proposal(e *ledger.Entry, b []byte) error {
	if err := r.require(e, ledger.RoleProposer, ledger.RoleAgent); err != nil {
		return err
	}
	p, err := ledger.DecodeProposal(b)
	if err != nil {
		return decodeFail(e.Height, err)
	}
	switch p.Target {
	case targetValidators, targetConstitution, targetGatekeeper:
		if p.Tier != ledger.T4 {
			return fail(e.Height, CodeReservedTarget, "this target can only change at tier T4")
		}
	default:
		if strings.HasPrefix(p.Target, "cairn/") {
			return fail(e.Height, CodeReservedTarget, "the cairn/ target namespace is reserved")
		}
	}
	h := e.Hash()
	r.proposals[h] = &proposalRec{hash: h, author: e.Author, time: e.Time, epoch: r.epoch(), p: p, voters: map[[32]byte]bool{}}
	return nil
}

func (r *replayer) vote(e *ledger.Entry, b []byte) error {
	if err := r.require(e, ledger.RoleReviewer, ledger.RoleSecurityReviewer); err != nil {
		return err
	}
	v, err := ledger.DecodeVote(b)
	if err != nil {
		return decodeFail(e.Height, err)
	}
	prop, ok := r.proposals[v.ProposalHash]
	switch {
	case !ok:
		return fail(e.Height, CodeUnknownProposal, "vote does not refer to a proposal")
	case prop.epoch != r.epoch():
		return fail(e.Height, CodeWrongEpoch, "the proposal belongs to an earlier epoch")
	case prop.activated:
		return fail(e.Height, CodeAlreadyActivated, "the proposal is already activated")
	case prop.voters[e.Author]:
		return fail(e.Height, CodeDuplicateVote, "this reviewer already voted on the proposal")
	}
	prop.voters[e.Author] = true
	if v.Verdict != ledger.VerdictApprove {
		prop.blocked = true
	}
	r.votes[e.Hash()] = voteRec{proposal: v.ProposalHash, author: e.Author, verdict: v.Verdict}
	return nil
}

func (r *replayer) activate(e *ledger.Entry, b []byte) error {
	if err := r.require(e, ledger.RoleValidator); err != nil {
		return err
	}
	a, err := ledger.DecodeActivate(b)
	if err != nil {
		return decodeFail(e.Height, err)
	}
	prop, ok := r.proposals[a.ProposalHash]
	switch {
	case !ok:
		return fail(e.Height, CodeUnknownProposal, "activation does not refer to a proposal")
	case prop.activated:
		return fail(e.Height, CodeAlreadyActivated, "the proposal is already activated")
	case prop.epoch != r.epoch():
		return fail(e.Height, CodeWrongEpoch, "the proposal belongs to an earlier epoch")
	case r.st.Frozen && prop.p.Tier > ledger.T0:
		return fail(e.Height, CodeFrozen, "only T0 changes may activate during a freeze")
	case prop.blocked:
		return fail(e.Height, CodeBlockedByVote, "a reviewer rejected or escalated this proposal")
	}
	seen := map[[32]byte]bool{}
	total, security := 0, 0
	for _, vh := range a.VoteHashes {
		vr, ok := r.votes[vh]
		if !ok || vr.proposal != a.ProposalHash || vr.verdict != ledger.VerdictApprove || seen[vr.author] {
			return fail(e.Height, CodeBadVoteReference, "a listed vote is missing, not an approval of this proposal, or repeated")
		}
		role, held := r.trust().RoleOf(vr.author)
		if !held || (role != ledger.RoleReviewer && role != ledger.RoleSecurityReviewer) {
			return fail(e.Height, CodeBadVoteReference, "a listed voter no longer holds a reviewer role")
		}
		seen[vr.author] = true
		total++
		if role == ledger.RoleSecurityReviewer {
			security++
		}
	}
	need := approvals[prop.p.Tier]
	if total < need.total || security < need.security {
		return fail(e.Height, CodeInsufficientApprovals, fmt.Sprintf("tier %d needs %d approvals including %d from security reviewers", prop.p.Tier, need.total, need.security))
	}
	if a.EffectiveAfter < prop.time || a.EffectiveAfter-prop.time < delays[prop.p.Tier] {
		return fail(e.Height, CodeDelayTooShort, "effective_after is sooner than the tier's minimum delay after the proposal")
	}
	prop.activated, prop.effective = true, a.EffectiveAfter
	r.st.Activations = append(r.st.Activations, Activation{
		ProposalHash: prop.hash, Proposal: prop.p, ProposedBy: prop.author, Epoch: prop.epoch,
		ActivatedAt: e.Height, EffectiveAfter: a.EffectiveAfter,
	})
	if prop.p.Target == targetValidators {
		r.pending = append(r.pending, prop)
	}
	return nil
}

func (r *replayer) action(e *ledger.Entry, b []byte) error {
	if err := r.require(e, ledger.RoleAgent); err != nil {
		return err
	}
	a, err := ledger.DecodeAction(b)
	if err != nil {
		return decodeFail(e.Height, err)
	}
	ag := r.agents[e.Author]
	if ag == nil {
		ag = &agentRec{}
		r.agents[e.Author] = ag
	}
	if a.PrevActionHash != ag.last {
		return fail(e.Height, CodeBadActionChain, "prev_action_hash is not this agent's previous action")
	}
	h := e.Hash()
	if a.ResultHash == (ledger.Hash{}) {
		oi := OpenIntent{Agent: e.Author, Height: e.Height, Hash: h, ActionType: a.ActionType, ArgsHash: a.ArgsHash, Time: e.Time}
		ag.open = append(ag.open, oi)
	} else {
		if len(ag.open) == 0 {
			return fail(e.Height, CodeBadActionCompletion, "completion with no open intent")
		}
		if o := ag.open[0]; o.ActionType != a.ActionType || o.ArgsHash != a.ArgsHash {
			return fail(e.Height, CodeBadActionCompletion, "completion does not match the oldest open intent")
		}
		ag.open = ag.open[1:]
		r.st.Completed++
	}
	ag.last = h
	return nil
}

func (r *replayer) freeze(e *ledger.Entry, b []byte) error {
	f, err := ledger.DecodeFreeze(b)
	if err != nil {
		return decodeFail(e.Height, err)
	}
	if f.Scope == ledger.FreezeLift {
		if err := r.require(e, ledger.RoleValidator); err != nil {
			return err
		}
		if !r.st.Frozen {
			return fail(e.Height, CodeBadFreezeState, "there is no freeze to lift")
		}
		r.st.Frozen = false
		return nil
	}
	if err := r.require(e, ledger.RoleValidator, ledger.RoleSecurityReviewer); err != nil {
		return err
	}
	if r.st.Frozen {
		return fail(e.Height, CodeBadFreezeState, "activations are already frozen")
	}
	r.st.Frozen = true
	return nil
}

func (r *replayer) validators(e *ledger.Entry, b []byte) error {
	if err := r.require(e, ledger.RoleValidator); err != nil {
		return err
	}
	tc, err := ledger.DecodeTrustConfig(b)
	if err != nil {
		return decodeFail(e.Height, err)
	}
	if tc.Epoch != r.epoch()+1 {
		return fail(e.Height, CodeWrongEpoch, "a new epoch must be exactly one more than the current one")
	}
	if r.st.Frozen {
		return fail(e.Height, CodeFrozen, "the validator set cannot change during a freeze")
	}
	want := ledger.BlobHash(b)
	var auth *proposalRec
	for _, p := range r.pending {
		if p.p.DiffHash == want {
			auth = p
			break
		}
	}
	if auth == nil {
		return fail(e.Height, CodeBadValidatorsChange, "no activated T4 proposal authorises exactly this configuration")
	}
	if e.Time < auth.effective {
		return fail(e.Height, CodeDelayNotElapsed, "the validator change is not yet effective")
	}
	r.pending = nil
	r.st.Epochs = append(r.st.Epochs, EpochSpan{From: e.Height, Trust: tc})
	return nil
}
