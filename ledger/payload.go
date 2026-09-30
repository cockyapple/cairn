package ledger

import "github.com/cockyapple/cairn/wire"

// Payload structs are the canonical contents of the blobs that entries point
// to. Each entry's PayloadHash is BlobHash(payload.Encode()).

const SpecVersion = 1

type Genesis struct {
	SpecVersion      uint32
	ConstitutionHash Hash
	Trust            TrustConfig
}

func (g *Genesis) Encode() []byte {
	var w wire.Writer
	w.U32(g.SpecVersion)
	w.Fixed(g.ConstitutionHash[:])
	writeTrust(&w, &g.Trust)
	return w.Out()
}

func DecodeGenesis(b []byte) (Genesis, error) {
	var g Genesis
	r := wire.NewReader(b)
	g.SpecVersion = r.U32()
	copy(g.ConstitutionHash[:], r.Fixed(32))
	g.Trust = readTrust(r)
	if err := r.Done(); err != nil {
		return g, fail(CodeBadPayload, err.Error())
	}
	return g, g.Trust.validate()
}

type Tier uint8

const (
	T0 Tier = iota
	T1
	T2
	T3
	T4
)

type Proposal struct {
	Tier          Tier
	Target        string // what is being changed, e.g. "prompt/system"
	DiffHash      Hash
	RationaleHash Hash
	EvalHash      Hash // zero if no eval ran
}

func (p *Proposal) Encode() []byte {
	var w wire.Writer
	w.U8(uint8(p.Tier))
	w.String(p.Target)
	w.Fixed(p.DiffHash[:])
	w.Fixed(p.RationaleHash[:])
	w.Fixed(p.EvalHash[:])
	return w.Out()
}

func DecodeProposal(b []byte) (Proposal, error) {
	var p Proposal
	r := wire.NewReader(b)
	p.Tier = Tier(r.U8())
	p.Target = r.String()
	copy(p.DiffHash[:], r.Fixed(32))
	copy(p.RationaleHash[:], r.Fixed(32))
	copy(p.EvalHash[:], r.Fixed(32))
	if err := r.Done(); err != nil {
		return p, fail(CodeBadPayload, err.Error())
	}
	if p.Tier > T4 {
		return p, fail(CodeBadPayload, "unknown tier")
	}
	return p, nil
}

type Verdict uint8

const (
	VerdictApprove  Verdict = 1
	VerdictReject   Verdict = 2
	VerdictEscalate Verdict = 3
)

type Vote struct {
	ProposalHash Hash // entry hash of the PROPOSAL entry
	Verdict      Verdict
	CommentHash  Hash
}

func (v *Vote) Encode() []byte {
	var w wire.Writer
	w.Fixed(v.ProposalHash[:])
	w.U8(uint8(v.Verdict))
	w.Fixed(v.CommentHash[:])
	return w.Out()
}

func DecodeVote(b []byte) (Vote, error) {
	var v Vote
	r := wire.NewReader(b)
	copy(v.ProposalHash[:], r.Fixed(32))
	v.Verdict = Verdict(r.U8())
	copy(v.CommentHash[:], r.Fixed(32))
	if err := r.Done(); err != nil {
		return v, fail(CodeBadPayload, err.Error())
	}
	if v.Verdict < VerdictApprove || v.Verdict > VerdictEscalate {
		return v, fail(CodeBadPayload, "unknown verdict")
	}
	return v, nil
}

const maxVotes = 256

type Activate struct {
	ProposalHash   Hash
	VoteHashes     []Hash // entry hashes of the VOTE entries relied on
	EffectiveAfter uint64 // unix seconds; must respect the tier's delay
}

func (a *Activate) Encode() []byte {
	var w wire.Writer
	w.Fixed(a.ProposalHash[:])
	w.U32(uint32(len(a.VoteHashes)))
	for _, h := range a.VoteHashes {
		w.Fixed(h[:])
	}
	w.U64(a.EffectiveAfter)
	return w.Out()
}

func DecodeActivate(b []byte) (Activate, error) {
	var a Activate
	r := wire.NewReader(b)
	copy(a.ProposalHash[:], r.Fixed(32))
	n := r.Count(maxVotes)
	for i := 0; i < n; i++ {
		var h Hash
		copy(h[:], r.Fixed(32))
		a.VoteHashes = append(a.VoteHashes, h)
	}
	a.EffectiveAfter = r.U64()
	if err := r.Done(); err != nil {
		return a, fail(CodeBadPayload, err.Error())
	}
	return a, nil
}

type Action struct {
	ActionType     string // e.g. "tool_call", "spend"
	ArgsHash       Hash
	ResultHash     Hash
	PrevActionHash Hash // zero for an agent's first action; chains its own actions
}

func (a *Action) Encode() []byte {
	var w wire.Writer
	w.String(a.ActionType)
	w.Fixed(a.ArgsHash[:])
	w.Fixed(a.ResultHash[:])
	w.Fixed(a.PrevActionHash[:])
	return w.Out()
}

func DecodeAction(b []byte) (Action, error) {
	var a Action
	r := wire.NewReader(b)
	a.ActionType = r.String()
	copy(a.ArgsHash[:], r.Fixed(32))
	copy(a.ResultHash[:], r.Fixed(32))
	copy(a.PrevActionHash[:], r.Fixed(32))
	if err := r.Done(); err != nil {
		return a, fail(CodeBadPayload, err.Error())
	}
	return a, nil
}

type FreezeScope uint8

const FreezeActivations FreezeScope = 1

type Freeze struct {
	Scope      FreezeScope
	ReasonHash Hash
}

func (f *Freeze) Encode() []byte {
	var w wire.Writer
	w.U8(uint8(f.Scope))
	w.Fixed(f.ReasonHash[:])
	return w.Out()
}

func DecodeFreeze(b []byte) (Freeze, error) {
	var f Freeze
	r := wire.NewReader(b)
	f.Scope = FreezeScope(r.U8())
	copy(f.ReasonHash[:], r.Fixed(32))
	if err := r.Done(); err != nil {
		return f, fail(CodeBadPayload, err.Error())
	}
	if f.Scope != FreezeActivations {
		return f, fail(CodeBadPayload, "unknown freeze scope")
	}
	return f, nil
}
