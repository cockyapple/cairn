// Package gatekeeper stands between governed agents and the things they can do.
// An agent asks for an action by name; the gatekeeper checks the agent's
// capabilities and that the configuration it runs is the one the log has
// activated, writes the intent to the ledger, and only then runs the handler. A
// refusal is logged the same way, as an intent with a completion that records
// the refusal.
//
// What this is: a policy and recording layer in one process. What it is not: an
// operating-system sandbox. A handler is ordinary Go code with the privileges of
// the process, and an agent that can run its own code outside the gatekeeper
// can skip it. The guarantee is that every action that goes through the
// gatekeeper is logged first, and that actions the policy denies never run.
package gatekeeper

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/cockyapple/cairn/ledger"
	"github.com/cockyapple/cairn/loader"
	"github.com/cockyapple/cairn/review"
)

const (
	DefaultMaxArgs = 64 << 10
	maxResult      = 256 << 10
)

// Refusal codes.
const (
	CodeUnknownAction  = "unknown_action"
	CodeNotPermitted   = "not_permitted"
	CodeArgsTooLarge   = "args_too_large"
	CodeNoConfig       = "no_config"
	CodeConfigUnusable = "config_unverifiable"
	CodeMessageInvalid = "message_invalid"
	CodeRouteDenied    = "route_denied"
	CodeMailboxFull    = "mailbox_full"
	CodeUnknownMessage = "unknown_message_type"
)

// Refusal is returned when policy stopped an action. Code is stable.
type Refusal struct{ Code, Detail string }

func (r *Refusal) Error() string { return "refused: " + r.Code + ": " + r.Detail }

// ErrCode returns the refusal code of err, which may carry a loader code
// ("config_" plus the loader's), or "" if err is not a refusal.
func ErrCode(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	return ""
}

var (
	ErrUnknownAgent = errors.New("gatekeeper: no such agent")
	ErrNotLogged    = errors.New("gatekeeper: the intent could not be logged, so the action did not run")
)

// Handler performs one kind of action. It runs only after the intent is on the log.
type Handler func(ctx context.Context, args []byte) ([]byte, error)

// Agent is one governed actor. Key must hold the agent role in the trust
// configuration, or no intent can be logged and nothing it asks for runs.
type Agent struct {
	Name string
	Key  ed25519.PrivateKey
	// Allow lists the action types the agent may request. Empty allows nothing.
	Allow   []string
	MaxArgs int
	// RateLimit caps requests per RateWindow (default one minute). Zero means no cap.
	RateLimit  int
	RateWindow time.Duration
	// Review lists action types that run only after a reviewer signs off. Each must
	// also be in Allow. The intent stays open on the log while the action waits.
	Review []string
	// Untrusted lists action types whose results taint the agent: handlers that
	// read the web, a mailbox, a file someone else wrote. Each must be in Allow.
	Untrusted []string
	// Guard lists action types the agent may not run while tainted (each must be
	// in Allow). With GuardEscalate a tainted request is held for human review
	// instead of refused.
	Guard         []string
	GuardEscalate bool
	// Config names the artifact the agent is running. When the gatekeeper has a
	// View, the agent acts only while that exact artifact is the one in force.
	ConfigTarget   string
	ConfigArtifact []byte

	mu               sync.Mutex // serialises this agent's actions: the log chains them
	allowed          map[string]bool
	review           map[string]bool
	untrusted, guard map[string]bool
	tmu              sync.Mutex // guards taintedBy; a leaf lock, taken while holding g.mu
	taintedBy        string
	// pending is a completion the log refused after the handler had run. The
	// intent is still open, and the replay wants it closed first, so the agent
	// takes no new action until this is written.
	pending     *pendingCompletion
	winStart    time.Time
	winCount    int
	unlogged    int  // refusals counted but not individually logged
	limitLogged bool // the first over-budget refusal of this window is on the log
}

type pendingCompletion struct {
	actionType string
	args, blob []byte
}

// View returns a freshly verified loader gate and the current trusted time.
// Where the gate comes from, and how fresh it is, is the caller's responsibility.
type View func() (*loader.Gate, uint64, error)

type Gatekeeper struct {
	mu       sync.Mutex // guards the log and the tables below
	log      *review.Log
	agents   map[string]*Agent
	handlers map[string]Handler
	types    map[string]*MessageType
	boxes    map[string][]Message
	waiting  map[ledger.Hash]*waiting

	View    View
	Timeout time.Duration    // per action; zero means one minute
	Now     func() time.Time // clock for rate windows; nil means time.Now
	// ReviewTimeout bounds the wait for a human decision; zero means DefaultReviewTimeout.
	ReviewTimeout time.Duration
}

func New(l *review.Log) *Gatekeeper {
	return &Gatekeeper{
		log: l, agents: map[string]*Agent{}, handlers: map[string]Handler{},
		types: map[string]*MessageType{}, boxes: map[string][]Message{}, waiting: map[ledger.Hash]*waiting{},
	}
}

func (g *Gatekeeper) AddAgent(a *Agent) error {
	if a.Name == "" || len(a.Key) != ed25519.PrivateKeySize {
		return errors.New("gatekeeper: an agent needs a name and an ed25519 key")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, dup := g.agents[a.Name]; dup {
		return fmt.Errorf("gatekeeper: agent %q already exists", a.Name)
	}
	a.allowed = map[string]bool{}
	for _, t := range a.Allow {
		a.allowed[t] = true
	}
	a.review = map[string]bool{}
	for _, t := range a.Review {
		a.review[t] = true
	}
	for _, t := range a.Review {
		if !slices.Contains(a.Allow, t) {
			return fmt.Errorf("gatekeeper: %q needs review but the agent may not request it", t)
		}
	}
	if err := a.setProvenance(); err != nil {
		return err
	}
	if a.RateLimit < 0 || a.RateWindow < 0 {
		return errors.New("gatekeeper: rate limit and window cannot be negative")
	}
	if a.MaxArgs <= 0 {
		a.MaxArgs = DefaultMaxArgs
	}
	g.agents[a.Name] = a
	return nil
}

func (g *Gatekeeper) Handle(actionType string, h Handler) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.handlers[actionType] = h
}

func (g *Gatekeeper) agent(name string) (*Agent, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	a, ok := g.agents[name]
	if !ok {
		return nil, ErrUnknownAgent
	}
	return a, nil
}

// Result blobs start with a status line so a completion says what happened.
func okResult(b []byte) []byte      { return append([]byte("ok\n"), b...) }
func errResult(msg string) []byte   { return []byte("error\n" + msg) }
func refusalBlob(r *Refusal) []byte { return []byte("refused\n" + r.Code + "\n" + r.Detail) }

func (g *Gatekeeper) intent(a *Agent, actionType string, args []byte) (ledger.Hash, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	h, err := g.log.Intent(a.Key, actionType, args)
	if err != nil {
		return h, fmt.Errorf("%w: %v", ErrNotLogged, err)
	}
	return h, nil
}

func (g *Gatekeeper) complete(a *Agent, actionType string, args, result []byte) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, err := g.log.Complete(a.Key, actionType, args, result)
	return err
}

// refuse logs the refusal and returns it.
func (g *Gatekeeper) refuse(a *Agent, actionType string, args []byte, r *Refusal) error {
	if err := g.flush(a); err != nil {
		return err
	}
	if _, err := g.intent(a, actionType, args); err != nil {
		return err
	}
	if err := g.finish(a, actionType, args, refusalBlob(r)); err != nil {
		return err
	}
	return r
}

// finish writes a completion and, if the log refuses it, remembers it so that
// flush can retry before the agent does anything else.
func (g *Gatekeeper) finish(a *Agent, actionType string, args, blob []byte) error {
	err := g.complete(a, actionType, args, blob)
	if err != nil {
		a.pending = &pendingCompletion{actionType, args, blob}
	}
	return err
}

// flush retries a completion the log refused earlier. Until it is written the
// agent's oldest open intent is still open, so no new action may start.
func (g *Gatekeeper) flush(a *Agent) error {
	p := a.pending
	if p == nil {
		return nil
	}
	if err := g.complete(a, p.actionType, p.args, p.blob); err != nil {
		return fmt.Errorf("%w: an earlier completion is still unwritten: %v", ErrNotLogged, err)
	}
	a.pending = nil
	return nil
}

func (g *Gatekeeper) configOK(a *Agent) *Refusal {
	if g.View == nil {
		return nil
	}
	if a.ConfigTarget == "" {
		return &Refusal{CodeNoConfig, "the agent declares no configuration to verify"}
	}
	gate, now, err := g.View()
	if err != nil || gate == nil {
		return &Refusal{CodeConfigUnusable, "the log could not be verified"}
	}
	if err := gate.Check(a.ConfigTarget, a.ConfigArtifact, now); err != nil {
		return &Refusal{"config_" + loader.ErrCode(err), "the agent's configuration is not the one in force"}
	}
	return nil
}

// Do runs one action for an agent: policy, then intent, then the handler, then
// completion. The returned error is a *Refusal when policy said no, and wraps
// ErrNotLogged when the log would not take the intent.
func (g *Gatekeeper) Do(ctx context.Context, agent, actionType string, args []byte) ([]byte, error) {
	a, err := g.agent(agent)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := g.admit(a); err != nil {
		return nil, err
	}
	return g.do(ctx, a, actionType, args, nil)
}

func (g *Gatekeeper) do(ctx context.Context, a *Agent, actionType string, args []byte, run Handler) ([]byte, error) {
	if err := g.flush(a); err != nil {
		return nil, err
	}
	if len(args) > a.MaxArgs {
		return nil, g.refuse(a, actionType, nil, &Refusal{CodeArgsTooLarge, fmt.Sprintf("%d bytes exceeds the limit of %d", len(args), a.MaxArgs)})
	}
	if !a.allowed[actionType] {
		return nil, g.refuse(a, actionType, args, &Refusal{CodeNotPermitted, "the agent holds no capability for this action"})
	}
	if run == nil {
		g.mu.Lock()
		run = g.handlers[actionType]
		g.mu.Unlock()
		if run == nil {
			return nil, g.refuse(a, actionType, args, &Refusal{CodeUnknownAction, "no handler is registered for this action"})
		}
	}
	if r := g.configOK(a); r != nil {
		return nil, g.refuse(a, actionType, args, r)
	}
	escalated := false
	if a.guard[actionType] {
		if by := a.taintOf(); by != "" {
			if !a.GuardEscalate {
				return nil, g.refuse(a, actionType, args, &Refusal{CodeTaintedInput, "the agent has handled untrusted input (" + by + ") and has not been reset"})
			}
			escalated = true
		}
	}
	ih, err := g.intent(a, actionType, args)
	if err != nil {
		return nil, err
	}
	var reviewed []byte
	if a.review[actionType] || escalated {
		d, r := g.awaitReview(ctx, a, ih, actionType, args)
		if r == nil {
			reviewed = d.header()
			r = g.configOK(a) // the wait can be long; the configuration may have changed
		} else if d.Reviewer != ([32]byte{}) {
			reviewed = d.header()
		}
		if r != nil {
			if err := g.finish(a, actionType, args, append(reviewed, refusalBlob(r)...)); err != nil {
				return nil, err
			}
			return nil, r
		}
	}
	timeout := g.Timeout
	if timeout == 0 {
		timeout = time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	res, herr := safeRun(cctx, run, args)
	if a.untrusted[actionType] {
		a.taint(actionType)
	}
	var blob []byte
	switch {
	case herr != nil:
		blob = errResult(herr.Error())
	case len(res) > maxResult:
		herr, blob = errors.New("result too large"), errResult("result too large")
	default:
		blob = okResult(res)
	}
	blob = append(reviewed, blob...)
	if err := g.finish(a, actionType, args, blob); err != nil {
		return nil, fmt.Errorf("gatekeeper: action ran but its completion could not be logged: %w", err)
	}
	if herr != nil {
		return nil, herr
	}
	return res, nil
}

func safeRun(ctx context.Context, h Handler, args []byte) (res []byte, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("handler panicked: %v", p)
		}
	}()
	return h(ctx, args)
}
