package gatekeeper

import (
	"errors"
	"fmt"
	"slices"
)

// Provenance tracking. The gatekeeper cannot see data flow inside a model, so
// taint is a property of an agent's session, not of a value: once an agent has
// handled untrusted input it stays tainted until an operator resets it. A
// tainted agent cannot run its Guard actions, or, with GuardEscalate, can run
// them only after a reviewer approves.
//
// This narrows what injected text can make an agent do. It does not detect a
// lie that arrives through a channel the operator marked trusted, and it does
// not survive a process restart: a restarted gatekeeper starts every agent clean.

const CodeTaintedInput = "tainted_input"

const maxResetReason = 1024

var ErrBadReset = errors.New("gatekeeper: a taint reset needs a reason of at most 1024 bytes")

func (a *Agent) taint(by string) {
	a.tmu.Lock()
	defer a.tmu.Unlock()
	if a.taintedBy == "" {
		a.taintedBy = by
	}
}

func (a *Agent) taintOf() string {
	a.tmu.Lock()
	defer a.tmu.Unlock()
	return a.taintedBy
}

func (a *Agent) untaint() {
	a.tmu.Lock()
	defer a.tmu.Unlock()
	a.taintedBy = ""
}

func (a *Agent) setProvenance() error {
	a.untrusted, a.guard = map[string]bool{}, map[string]bool{}
	for _, t := range a.Untrusted {
		if !slices.Contains(a.Allow, t) {
			return fmt.Errorf("gatekeeper: %q is marked untrusted but the agent may not request it", t)
		}
		a.untrusted[t] = true
	}
	for _, t := range a.Guard {
		if !slices.Contains(a.Allow, t) {
			return fmt.Errorf("gatekeeper: %q is guarded but the agent may not request it", t)
		}
		a.guard[t] = true
	}
	return nil
}

// Tainted reports whether the agent has handled untrusted input since its last
// reset, and the first source that tainted it.
func (g *Gatekeeper) Tainted(agent string) (by string, tainted bool, err error) {
	a, err := g.agent(agent)
	if err != nil {
		return "", false, err
	}
	by = a.taintOf()
	return by, by != "", nil
}

// ResetTaint clears an agent's taint. The reset is logged as the agent's action
// "taint.reset", with the source it cleared and the operator's reason, so it
// cannot be done quietly. Agents cannot call this; it is for the operator.
//
// ResetTaint waits for the agent's action in flight, including one held for
// review. Once the intent is on the log the taint is cleared; if the completion
// cannot be written, an error says so and the next action writes it first.
func (g *Gatekeeper) ResetTaint(agent, reason string) error {
	if reason == "" || len(reason) > maxResetReason {
		return ErrBadReset
	}
	a, err := g.agent(agent)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := g.flush(a); err != nil {
		return err
	}
	args := []byte("cleared:" + a.taintOf() + "\nreason:" + reason)
	if _, err := g.intent(a, "taint.reset", args, nil); err != nil {
		return err
	}
	a.untaint()
	if err := g.finish(a, okResult(nil)); err != nil {
		return fmt.Errorf("gatekeeper: taint cleared but its completion could not be logged yet: %w", err)
	}
	return nil
}
