package review

import (
	"crypto/ed25519"

	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
)

// ProposeGrant files a proposal that sets agent's capability grant. The tier
// must be T3 or T4; the replay decides the rest.
func (l *Log) ProposeGrant(key ed25519.PrivateKey, tier ledger.Tier, agent [32]byte, g governance.Grant, rationale []byte) (ledger.Hash, error) {
	b, err := g.Encode()
	if err != nil {
		return ledger.Hash{}, err
	}
	return l.Propose(key, tier, governance.GrantTarget(agent), b, rationale, nil)
}

// Delegate records a delegation from the agent holding key to child: an intent
// and its completion, so no intent is left open. The intent is the entry the
// replay checks; if it is refused nothing is written and the error says why.
func (l *Log) Delegate(key ed25519.PrivateKey, child [32]byte, g governance.Grant) (ledger.Hash, error) {
	b, err := governance.Delegation{Child: child, Grant: g}.Encode()
	if err != nil {
		return ledger.Hash{}, err
	}
	h, err := l.Intent(key, governance.ActionDelegate, b)
	if err != nil {
		return ledger.Hash{}, err
	}
	if _, err := l.Complete(key, governance.ActionDelegate, b, []byte("ok\n")); err != nil {
		return h, err
	}
	return h, nil
}

// ProposeRequireGrants files the T4 proposal that switches the require-grants
// rule (SPEC 10.3.4) on or off.
func (l *Log) ProposeRequireGrants(key ed25519.PrivateKey, on bool, rationale []byte) (ledger.Hash, error) {
	return l.Propose(key, ledger.T4, governance.PolicyTarget, governance.RequirePolicy{Require: on}.Encode(), rationale, nil)
}
