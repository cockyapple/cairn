package review

import (
	"crypto/ed25519"

	"github.com/cockyapple/cairn/ledger"
)

func (l *Log) lastAction(author [32]byte) ledger.Hash {
	for i := len(l.Entries) - 1; i >= 0; i-- {
		if e := &l.Entries[i]; e.Kind == ledger.KindAction && e.Author == author {
			return e.Hash()
		}
	}
	return ledger.Hash{}
}

func (l *Log) action(key ed25519.PrivateKey, actionType string, args []byte, result *ledger.Hash) (ledger.Hash, error) {
	var pub [32]byte
	copy(pub[:], key.Public().(ed25519.PublicKey))
	a := ledger.Action{ActionType: actionType, ArgsHash: l.store(args), PrevActionHash: l.lastAction(pub)}
	if result != nil {
		a.ResultHash = *result
	}
	return l.append(ledger.KindAction, key, a.Encode())
}

// Intent records that the agent is about to act. It must be appended before
// the action runs (ADR-13); a refusal here means the action must not run.
func (l *Log) Intent(key ed25519.PrivateKey, actionType string, args []byte) (ledger.Hash, error) {
	return l.action(key, actionType, args, nil)
}

// Complete records the outcome of the oldest open intent of the same type and
// arguments. result is stored as a blob and its hash is the entry's result_hash.
func (l *Log) Complete(key ed25519.PrivateKey, actionType string, args, result []byte) (ledger.Hash, error) {
	h := l.store(result)
	return l.action(key, actionType, args, &h)
}
