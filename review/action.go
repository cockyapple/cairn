package review

import (
	"bytes"
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

func (l *Log) actionHash(key ed25519.PrivateKey, actionType string, args ledger.Hash, result *ledger.Hash) (ledger.Hash, error) {
	var pub [32]byte
	copy(pub[:], key.Public().(ed25519.PublicKey))
	a := ledger.Action{ActionType: actionType, ArgsHash: args, PrevActionHash: l.lastAction(pub)}
	if result != nil {
		a.ResultHash = *result
	}
	return l.append(ledger.KindAction, key, a.Encode())
}

// Intent records that the agent is about to act. It must be appended before
// the action runs (ADR-13); a refusal here means the action must not run.
func (l *Log) Intent(key ed25519.PrivateKey, actionType string, args []byte) (ledger.Hash, error) {
	return l.actionHash(key, actionType, l.store(args), nil)
}

// Complete records the outcome of the oldest open intent of the same type and
// arguments. result is stored as a blob and its hash is the entry's result_hash.
func (l *Log) Complete(key ed25519.PrivateKey, actionType string, args, result []byte) (ledger.Hash, error) {
	h := l.store(result)
	return l.actionHash(key, actionType, ledger.BlobHash(args), &h)
}

// IntentHash is Intent for arguments the caller keeps to itself: only their hash
// goes on the log, and nothing is stored. If the agent is bound by a grant the
// replay needs the args blob, use IntentPublished instead.
func (l *Log) IntentHash(key ed25519.PrivateKey, actionType string, args ledger.Hash) (ledger.Hash, error) {
	return l.actionHash(key, actionType, args, nil)
}

// CompleteHash is Complete for arguments and a result the caller keeps to itself.
func (l *Log) CompleteHash(key ed25519.PrivateKey, actionType string, args, result ledger.Hash) (ledger.Hash, error) {
	return l.actionHash(key, actionType, args, &result)
}

// IntentPublished is IntentHash for an intent whose args blob the replay must
// read (a bound agent's use blob). The blob is published only if the log takes
// the entry, so a rejected attempt leaves nothing behind.
func (l *Log) IntentPublished(key ed25519.PrivateKey, actionType string, blob []byte) (ledger.Hash, ledger.Hash, error) {
	h := ledger.BlobHash(blob)
	_, had := l.Blobs[h]
	l.Blobs[h] = bytes.Clone(blob)
	eh, err := l.actionHash(key, actionType, h, nil)
	if err != nil && !had {
		delete(l.Blobs, h)
	}
	return eh, h, err
}
