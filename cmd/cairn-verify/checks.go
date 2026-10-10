package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/cockyapple/cairn/ledger"
)

const (
	codeWrongGenesis = "wrong_genesis" // same string cairn-witness uses for its pin
	codeStale        = "stale_checkpoint"
	codeFutureDated  = "future_dated"
	futureSkew       = 300 // seconds, the same allowance -use-clock gives
)

// now is the verifier's clock, replaceable in tests.
var now = time.Now

// testKeyNames are the keys whose private halves are derivable from a public
// rule (testdata/vectors-v1.json is published). Anyone can sign as them.
var testKeyNames = []string{"founder", "v1", "v2", "v3", "v4", "v5", "w1", "w2", "r1", "r2", "r3", "s1", "s2", "p1", "a1", "outsider"}

func publishedTestKeys() map[[32]byte]string {
	m := map[[32]byte]string{}
	for _, n := range testKeyNames {
		seed := sha256.Sum256([]byte("cairn-test-key-" + n))
		var p [32]byte
		copy(p[:], ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey))
		m[p] = n
	}
	return m
}

var roleNames = map[ledger.Role]string{
	ledger.RoleValidator: "validator", ledger.RoleWitness: "witness", ledger.RoleReviewer: "reviewer",
	ledger.RoleSecurityReviewer: "security reviewer", ledger.RoleProposer: "proposer", ledger.RoleAgent: "agent",
}

// trustWarnings names configurations that are legal but weak. They are
// warnings, never failures: the log is allowed to be set up this way.
func trustWarnings(t ledger.TrustConfig) []string {
	var w []string
	validators := 0
	known := publishedTestKeys()
	for _, k := range t.Keys {
		if k.Role == ledger.RoleValidator {
			validators++
		}
		if n, ok := known[k.Public]; ok {
			w = append(w, fmt.Sprintf("a %s key in this log is the published test key %q; anyone can sign as it", roleNames[k.Role], n))
		}
	}
	if validators == 1 {
		w = append(w, "this log has a single validator, so one operator can sign checkpoints alone")
	}
	if t.WitnessThreshold == 0 {
		w = append(w, "the witness threshold is 0, so no outside cosignature is needed for a checkpoint to pass")
	}
	return w
}

func parseGenesisPin(s string) (ledger.Hash, error) {
	var h ledger.Hash
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(h) {
		return h, fmt.Errorf("-genesis must be 64 hex characters")
	}
	copy(h[:], b)
	return h, nil
}

// checkAge refuses a log whose newest signed entry is older than max by this
// machine's clock. Entry times are claimed by their signers, so this catches a
// server replaying an old log, not a key holder who back- or forward-dates.
func checkAge(head ledger.Entry, max time.Duration) (string, string) {
	t := now().Unix()
	if head.Time > uint64(t)+futureSkew {
		return codeFutureDated, fmt.Sprintf("the newest covered entry (height %d) is dated %d seconds ahead of this machine's clock", head.Height, head.Time-uint64(t))
	}
	age := time.Duration(0)
	if uint64(t) > head.Time {
		age = time.Duration(uint64(t)-head.Time) * time.Second
	}
	if age > max {
		return codeStale, fmt.Sprintf("the newest covered entry (height %d) is %s old, over the limit of %s; this may be an old copy of the log", head.Height, age.Round(time.Second), max)
	}
	return "", fmt.Sprintf("newest covered entry (height %d) is %s old, within %s", head.Height, age.Round(time.Second), max)
}
