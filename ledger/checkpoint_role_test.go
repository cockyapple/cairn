package ledger

import (
	"bytes"
	"testing"
)

func TestCheckpointRefusesASignerWhoseRoleDoesNotSignCheckpoints(t *testing.T) {
	vk, rk := testKey("cp-validator"), testKey("cp-reviewer")
	g := Entry{Kind: KindGenesis, Time: 1}
	g.Sign(vk)
	entries := []Entry{g}
	trust := &TrustConfig{Epoch: 0, Keys: []Key{{Role: RoleValidator, Public: pub(vk)}, {Role: RoleReviewer, Public: pub(rk)}}}

	sc := SignedCheckpoint{Checkpoint: NewCheckpoint(0, entries)}
	sc.Cosign(vk)
	if err := VerifyCheckpoint(&sc, entries, trust); err != nil {
		t.Fatalf("a validator-only checkpoint should verify: %v", err)
	}

	sc.Cosign(rk)
	if bytes.Compare(sc.Sigs[0].Public[:], sc.Sigs[1].Public[:]) > 0 {
		sc.Sigs[0], sc.Sigs[1] = sc.Sigs[1], sc.Sigs[0]
	}
	if err := VerifyCheckpoint(&sc, entries, trust); ErrCode(err) != CodeUnknownSigner {
		t.Fatalf("a reviewer's signature must not be admitted, got %v", err)
	}
}
