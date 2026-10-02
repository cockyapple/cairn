package ledger

import "github.com/cockyapple/cairn/wire"

type Role uint8

const (
	RoleValidator        Role = 1
	RoleWitness          Role = 2
	RoleReviewer         Role = 3
	RoleSecurityReviewer Role = 4
	RoleProposer         Role = 5
	RoleAgent            Role = 6
)

func (r Role) Valid() bool { return r >= RoleValidator && r <= RoleAgent }

type Key struct {
	Role   Role
	Public [32]byte
}

// TrustConfig is who is admitted to which role in one epoch. It is the payload
// of GENESIS (epoch 0) and VALIDATORS (later epochs).
type TrustConfig struct {
	Epoch            uint64
	Keys             []Key
	WitnessThreshold uint32
}

const maxKeys = 1024

func (t *TrustConfig) Encode() []byte {
	var w wire.Writer
	w.U64(t.Epoch)
	w.U32(uint32(len(t.Keys)))
	for _, k := range t.Keys {
		w.U8(uint8(k.Role))
		w.Fixed(k.Public[:])
	}
	w.U32(t.WitnessThreshold)
	return w.Out()
}

func writeTrust(w *wire.Writer, t *TrustConfig) { w.Fixed(t.Encode()) }

func readTrust(r *wire.Reader) TrustConfig {
	var t TrustConfig
	t.Epoch = r.U64()
	n := r.Count(maxKeys)
	for i := 0; i < n; i++ {
		var k Key
		k.Role = Role(r.U8())
		copy(k.Public[:], r.Fixed(32))
		t.Keys = append(t.Keys, k)
	}
	t.WitnessThreshold = r.U32()
	return t
}

func DecodeTrustConfig(b []byte) (TrustConfig, error) {
	r := wire.NewReader(b)
	t := readTrust(r)
	if err := r.Done(); err != nil {
		return t, fail(CodeBadTrustConfig, err.Error())
	}
	return t, t.validate()
}

func (t *TrustConfig) validate() error {
	if len(t.Keys) > maxKeys {
		return fail(CodeBadTrustConfig, "too many keys")
	}
	seen := map[[32]byte]bool{}
	var validators, witnesses uint32
	for _, k := range t.Keys {
		if smallOrder(k.Public) {
			return fail(CodeBadTrustConfig, "small-order public key")
		}
		if !k.Role.Valid() {
			return fail(CodeBadTrustConfig, "unknown role")
		}
		if seen[k.Public] {
			return fail(CodeBadTrustConfig, "a key may hold only one role")
		}
		seen[k.Public] = true
		switch k.Role {
		case RoleValidator:
			validators++
		case RoleWitness:
			witnesses++
		}
	}
	if validators == 0 {
		return fail(CodeBadTrustConfig, "at least one validator is required")
	}
	if t.WitnessThreshold > witnesses {
		return fail(CodeBadTrustConfig, "witness threshold exceeds witness count")
	}
	return nil
}

// RoleOf reports the role a key holds in this configuration.
func (t *TrustConfig) RoleOf(pub [32]byte) (Role, bool) {
	for _, k := range t.Keys {
		if k.Public == pub {
			return k.Role, true
		}
	}
	return 0, false
}

func (t *TrustConfig) count(role Role) int {
	n := 0
	for _, k := range t.Keys {
		if k.Role == role {
			n++
		}
	}
	return n
}

// ValidatorQuorum is n - f where f = (n-1)/3: the number of validator
// signatures that guarantees any two quorums overlap in an honest validator.
// n=1 -> 1, n=4 -> 3, n=7 -> 5.
func ValidatorQuorum(n int) int {
	if n < 1 {
		return 0
	}
	return n - (n-1)/3
}

// Validate reports whether t is a well-formed trust configuration.
func (t *TrustConfig) Validate() error { return t.validate() }
