package ledger

import (
	"crypto/ecdh"
	"math/big"
)

var (
	fieldP     = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	probeScale = func() *ecdh.PrivateKey {
		// Clamped X25519 scalars are multiples of 8, so the product with any
		// point of order dividing 8 is the identity, which crypto/ecdh rejects.
		k, err := ecdh.X25519().NewPrivateKey([]byte("cairn small-order probe scalar!!"))
		if err != nil {
			panic(err)
		}
		return k
	}()
)

// smallOrder reports whether an Ed25519 public key has order dividing 8.
// ed25519.Verify accepts such keys, and anyone can then forge signatures for
// them, so no entry author and no admitted key may be one. Non-canonical
// encodings are reduced mod p exactly as the verifier decodes them.
func smallOrder(pub [32]byte) bool {
	var be [32]byte
	for i := range be {
		be[i] = pub[31-i]
	}
	be[0] &= 0x7f
	y := new(big.Int).SetBytes(be[:])
	y.Mod(y, fieldP)
	den := new(big.Int).Sub(big.NewInt(1), y)
	den.Mod(den, fieldP)
	if den.Sign() == 0 {
		return true // y = 1 is the identity
	}
	u := new(big.Int).Add(big.NewInt(1), y)
	u.Mul(u, den.ModInverse(den, fieldP)).Mod(u, fieldP)
	var le [32]byte
	ub := u.FillBytes(make([]byte, 32))
	for i := range le {
		le[i] = ub[31-i]
	}
	pk, err := ecdh.X25519().NewPublicKey(le[:])
	if err != nil {
		return true
	}
	_, err = probeScale.ECDH(pk)
	return err != nil
}
