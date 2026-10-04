package note

import "testing"

// Standard base64 contains '+', so a verifier key must parse whatever its
// third part holds.
func TestParseVKeyWhenTheBase64PartContainsPlus(t *testing.T) {
	found := 0
	for i := 0; i < 400 && found < 5; i++ {
		k := key(string(rune('a'+i%26)) + string(rune('A'+i/26)))
		v, err := VKey(origin, SigEd25519, pub(k))
		if err != nil {
			t.Fatal(err)
		}
		hasPlus := false
		for _, c := range v[len(origin)+10:] {
			hasPlus = hasPlus || c == '+'
		}
		if !hasPlus {
			continue
		}
		found++
		n, typ, pk, err := ParseVKey(v)
		if err != nil || n != origin || typ != SigEd25519 || pk != pub(k) {
			t.Fatalf("%s: %v", v, err)
		}
	}
	if found == 0 {
		t.Fatal("no test key produced a '+'")
	}
}
