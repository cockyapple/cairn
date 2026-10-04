package governance

import (
	"bytes"
	"testing"
)

func TestOpeningRejectsTampering(t *testing.T) {
	o, c, err := NewOpening([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	if p, err := CheckOpening(c, o); err != nil || string(p) != "payload" {
		t.Fatalf("%q %v", p, err)
	}
	bad := append([]byte(nil), o...)
	bad[len(bad)-1] ^= 1
	for name, b := range map[string][]byte{"altered": bad, "short": o[:10], "empty": nil, "salt only": o[:SaltSize]} {
		if _, err := CheckOpening(c, b); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	o2, c2, _ := NewOpening([]byte("payload"))
	if bytes.Equal(o, o2) || c == c2 {
		t.Fatal("two openings of one payload are identical")
	}
	if _, err := CheckOpening(c2, o); err == nil {
		t.Fatal("an opening was accepted for another commitment")
	}
}
