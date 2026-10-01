package eval

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

// score gives 10000 per occurrence of "good" in the artifact, capped, so the
// outcome depends on the artifact and the case.
func scorer(artifact []byte, c Case) (int, error) {
	n := bytes.Count(artifact, []byte(string(c.Input)))
	if n > 1 {
		n = 1
	}
	return n * MaxScore, nil
}

func suite() []Case {
	return []Case{{"b-refund", []byte("refund")}, {"a-greet", []byte("hello")}, {"c-refuse", []byte("never")}}
}

func TestRunIsDeterministicAndOrdered(t *testing.T) {
	base := []byte("hello refund")
	cand := []byte("hello refund never")
	r1, err := Run("support-v1", suite(), base, cand, scorer)
	if err != nil {
		t.Fatal(err)
	}
	rev := []Case{suite()[2], suite()[1], suite()[0]}
	r2, _ := Run("support-v1", rev, base, cand, scorer)
	if r1.Hash() != r2.Hash() {
		t.Fatal("result hash depends on the order the suite was written in")
	}
	if r1.Cases[0].Name != "a-greet" || r1.Cases[2].Name != "c-refuse" {
		t.Fatalf("cases not sorted: %+v", r1.Cases)
	}
	s := r1.Summary()
	if s.BaselineMean != 6666 || s.CandidateMean != 10000 || s.Delta != 3334 || len(s.Regressions) != 0 {
		t.Fatalf("summary %+v", s)
	}
}

func TestRoundTripAndTamper(t *testing.T) {
	r, _ := Run("s", suite(), []byte("hello"), []byte("hello refund"), scorer)
	enc := r.Encode()
	back, err := Decode(enc)
	if err != nil || back.Hash() != r.Hash() {
		t.Fatalf("round trip: %v", err)
	}
	for i := range enc {
		for _, bit := range []byte{1, 0x80} {
			m := append([]byte(nil), enc...)
			m[i] ^= bit
			d, err := Decode(m)
			if err == nil && d.Hash() == r.Hash() {
				t.Fatalf("flip at %d decodes to the same hash", i)
			}
		}
	}
	if _, err := Decode(append(enc, 0)); err == nil {
		t.Fatal("trailing byte accepted")
	}
	if _, err := Decode(enc[:len(enc)-1]); err == nil {
		t.Fatal("short input accepted")
	}
}

func TestDecodeRejectsNonCanonical(t *testing.T) {
	r := &Result{Suite: "s", Cases: []CaseScore{{"b", 1, 1}, {"a", 1, 1}}}
	if _, err := Decode(r.Encode()); !errors.Is(err, ErrBadResult) {
		t.Fatalf("unsorted cases accepted: %v", err)
	}
	r = &Result{Suite: "s", Cases: []CaseScore{{"a", 1, 1}, {"a", 1, 1}}}
	if _, err := Decode(r.Encode()); !errors.Is(err, ErrBadResult) {
		t.Fatalf("repeated case accepted: %v", err)
	}
	r = &Result{Suite: "s", Cases: []CaseScore{{"a", MaxScore + 1, 1}}}
	if _, err := Decode(r.Encode()); !errors.Is(err, ErrBadScore) {
		t.Fatalf("out-of-range score accepted: %v", err)
	}
	if _, err := Decode(nil); err == nil {
		t.Fatal("empty input accepted")
	}
}

func TestRunRejectsBadInput(t *testing.T) {
	ok := func(a []byte, c Case) (int, error) { return 1, nil }
	if _, err := Run("", suite(), nil, nil, ok); err == nil {
		t.Fatal("empty suite name accepted")
	}
	if _, err := Run("s", nil, nil, nil, ok); err == nil {
		t.Fatal("no cases accepted")
	}
	if _, err := Run("s", []Case{{"x", nil}, {"x", nil}}, nil, nil, ok); err == nil {
		t.Fatal("repeated case name accepted")
	}
	if _, err := Run("s", []Case{{strings.Repeat("n", 257), nil}}, nil, nil, ok); err == nil {
		t.Fatal("long case name accepted")
	}
	bad := func(a []byte, c Case) (int, error) { return MaxScore + 1, nil }
	if _, err := Run("s", suite(), nil, nil, bad); !errors.Is(err, ErrBadScore) {
		t.Fatalf("bad score: %v", err)
	}
	boom := func(a []byte, c Case) (int, error) { return 0, errors.New("boom") }
	if _, err := Run("s", suite(), nil, nil, boom); err == nil {
		t.Fatal("scorer error swallowed")
	}
}

func TestSummaryListsRegressions(t *testing.T) {
	r, _ := Run("s", suite(), []byte("hello refund never"), []byte("hello"), scorer)
	s := r.Summary()
	if len(s.Regressions) != 2 || s.Delta >= 0 {
		t.Fatalf("summary %+v", s)
	}
}
