package vectorgen

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"sort"
	"testing"

	"github.com/cockyapple/cairn/ledger"
)

// Tamper suite: take a known-good log and checkpoint, damage the encoded bytes
// in every way we can think of, and require that an outside verifier notices.
// "Notices" means VerifyLog (or a decoder) returns an error. The only accepted
// mutations allowed are ones the spec says are benign, and each is classified.

type tamperKit struct {
	chain [][]byte
	trust ledger.TrustConfig
	cp    []byte
}

func kit(t *testing.T, caseName string) tamperKit {
	t.Helper()
	f := Build()
	var k tamperKit
	for _, c := range f.Chains {
		if c.Name == "main_chain" {
			for _, h := range c.EntriesHex {
				k.chain = append(k.chain, mustHex(t, h))
			}
		}
	}
	for _, c := range f.Checkpoints {
		if c.Name == caseName {
			tr, err := ledger.DecodeTrustConfig(mustHex(t, c.TrustHex))
			if err != nil {
				t.Fatal(err)
			}
			k.trust = tr
			k.cp = mustHex(t, c.CheckpointHex)
		}
	}
	if len(k.chain) == 0 || k.cp == nil {
		t.Fatalf("missing vectors for %s", caseName)
	}
	return k
}

func clone(b [][]byte) [][]byte {
	out := make([][]byte, len(b))
	for i := range b {
		out[i] = append([]byte(nil), b[i]...)
	}
	return out
}

// verify returns "" when the log is accepted, else the stable error code.
func verify(chain [][]byte, cp []byte, trust ledger.TrustConfig) string {
	entries, err := ledger.DecodeChain(chain)
	if err != nil {
		return code(err)
	}
	sc, err := ledger.DecodeSignedCheckpoint(cp)
	if err != nil {
		return code(err)
	}
	if err := ledger.VerifyLog(entries, &sc, &trust); err != nil {
		return code(err)
	}
	return ""
}

func code(err error) string {
	if c := ledger.ErrCode(err); c != "" {
		return c
	}
	return "NON_LEDGER_ERROR:" + err.Error()
}

func TestTamperBaselineAccepted(t *testing.T) {
	k := kit(t, "quorum_3_of_4_full_log")
	if c := verify(k.chain, k.cp, k.trust); c != "" {
		t.Fatalf("baseline must verify, got %s", c)
	}
}

// Every single-bit flip of every byte of the chain and of the checkpoint.
func TestTamperExhaustiveBitFlips(t *testing.T) {
	k := kit(t, "quorum_3_of_4_full_log")
	tally := map[string]int{}
	total := 0
	for i := range k.chain {
		for by := range k.chain[i] {
			for bit := 0; bit < 8; bit++ {
				m := clone(k.chain)
				m[i][by] ^= 1 << bit
				c := verify(m, k.cp, k.trust)
				total++
				tally[c]++
				if c == "" {
					t.Errorf("ACCEPTED: chain entry %d byte %d bit %d", i, by, bit)
				}
			}
		}
	}
	chainTotal := total
	for by := range k.cp {
		for bit := 0; bit < 8; bit++ {
			cp := append([]byte(nil), k.cp...)
			cp[by] ^= 1 << bit
			c := verify(k.chain, cp, k.trust)
			total++
			tally[c]++
			if c == "" {
				t.Errorf("ACCEPTED: checkpoint byte %d bit %d", by, bit)
			}
		}
	}
	t.Logf("exhaustive single-bit flips: %d total (%d chain, %d checkpoint), 0 must be accepted", total, chainTotal, total-chainTotal)
	report(t, tally)
}

// Seeded random damage: multi-bit flips, byte overwrites, truncation and
// extension of a randomly chosen entry or the checkpoint.
func TestTamperSeededRandom(t *testing.T) {
	const n = 1000
	k := kit(t, "quorum_3_of_4_full_log")
	rng := rand.New(rand.NewPCG(0xC41124, 2026))
	tally := map[string]int{}
	accepted, changed := 0, 0
	for i := 0; i < n; i++ {
		chain := clone(k.chain)
		cp := append([]byte(nil), k.cp...)
		target := rng.IntN(len(chain) + 1) // last slot = checkpoint
		buf := &cp
		if target < len(chain) {
			buf = &chain[target]
		}
		b := *buf
		switch rng.IntN(5) {
		case 0: // 2..8 random bit flips
			for j, m := 0, 2+rng.IntN(7); j < m; j++ {
				b[rng.IntN(len(b))] ^= 1 << rng.IntN(8)
			}
		case 1: // overwrite a run with random bytes
			s := rng.IntN(len(b))
			for j := s; j < len(b) && j < s+1+rng.IntN(16); j++ {
				b[j] = byte(rng.IntN(256))
			}
		case 2: // truncate
			b = b[:rng.IntN(len(b))]
		case 3: // extend with junk
			for j, m := 0, 1+rng.IntN(32); j < m; j++ {
				b = append(b, byte(rng.IntN(256)))
			}
		case 4: // zero a run
			s := rng.IntN(len(b))
			for j := s; j < len(b) && j < s+1+rng.IntN(32); j++ {
				b[j] = 0
			}
		}
		*buf = b
		if bytes.Equal(b, k.cp) && target == len(chain) || target < len(chain) && bytes.Equal(b, k.chain[target]) {
			continue // random overwrite happened to be a no-op; not a mutation
		}
		changed++
		c := verify(chain, cp, k.trust)
		tally[c]++
		if c == "" {
			accepted++
			t.Errorf("ACCEPTED random mutation %d (target %d)", i, target)
		}
	}
	t.Logf("seeded random mutations: %d drawn, %d changed bytes, %d accepted", n, changed, accepted)
	report(t, tally)
}

// Structural attacks on the list of entries.
func TestTamperStructural(t *testing.T) {
	k := kit(t, "quorum_3_of_4_full_log")
	n := len(k.chain)
	type attack struct {
		name string
		mk   func() [][]byte
	}
	var attacks []attack
	for i := 0; i < n; i++ {
		i := i
		attacks = append(attacks, attack{fmt.Sprintf("delete_entry_%d", i), func() [][]byte {
			c := clone(k.chain)
			return append(c[:i], c[i+1:]...)
		}})
		attacks = append(attacks, attack{fmt.Sprintf("duplicate_entry_%d", i), func() [][]byte {
			c := clone(k.chain)
			out := append([][]byte{}, c[:i+1]...)
			out = append(out, c[i])
			return append(out, c[i+1:]...)
		}})
		if i+1 < n {
			attacks = append(attacks, attack{fmt.Sprintf("swap_%d_%d", i, i+1), func() [][]byte {
				c := clone(k.chain)
				c[i], c[i+1] = c[i+1], c[i]
				return c
			}})
		}
		for j := 0; j < n; j++ {
			if j == i {
				continue
			}
			i, j := i, j
			attacks = append(attacks, attack{fmt.Sprintf("replace_%d_with_%d", i, j), func() [][]byte {
				c := clone(k.chain)
				c[i] = append([]byte(nil), c[j]...)
				return c
			}})
		}
	}
	attacks = append(attacks, attack{"empty_chain", func() [][]byte { return nil }})
	for cut := 1; cut < n; cut++ {
		cut := cut
		attacks = append(attacks, attack{fmt.Sprintf("truncate_tail_to_%d_entries", cut), func() [][]byte {
			return clone(k.chain)[:cut]
		}})
		attacks = append(attacks, attack{fmt.Sprintf("drop_head_%d_entries", cut), func() [][]byte {
			return clone(k.chain)[cut:]
		}})
	}
	tally := map[string]int{}
	var chainOnly []string
	for _, a := range attacks {
		m := a.mk()
		c := verify(m, k.cp, k.trust)
		tally[c]++
		if c == "" {
			t.Errorf("ACCEPTED structural attack %s", a.name)
		}
		// Does the chain alone (no checkpoint) notice?
		if _, err := ledger.DecodeChain(m); err == nil {
			chainOnly = append(chainOnly, a.name)
		}
	}
	t.Logf("structural attacks: %d run", len(attacks))
	report(t, tally)
	t.Logf("attacks the CHAIN ALONE does not catch (only the checkpoint does): %d", len(chainOnly))
	for _, s := range chainOnly {
		t.Logf("   chain-only pass: %s", s)
	}
}

// Extra validly-signed entry appended after the checkpoint was cut.
func TestTamperAppendAfterCheckpoint(t *testing.T) {
	k := kit(t, "quorum_3_of_4_full_log")
	b := newBuilder()
	entries, err := ledger.DecodeChain(k.chain)
	if err != nil {
		t.Fatal(err)
	}
	last := entries[len(entries)-1]
	extra := b.entry(last.Height+1, last.Hash(), ledger.KindAction, []byte("extra"), "a1")
	chain := append(clone(k.chain), extra.Encode())
	if _, err := ledger.DecodeChain(chain); err != nil {
		t.Fatalf("a correctly signed extension is a valid chain by itself: %v", err)
	}
	if c := verify(chain, k.cp, k.trust); c != ledger.CodeSizeMismatch {
		t.Fatalf("checkpoint must not vouch for the extension, got %q", c)
	}
}

// With surplus signatures the checkpoint is still canonical (ADR-12): every
// single-bit flip anywhere in the encoding must be rejected, including flips
// that turn a signer into a stranger or break the key ordering.
func TestTamperSurplusSignersAllRejected(t *testing.T) {
	k := kit(t, "all_4_validators_prefix_of_4_entries")
	k.chain = k.chain[:4]
	if c := verify(k.chain, k.cp, k.trust); c != "" {
		t.Fatalf("baseline: %s", c)
	}
	sc, _ := ledger.DecodeSignedCheckpoint(k.cp)
	tally := map[string]int{}
	total := 0
	for by := range k.cp {
		for bit := 0; bit < 8; bit++ {
			cp := append([]byte(nil), k.cp...)
			cp[by] ^= 1 << bit
			c := verify(k.chain, cp, k.trust)
			total++
			tally[c]++
			if c == "" {
				t.Errorf("ACCEPTED single-bit flip at byte %d bit %d", by, bit)
			}
		}
	}
	t.Logf("surplus-signer checkpoint (%d sigs, exactly-quorum would be 5): %d single-bit flips", len(sc.Sigs), total)
	report(t, tally)
}

func report(t *testing.T, tally map[string]int) {
	keys := make([]string, 0, len(tally))
	for s := range tally {
		keys = append(keys, s)
	}
	sort.Strings(keys)
	for _, s := range keys {
		name := s
		if name == "" {
			name = "(ACCEPTED)"
		}
		t.Logf("   %-28s %6d", name, tally[s])
	}
}
