package vectorgen

import (
	"crypto/sha256"

	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
)

// UseVec is one use blob (SPEC 10.4.1) and what a decoder must make of it.
type UseVec struct {
	Name  string `json:"name"`
	Hex   string `json:"hex"`
	Valid bool   `json:"valid"`
	// For a valid blob Version, Host and Cost are always present, even when the
	// value is "" or 0, and so is ArgsHex (version 1) or CommitHex (version 2). An
	// invalid blob carries none of them.
	Version   *int    `json:"version,omitempty"`
	Host      *string `json:"host,omitempty"`
	Cost      *uint64 `json:"cost,omitempty"`
	ArgsHex   *string `json:"args_hex,omitempty"`
	CommitHex *string `json:"commit,omitempty"`
}

// OpeningVec is a candidate opening and the commitment it is checked against.
type OpeningVec struct {
	Name       string `json:"name"`
	OpeningHex string `json:"opening_hex"`
	Commitment string `json:"commitment"`
	Valid      bool   `json:"valid"`
	PayloadHex *string `json:"payload_hex,omitempty"` // present, possibly "", when Valid
}

type BlobVec struct {
	Hash string `json:"hash"`
	Hex  string `json:"hex"`
}

type LocationVec struct {
	Height uint64 `json:"height"`
	Field  string `json:"field"`
}

// LocateCase asks where a commitment sits on a log, given the blobs a verifier holds.
type LocateCase struct {
	Name       string        `json:"name"`
	EntriesHex []string      `json:"entries_hex"`
	Blobs      []BlobVec     `json:"blobs"`
	Commitment string        `json:"commitment"`
	Locations  []LocationVec `json:"locations"`
}

func (b *builder) useVectors() []UseVec {
	c1, c2 := h("args commitment one"), h("args commitment two")
	valid := []struct {
		name string
		u    governance.Use
	}{
		{"v1_with_args", governance.Use{Host: "api.example.com", Cost: 5, Args: []byte("GET /feed.xml")}},
		{"v1_no_host_no_args", governance.Use{}},
		{"v2_committed", governance.Use{Host: "api.example.com", Cost: 5, Commit: &c1}},
		{"v2_no_host_zero_cost", governance.Use{Commit: &c2}},
		{"v2_max_cost", governance.Use{Host: "h", Cost: ^uint64(0), Commit: &c1}},
		{"v1_binary_args", governance.Use{Host: "api.example.com", Cost: 1, Args: []byte{0x00, 0xff, 0x80, 0x41}}},
		{"v1_multibyte_host", governance.Use{Host: "例.example", Cost: 7, Args: []byte("x")}},
		{"v2_multibyte_host", governance.Use{Host: "例.example", Cost: 7, Commit: &c2}},
	}
	var out []UseVec
	for _, v := range valid {
		enc := v.u.Encode()
		ver, host, cost := int(enc[0]), v.u.Host, v.u.Cost
		vec := UseVec{Name: v.name, Hex: hx(enc), Valid: true, Version: &ver, Host: &host, Cost: &cost}
		if v.u.Commit != nil {
			s := hx(v.u.Commit[:])
			vec.CommitHex = &s
		} else {
			s := hx(v.u.Args)
			vec.ArgsHex = &s
		}
		out = append(out, vec)
	}
	v1 := governance.Use{Host: "api.example.com", Cost: 5, Args: []byte("x")}.Encode()
	v2 := governance.Use{Host: "api.example.com", Cost: 5, Commit: &c1}.Encode()
	bad := func(name string, raw []byte) { out = append(out, UseVec{Name: name, Hex: hx(raw)}) }
	bad("empty", nil)
	bad("version_0", append([]byte{0}, v1[1:]...))
	bad("version_3", append([]byte{3}, v2[1:]...))
	bad("v1_truncated", v1[:len(v1)-1])
	bad("v1_trailing_byte", append(append([]byte(nil), v1...), 0))
	bad("v2_truncated_commitment", v2[:len(v2)-1])
	bad("v2_trailing_byte", append(append([]byte(nil), v2...), 0))
	bad("v2_with_v1_args_length", append(append([]byte(nil), v2[:len(v2)-32]...), 0, 0, 0, 1, 7))
	bad("host_not_utf8", append([]byte{2, 0, 0, 0, 1, 0xff}, v2[5+len("api.example.com"):]...))
	bad("host_length_overruns", append([]byte{2, 0xff, 0xff, 0xff, 0xff}, v2[5:]...))
	// A field longer than 16 MiB is refused whatever follows. These two vectors are
	// short, so a reader that has no limit also refuses them, as truncated: telling
	// the two rules apart would take a 16 MiB blob, which the file does not carry.
	over := []byte{0x01, 0x00, 0x00, 0x01}
	bad("host_length_just_over_16mib", append([]byte{2}, over...))
	bad("v1_args_length_just_over_16mib", append(append([]byte{1, 0, 0, 0, 0}, make([]byte, 8)...), over...))
	return out
}

// opening builds salt | payload with a salt derived from a public string, so the
// vectors are reproducible. Real openings use random salts.
func opening(name string, payload []byte) []byte {
	salt := sha256.Sum256([]byte("cairn-test-salt-" + name))
	return append(salt[:], payload...)
}

func (b *builder) openingVectors() []OpeningVec {
	var out []OpeningVec
	good := func(name string, payload []byte) {
		o := opening(name, payload)
		c := ledger.BlobHash(o)
		p := hx(payload)
		out = append(out, OpeningVec{Name: name, OpeningHex: hx(o), Commitment: hx(c[:]), Valid: true, PayloadHex: &p})
	}
	good("args", []byte("web_fetch https://example.com/feed.xml"))
	good("empty_payload", nil)
	good("result", []byte("200 OK 4096 bytes"))
	good("binary_payload", []byte{0x00, 0xff, 0x80, 0x41})

	o := opening("args", []byte("web_fetch https://example.com/feed.xml"))
	c := ledger.BlobHash(o)
	badCase := func(name string, op []byte, commit ledger.Hash) {
		out = append(out, OpeningVec{Name: name, OpeningHex: hx(op), Commitment: hx(commit[:])})
	}
	flipped := append([]byte(nil), o...)
	flipped[len(flipped)-1] ^= 1
	badCase("payload_altered", flipped, c)
	badCase("opening_of_another_commitment", opening("result", []byte("200 OK 4096 bytes")), c)
	badCase("same_payload_other_salt", opening("other-salt", []byte("web_fetch https://example.com/feed.xml")), c)
	short := o[:governance.SaltSize-1]
	badCase("shorter_than_salt", short, ledger.BlobHash(short))
	badCase("empty", nil, ledger.BlobHash(nil))
	return out
}

func (b *builder) locateCases() []LocateCase {
	argsA := opening("loc-args", []byte("args of an unbound agent's call"))
	resA := opening("loc-result", []byte("result of that call"))
	argsB := opening("loc-bound", []byte("args of a bound agent's call"))
	resB := opening("loc-bound-result", []byte("result of the bound call"))
	same := opening("loc-same", []byte("a payload that is both the args and the result"))
	sameUse := opening("loc-same-use", []byte("args whose commitment is also the result"))
	cA, cRA := ledger.BlobHash(argsA), ledger.BlobHash(resA)
	cB, cRB := ledger.BlobHash(argsB), ledger.BlobHash(resB)
	cS, cU := ledger.BlobHash(same), ledger.BlobHash(sameUse)

	genesis := &ledger.Genesis{SpecVersion: ledger.SpecVersion,
		ConstitutionHash: h("cairn-test-constitution"), Trust: b.trust(0, "v1", "v2", "v3", "v4")}
	use := governance.Use{Host: "api.example.com", Cost: 5, Commit: &cB}.Encode()
	useHash := ledger.BlobHash(use)
	use2 := governance.Use{Host: "api.example.com", Cost: 1, Commit: &cU}.Encode()
	use2Hash := ledger.BlobHash(use2)

	actions := []ledger.Action{
		{ActionType: "tool_call", ArgsHash: cA},
		{ActionType: "tool_call", ArgsHash: cA, ResultHash: cRA},
		{ActionType: "tool_call", ArgsHash: useHash},
		{ActionType: "tool_call", ArgsHash: useHash, ResultHash: cRB},
		{ActionType: "tool_call", ArgsHash: cS, ResultHash: cS},
		{ActionType: "tool_call", ArgsHash: use2Hash, ResultHash: cU},
	}
	var chain []ledger.Entry
	blobs := map[ledger.Hash][]byte{}
	add := func(kind ledger.Kind, payload []byte, signer string) {
		var prev ledger.Hash
		if n := len(chain); n > 0 {
			prev = chain[n-1].Hash()
		}
		e := b.entry(uint64(len(chain)), prev, kind, payload, signer)
		chain = append(chain, e)
		blobs[e.PayloadHash] = payload
	}
	add(ledger.KindGenesis, genesis.Encode(), "founder")
	for i := range actions {
		add(ledger.KindAction, actions[i].Encode(), "a1")
	}
	blobs[useHash] = use
	blobs[use2Hash] = use2

	mk := func(name string, commit ledger.Hash, held map[ledger.Hash][]byte, locs ...LocationVec) LocateCase {
		c := LocateCase{Name: name, EntriesHex: hashes(chain), Commitment: hx(commit[:]), Locations: locs}
		if c.Locations == nil {
			c.Locations = []LocationVec{}
		}
		keys := make([]ledger.Hash, 0, len(held))
		for k := range held {
			keys = append(keys, k)
		}
		sortHashes(keys)
		for _, k := range keys {
			c.Blobs = append(c.Blobs, BlobVec{Hash: hx(k[:]), Hex: hx(held[k])})
		}
		return c
	}
	without := map[ledger.Hash][]byte{}
	for k, v := range blobs {
		if k != useHash {
			without[k] = v
		}
	}
	noPayload := map[ledger.Hash][]byte{}
	for k, v := range blobs {
		if k != chain[1].PayloadHash {
			noPayload[k] = v
		}
	}
	return []LocateCase{
		mk("unbound_args_commitment", cA, blobs, LocationVec{1, "args"}, LocationVec{2, "args"}),
		mk("unbound_result_commitment", cRA, blobs, LocationVec{2, "result"}),
		mk("bound_args_commitment_inside_use_blob", cB, blobs, LocationVec{3, "use"}, LocationVec{4, "use"}),
		mk("bound_result_commitment", cRB, blobs, LocationVec{4, "result"}),
		mk("commitment_nobody_made", h("no such commitment"), blobs),
		mk("use_blob_withheld_hides_the_args_commitment", cB, without),
		mk("use_blob_hash_is_an_args_location_not_a_use_location", useHash, blobs, LocationVec{3, "args"}, LocationVec{4, "args"}),
		mk("one_commitment_as_args_and_result_of_one_action", cS, blobs, LocationVec{5, "args"}, LocationVec{5, "result"}),
		mk("one_commitment_in_use_blob_and_result_of_one_action", cU, blobs, LocationVec{6, "use"}, LocationVec{6, "result"}),
		mk("action_payload_withheld_skips_that_entry", cA, noPayload, LocationVec{2, "args"}),
	}
}

func sortHashes(hs []ledger.Hash) {
	for i := 1; i < len(hs); i++ {
		for j := i; j > 0 && string(hs[j][:]) < string(hs[j-1][:]); j-- {
			hs[j], hs[j-1] = hs[j-1], hs[j]
		}
	}
}
