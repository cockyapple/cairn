package vectorgen

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"unicode/utf8"

	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
)

// rawUse parses a use blob with offsets written out by hand and nothing from the
// repository, so the format in SPEC 10.4.1 can be implemented from the vectors alone.
const (
	rawMaxField   = 16 << 20 // SPEC 10.4.1: no string or bytes field is longer than 16 MiB
	rawKindAction = 4        // the ACTION entry kind byte
)

func rawUse(b []byte) (v int, host string, cost uint64, tail []byte, ok bool) {
	if len(b) < 1 || (b[0] != 1 && b[0] != 2) {
		return
	}
	v = int(b[0])
	if len(b) < 5 {
		return
	}
	n := uint64(binary.BigEndian.Uint32(b[1:5]))
	if n > rawMaxField || uint64(len(b)) < 5+n+8 {
		return
	}
	host = string(b[5 : 5+n])
	if !utf8.ValidString(host) {
		return
	}
	cost = binary.BigEndian.Uint64(b[5+n : 13+n])
	rest := b[13+n:]
	switch v {
	case 2:
		if len(rest) != 32 {
			return
		}
		tail = rest
	case 1:
		if len(rest) < 4 {
			return
		}
		an := uint64(binary.BigEndian.Uint32(rest[:4]))
		if an > rawMaxField || an != uint64(len(rest)-4) {
			return
		}
		tail = rest[4:]
	}
	return v, host, cost, tail, true
}

func TestUseBlobVectors(t *testing.T) {
	var valid, invalid int
	for _, u := range load(t).UseBlobs {
		raw := mustHex(t, u.Hex)
		got, err := governance.DecodeUse(raw)
		v, host, cost, tail, ok := rawUse(raw)
		if ok != u.Valid || (err == nil) != u.Valid {
			t.Errorf("%s: valid=%v but raw=%v decoder err=%v", u.Name, u.Valid, ok, err)
			continue
		}
		if !u.Valid {
			invalid++
			continue
		}
		valid++
		if u.Version == nil || u.Host == nil || u.Cost == nil {
			t.Errorf("%s: a valid vector must state version, host and cost", u.Name)
			continue
		}
		if v != *u.Version || host != *u.Host || cost != *u.Cost || got.Host != *u.Host || got.Cost != *u.Cost {
			t.Errorf("%s: fields differ", u.Name)
		}
		if *u.Version == 2 {
			if u.CommitHex == nil || u.ArgsHex != nil {
				t.Errorf("%s: a version 2 vector states the commitment and no args", u.Name)
			} else if hex.EncodeToString(tail) != *u.CommitHex || got.Commit == nil || hex.EncodeToString(got.Commit[:]) != *u.CommitHex {
				t.Errorf("%s: commitment differs", u.Name)
			}
		} else if u.ArgsHex == nil || u.CommitHex != nil {
			t.Errorf("%s: a version 1 vector states the args and no commitment", u.Name)
		} else if hex.EncodeToString(tail) != *u.ArgsHex || got.Commit != nil || hex.EncodeToString(got.Args) != *u.ArgsHex {
			t.Errorf("%s: args differ", u.Name)
		}
		if !bytes.Equal(got.Encode(), raw) {
			t.Errorf("%s: decode then encode is not the identity", u.Name)
		}
	}
	if valid < 8 || invalid < 5 {
		t.Fatalf("too few cases: %d valid, %d invalid", valid, invalid)
	}
}

func TestOpeningVectors(t *testing.T) {
	var valid, invalid int
	for _, o := range load(t).Openings {
		raw := mustHex(t, o.OpeningHex)
		sum := sha256.Sum256(raw)
		want := len(raw) >= 32 && hex.EncodeToString(sum[:]) == o.Commitment
		if want != o.Valid {
			t.Errorf("%s: raw check says %v, vector says %v", o.Name, want, o.Valid)
		}
		var c ledger.Hash
		copy(c[:], mustHex(t, o.Commitment))
		payload, err := governance.CheckOpening(c, raw)
		if (err == nil) != o.Valid {
			t.Errorf("%s: CheckOpening err=%v, valid=%v", o.Name, err, o.Valid)
		}
		if o.Valid {
			valid++
			if o.PayloadHex == nil {
				t.Errorf("%s: a valid opening must state its payload", o.Name)
			} else if hex.EncodeToString(payload) != *o.PayloadHex || !bytes.Equal(payload, raw[32:]) {
				t.Errorf("%s: payload differs", o.Name)
			}
		} else {
			invalid++
		}
	}
	if valid < 4 || invalid < 5 {
		t.Fatalf("too few cases: %d valid, %d invalid", valid, invalid)
	}
}

// rawLocate is Locate again from raw bytes: a payload of an ACTION entry is
// u32 len | type | args(32) | result(32) | prev(32).
func rawLocate(t *testing.T, entries [][]byte, blobs map[string][]byte, commit string) []LocationVec {
	t.Helper()
	out := []LocationVec{}
	for _, raw := range entries {
		if len(raw) < 74 {
			t.Errorf("entry of %d bytes is too short to hold a payload hash", len(raw))
			continue
		}
		if raw[1+8+32] != rawKindAction {
			continue
		}
		height := binary.BigEndian.Uint64(raw[1:9])
		payloadHash := hex.EncodeToString(raw[42:74])
		pb, ok := blobs[payloadHash]
		if !ok || len(pb) < 4 {
			continue
		}
		n := uint64(binary.BigEndian.Uint32(pb[:4]))
		if uint64(len(pb)) != 4+n+96 {
			continue
		}
		args := hex.EncodeToString(pb[4+n : 36+n])
		result := hex.EncodeToString(pb[36+n : 68+n])
		if args == commit {
			out = append(out, LocationVec{height, "args"})
		}
		if ub, ok := blobs[args]; ok {
			if v, _, _, tail, ok := rawUse(ub); ok && v == 2 && hex.EncodeToString(tail) == commit {
				out = append(out, LocationVec{height, "use"})
			}
		}
		if result == commit {
			out = append(out, LocationVec{height, "result"})
		}
	}
	return out
}

func TestLocateVectors(t *testing.T) {
	for _, c := range load(t).Locate {
		encoded := make([][]byte, len(c.EntriesHex))
		for i, h := range c.EntriesHex {
			encoded[i] = mustHex(t, h)
		}
		entries, err := ledger.DecodeChain(encoded)
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		blobs := map[ledger.Hash][]byte{}
		rawBlobs := map[string][]byte{}
		for _, b := range c.Blobs {
			body := mustHex(t, b.Hex)
			sum := sha256.Sum256(body)
			if hex.EncodeToString(sum[:]) != b.Hash {
				t.Errorf("%s: blob %s is filed under the wrong hash", c.Name, b.Hash)
			}
			blobs[sum] = body
			rawBlobs[b.Hash] = body
		}
		var commit ledger.Hash
		copy(commit[:], mustHex(t, c.Commitment))
		var got []LocationVec
		for _, l := range governance.Locate(entries, blobs, commit) {
			got = append(got, LocationVec{l.Height, l.Field})
		}
		want := fmt.Sprint(c.Locations)
		if fmt.Sprint(got) != want && !(len(got) == 0 && len(c.Locations) == 0) {
			t.Errorf("%s: Locate gave %v, vector says %v", c.Name, got, c.Locations)
		}
		if raw := rawLocate(t, encoded, rawBlobs, c.Commitment); fmt.Sprint(raw) != want {
			t.Errorf("%s: raw locate gave %v, vector says %v", c.Name, raw, c.Locations)
		}
	}
}
