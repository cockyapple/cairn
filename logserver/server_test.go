package logserver_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
	"github.com/cockyapple/cairn/logserver"
	"github.com/cockyapple/cairn/review"
)

func key(name string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("cairn-logserver-test-" + name))
	return ed25519.NewKeyFromSeed(s[:])
}

func pub(p ed25519.PrivateKey) (o [32]byte) { copy(o[:], p.Public().(ed25519.PublicKey)); return }

type fx struct {
	t                               *testing.T
	dir                             string
	srv                             *logserver.Server
	ts                              *httptest.Server
	l                               *review.Log
	val, wit, r1, r2, r3, sec, prop ed25519.PrivateKey
	trust                           ledger.TrustConfig
	mu                              sync.Mutex
	now                             time.Time
	cfg                             logserver.Config
	sent                            int
}

func (f *fx) clock() time.Time        { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
func (f *fx) advance(d time.Duration) { f.mu.Lock(); f.now = f.now.Add(d); f.mu.Unlock() }

func newFx(t *testing.T, mod func(*logserver.Config)) *fx {
	t.Helper()
	f := &fx{t: t, dir: t.TempDir(), now: time.Unix(2_000_000, 0),
		val: key("val"), wit: key("wit"), r1: key("r1"), r2: key("r2"), r3: key("r3"), sec: key("sec"), prop: key("prop")}
	f.trust = ledger.TrustConfig{WitnessThreshold: 1, Keys: []ledger.Key{
		{Role: ledger.RoleValidator, Public: pub(f.val)}, {Role: ledger.RoleWitness, Public: pub(f.wit)},
		{Role: ledger.RoleReviewer, Public: pub(f.r1)}, {Role: ledger.RoleReviewer, Public: pub(f.r2)},
		{Role: ledger.RoleReviewer, Public: pub(f.r3)}, {Role: ledger.RoleSecurityReviewer, Public: pub(f.sec)},
		{Role: ledger.RoleProposer, Public: pub(f.prop)},
	}}
	clk := uint64(1_000_000)
	l, err := review.New(f.val, ledger.BlobHash([]byte("c")), f.trust, func() uint64 { clk++; return clk })
	if err != nil {
		t.Fatal(err)
	}
	f.l = l
	f.cfg = logserver.Config{Dir: f.dir, GenesisAuthor: pub(f.val), Now: f.clock}
	if mod != nil {
		mod(&f.cfg)
	}
	f.open()
	return f
}

func (f *fx) open() {
	f.t.Helper()
	srv, err := logserver.Open(f.cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	f.srv = srv
	f.ts = httptest.NewServer(srv.Handler())
	f.t.Cleanup(func() { f.ts.Close(); srv.Close() })
}

func (f *fx) reopen() {
	f.ts.Close()
	f.srv.Close()
	f.open()
}

type resp struct {
	Status int
	Body   []byte
	Header http.Header
}

func (r resp) code() string {
	var m map[string]string
	json.Unmarshal(r.Body, &m)
	return m["error"]
}

func (f *fx) do(method, path string, body []byte) resp {
	f.t.Helper()
	req, _ := http.NewRequest(method, f.ts.URL+path, bytes.NewReader(body))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, b, res.Header}
}

func (f *fx) payloadOf(e ledger.Entry) []byte { return f.l.Blobs[e.PayloadHash] }

func (f *fx) submit(e ledger.Entry) resp {
	f.t.Helper()
	return f.do("POST", "/v1/append", logserver.EncodeAppend(e, f.payloadOf(e)))
}

// sendAll submits entries of the authoring log from index from onwards.
func (f *fx) sendAll(from int) {
	f.t.Helper()
	for _, e := range f.l.Entries[from:] {
		if r := f.submit(e); r.Status != 201 {
			f.t.Fatalf("entry %d: %d %s", e.Height, r.Status, r.Body)
		}
	}
}

func (f *fx) propose(name string) ledger.Hash {
	f.t.Helper()
	p, err := f.l.Propose(f.prop, ledger.T2, "prompt/"+name, []byte("content "+name), []byte("why"), nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return p
}

func (f *fx) fullFlow() {
	f.t.Helper()
	p := f.propose("x")
	for _, k := range []ed25519.PrivateKey{f.r1, f.r2, f.sec} {
		if _, err := f.l.Vote(k, p, ledger.VerdictApprove, []byte("ok")); err != nil {
			f.t.Fatal(err)
		}
	}
	if _, err := f.l.Activate(f.val, p); err != nil {
		f.t.Fatal(err)
	}
	f.sendAll(0)
}

func hashes(b []byte) [][]byte {
	var out [][]byte
	for i := 0; i+32 <= len(b); i += 32 {
		out = append(out, b[i:i+32])
	}
	return out
}

func decode(t *testing.T, raw []byte) []ledger.Entry {
	t.Helper()
	if len(raw)%ledger.EntrySize != 0 {
		t.Fatalf("length %d is not a whole number of entries", len(raw))
	}
	var parts [][]byte
	for i := 0; i < len(raw); i += ledger.EntrySize {
		parts = append(parts, raw[i:i+ledger.EntrySize])
	}
	es, err := ledger.DecodeChain(parts)
	if err != nil {
		t.Fatal(err)
	}
	return es
}

func TestFullFlowServedAndVerifiable(t *testing.T) {
	f := newFx(t, nil)
	f.fullFlow()

	r := f.do("GET", "/v1/entries?start=0&limit=1000", nil)
	if r.Status != 200 || r.Header.Get("X-Cairn-Size") != strconv.Itoa(len(f.l.Entries)) {
		t.Fatalf("entries: %d %v", r.Status, r.Header)
	}
	got := decode(t, r.Body)
	if len(got) != len(f.l.Entries) {
		t.Fatalf("got %d entries want %d", len(got), len(f.l.Entries))
	}
	for i := range got {
		if got[i] != f.l.Entries[i] {
			t.Fatalf("entry %d differs", i)
		}
	}

	var st logserver.Status
	json.Unmarshal(f.do("GET", "/v1/status", nil).Body, &st)
	if st.Entries != len(got) || st.Root != hex.EncodeToString(func() []byte { r := ledger.LogRoot(got); return r[:] }()) {
		t.Fatalf("status %+v", st)
	}

	// Proofs verify against roots computed independently.
	n := len(got)
	leaves := make([][]byte, n)
	for i, e := range got {
		leaves[i] = e.Encode()
	}
	root := ledger.LogRoot(got)
	for i := 0; i < n; i++ {
		pr := f.do("GET", "/v1/proof/inclusion?index="+strconv.Itoa(i)+"&size="+strconv.Itoa(n), nil)
		if pr.Status != 200 {
			t.Fatalf("inclusion %d: %d %s", i, pr.Status, pr.Body)
		}
		var path []ledger.Hash
		for _, h := range hashes(pr.Body) {
			var x ledger.Hash
			copy(x[:], h)
			path = append(path, x)
		}
		if err := ledger.VerifyInclusion(leaves[i], uint64(i), uint64(n), path, root); err != nil {
			t.Fatalf("inclusion %d: %v", i, err)
		}
	}
	for m := 1; m < n; m++ {
		pr := f.do("GET", "/v1/proof/consistency?first="+strconv.Itoa(m)+"&second="+strconv.Itoa(n), nil)
		if pr.Status != 200 {
			t.Fatalf("consistency %d: %d %s", m, pr.Status, pr.Body)
		}
		var path []ledger.Hash
		for _, h := range hashes(pr.Body) {
			var x ledger.Hash
			copy(x[:], h)
			path = append(path, x)
		}
		if err := ledger.VerifyConsistency(uint64(m), uint64(n), ledger.LogRoot(got[:m]), root, path); err != nil {
			t.Fatalf("consistency %d: %v", m, err)
		}
	}

	// The storage directory is exactly what cairn-verify reads.
	raw, err := os.ReadFile(filepath.Join(f.dir, "entries.bin"))
	if err != nil {
		t.Fatal(err)
	}
	disk := decode(t, raw)
	blobs := governance.MapBlobs{}
	des, _ := os.ReadDir(filepath.Join(f.dir, "blobs"))
	for _, de := range des {
		b, _ := os.ReadFile(filepath.Join(f.dir, "blobs", de.Name()))
		blobs[ledger.BlobHash(b)] = b
		if hex.EncodeToString(func() []byte { h := ledger.BlobHash(b); return h[:] }()) != de.Name() {
			t.Fatalf("blob %s misnamed", de.Name())
		}
	}
	if _, err := governance.Replay(disk, blobs, governance.Options{}); err != nil {
		t.Fatalf("on-disk log does not replay: %v", err)
	}

	// A blob can be fetched back by hash.
	h := ledger.BlobHash([]byte("content x"))
	if b := f.do("GET", "/v1/blob/"+hex.EncodeToString(h[:]), nil); b.Status != 200 && b.Status != 404 {
		t.Fatalf("blob status %d", b.Status)
	}
	ph := f.l.Entries[1].PayloadHash
	if b := f.do("GET", "/v1/blob/"+hex.EncodeToString(ph[:]), nil); b.Status != 200 || ledger.BlobHash(b.Body) != ph {
		t.Fatalf("payload blob: %d", b.Status)
	}
	if b := f.do("GET", "/v1/blob/zz", nil); b.Status != 400 {
		t.Fatalf("bad blob name: %d", b.Status)
	}
	if b := f.do("GET", "/v1/blob/"+hex.EncodeToString(make([]byte, 32)), nil); b.Status != 404 {
		t.Fatalf("missing blob: %d", b.Status)
	}
}

func TestGenesisOnlyFromConfiguredAuthor(t *testing.T) {
	f := newFx(t, nil)
	// A stranger's perfectly valid genesis is refused.
	stranger := key("stranger")
	other, err := review.New(stranger, ledger.BlobHash([]byte("c")), ledger.TrustConfig{Keys: []ledger.Key{{Role: ledger.RoleValidator, Public: pub(stranger)}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	e := other.Entries[0]
	r := f.do("POST", "/v1/append", logserver.EncodeAppend(e, other.Blobs[e.PayloadHash]))
	if r.Status != 403 || r.code() != logserver.CodeNotGenesisAuth {
		t.Fatalf("stranger genesis: %d %s", r.Status, r.Body)
	}
	if f.srv.Status().Entries != 0 {
		t.Fatal("log changed")
	}
	if r := f.submit(f.l.Entries[0]); r.Status != 201 {
		t.Fatalf("real genesis: %d %s", r.Status, r.Body)
	}
}

func TestNoGenesisAuthorMeansUninitialised(t *testing.T) {
	f := newFx(t, func(c *logserver.Config) { c.GenesisAuthor = [32]byte{} })
	r := f.submit(f.l.Entries[0])
	if r.Status != 503 || r.code() != logserver.CodeUninitialised {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
}

func TestRejections(t *testing.T) {
	f := newFx(t, nil)
	f.sendAll(0)
	p := f.propose("y")
	e := f.l.Entries[len(f.l.Entries)-1]
	_ = p
	good := f.payloadOf(e)

	t.Run("height", func(t *testing.T) {
		// Resubmitting an already accepted entry conflicts.
		r := f.submit(f.l.Entries[0])
		if r.Status != 409 || r.code() != ledger.CodeBadHeight {
			t.Fatalf("%d %s", r.Status, r.Body)
		}
	})
	t.Run("prev hash", func(t *testing.T) {
		b := e
		b.PrevHash[0] ^= 1
		b.Sign(f.prop)
		r := f.do("POST", "/v1/append", logserver.EncodeAppend(b, good))
		if r.Status != 409 || r.code() != ledger.CodeBadPrevHash {
			t.Fatalf("%d %s", r.Status, r.Body)
		}
	})
	t.Run("bad signature", func(t *testing.T) {
		b := e
		b.Signature[3] ^= 1
		r := f.do("POST", "/v1/append", logserver.EncodeAppend(b, good))
		if r.Status != 400 || r.code() != ledger.CodeBadSignature {
			t.Fatalf("%d %s", r.Status, r.Body)
		}
	})
	t.Run("stranger", func(t *testing.T) {
		b := e
		b.Author = pub(key("stranger"))
		b.Sign(key("stranger"))
		r := f.do("POST", "/v1/append", logserver.EncodeAppend(b, good))
		if r.Status != 403 || r.code() != governance.CodeUnauthorizedAuthor {
			t.Fatalf("%d %s", r.Status, r.Body)
		}
	})
	t.Run("payload mismatch", func(t *testing.T) {
		r := f.do("POST", "/v1/append", logserver.EncodeAppend(e, []byte("something else")))
		if r.Status != 400 || r.code() != ledger.CodeBadPayload {
			t.Fatalf("%d %s", r.Status, r.Body)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		for _, body := range [][]byte{nil, []byte("x"), e.Encode(), append(e.Encode(), 0), append(logserver.EncodeAppend(e, good), 7)} {
			if r := f.do("POST", "/v1/append", body); r.Status != 400 {
				t.Fatalf("%d %s", r.Status, r.Body)
			}
		}
	})
	t.Run("oversized blob", func(t *testing.T) {
		big := make([]byte, 1<<20+1)
		r := f.do("POST", "/v1/append", logserver.EncodeAppend(e, good, big))
		if r.Status != 413 || r.code() != logserver.CodeBlobTooLarge {
			t.Fatalf("%d %s", r.Status, r.Body)
		}
	})
	t.Run("unchanged", func(t *testing.T) {
		if got := f.srv.Status().Entries; got != len(f.l.Entries)-1 {
			t.Fatalf("log has %d entries after rejections", got)
		}
	})
	t.Run("then accepted", func(t *testing.T) {
		if r := f.submit(e); r.Status != 201 {
			t.Fatalf("%d %s", r.Status, r.Body)
		}
	})
}

func TestGovernanceViolationLeavesLogAndDiskUnchanged(t *testing.T) {
	f := newFx(t, nil)
	f.sendAll(0)
	p := f.propose("z")
	f.sendAll(len(f.l.Entries) - 1)
	before, _ := os.ReadFile(filepath.Join(f.dir, "entries.bin"))
	nblobs := func() int { d, _ := os.ReadDir(filepath.Join(f.dir, "blobs")); return len(d) }
	bb := nblobs()

	// Build an ACTIVATE for a T2 proposal that has no votes, signed by the validator.
	act := ledger.Activate{ProposalHash: p}
	e := ledger.Entry{Height: uint64(len(f.l.Entries)), PrevHash: f.l.Entries[len(f.l.Entries)-1].Hash(), Kind: ledger.KindActivate,
		PayloadHash: ledger.BlobHash(act.Encode()), Time: f.l.Entries[len(f.l.Entries)-1].Time + 1}
	e.Author = pub(f.val)
	e.Sign(f.val)
	r := f.do("POST", "/v1/append", logserver.EncodeAppend(e, act.Encode()))
	if r.Status != 422 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if r.code() == "" {
		t.Fatal("no stable code")
	}
	if b := f.do("GET", "/v1/blob/"+hex.EncodeToString(e.PayloadHash[:]), nil); b.Status != 404 {
		t.Fatalf("payload of a refused entry is being served: %d", b.Status)
	}
	after, _ := os.ReadFile(filepath.Join(f.dir, "entries.bin"))
	if !bytes.Equal(before, after) || nblobs() != bb {
		t.Fatal("a refused entry left something on disk")
	}
	if f.srv.Status().Entries != len(f.l.Entries) {
		t.Fatal("log grew")
	}
}

func TestFutureEntryRefusedByServerClock(t *testing.T) {
	f := newFx(t, nil)
	f.sendAll(0)
	f.propose("f")
	e := f.l.Entries[len(f.l.Entries)-1]
	f.mu.Lock()
	f.now = time.Unix(int64(e.Time)-1000, 0)
	f.mu.Unlock()
	r := f.submit(e)
	if r.Status != 422 || r.code() != governance.CodeFutureEntry {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	f.advance(900 * time.Second) // now within the 300 s skew
	if r := f.submit(e); r.Status != 201 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
}

func TestRateLimit(t *testing.T) {
	f := newFx(t, func(c *logserver.Config) {
		c.Limits.Default = 3
		c.Limits.Window = time.Minute
		c.Limits.PerRole = map[ledger.Role]int{ledger.RoleValidator: 0}
	})
	f.sendAll(0) // genesis is exempt
	e := f.propose("a")
	_ = e
	pe := f.l.Entries[len(f.l.Entries)-1]
	good := f.payloadOf(pe)

	// Invalid submissions from an admitted key count too.
	bad := pe
	bad.PrevHash[0] ^= 1
	bad.Sign(f.prop)
	for i := 0; i < 3; i++ {
		if r := f.do("POST", "/v1/append", logserver.EncodeAppend(bad, good)); r.Status != 409 {
			t.Fatalf("attempt %d: %d %s", i, r.Status, r.Body)
		}
	}
	r := f.do("POST", "/v1/append", logserver.EncodeAppend(pe, good))
	if r.Status != 429 || r.code() != logserver.CodeRateLimited || r.Header.Get("Retry-After") == "" {
		t.Fatalf("%d %s %v", r.Status, r.Body, r.Header)
	}
	// Another author is unaffected: the validator (unlimited) can still write.
	if _, err := f.l.Freeze(f.val, []byte("pause")); err != nil {
		t.Fatal(err)
	}
	// ... but the proposal is still ahead of it in the log, so it conflicts, not 429.
	if r := f.submit(f.l.Entries[len(f.l.Entries)-1]); r.Status == 429 {
		t.Fatalf("validator was limited: %s", r.Body)
	}
	f.advance(61 * time.Second)
	if r := f.do("POST", "/v1/append", logserver.EncodeAppend(pe, good)); r.Status != 201 {
		t.Fatalf("after the window: %d %s", r.Status, r.Body)
	}
}

func TestForgedSubmissionsDoNotSpendAnotherKeysBudget(t *testing.T) {
	f := newFx(t, func(c *logserver.Config) { c.Limits.Default = 2 })
	f.sendAll(0)
	f.propose("a")
	pe := f.l.Entries[len(f.l.Entries)-1]
	good := f.payloadOf(pe)
	forged := pe
	forged.Signature[0] ^= 1
	for i := 0; i < 10; i++ {
		if r := f.do("POST", "/v1/append", logserver.EncodeAppend(forged, good)); r.Status != 400 {
			t.Fatalf("forged %d: %d %s", i, r.Status, r.Body)
		}
	}
	if r := f.do("POST", "/v1/append", logserver.EncodeAppend(pe, good)); r.Status != 201 {
		t.Fatalf("real submission after forgeries: %d %s", r.Status, r.Body)
	}
}

func TestRestartPersistsAndRechecks(t *testing.T) {
	f := newFx(t, nil)
	f.fullFlow()
	n := f.srv.Status().Entries
	root := f.srv.Status().Root
	f.reopen()
	if st := f.srv.Status(); st.Entries != n || st.Root != root {
		t.Fatalf("after restart %+v", st)
	}
	// Appending continues from the right place.
	f.propose("after")
	f.sendAll(n)
	if f.srv.Status().Entries != n+1 {
		t.Fatal("append after restart failed")
	}
}

func TestTornTailIsCut(t *testing.T) {
	f := newFx(t, nil)
	f.sendAll(0)
	n := f.srv.Status().Entries
	f.ts.Close()
	f.srv.Close()
	fh, _ := os.OpenFile(filepath.Join(f.dir, "entries.bin"), os.O_APPEND|os.O_WRONLY, 0)
	fh.Write(bytes.Repeat([]byte{7}, 100))
	fh.Close()
	f.open()
	if f.srv.Status().Entries != n {
		t.Fatalf("torn tail changed the log")
	}
	if fi, _ := os.Stat(filepath.Join(f.dir, "entries.bin")); fi.Size() != int64(n*ledger.EntrySize) {
		t.Fatalf("tail not truncated: %d", fi.Size())
	}
	f.propose("p")
	f.sendAll(n)
}

func TestOpenRefusesDamagedStores(t *testing.T) {
	setup := func(t *testing.T) *fx {
		f := newFx(t, nil)
		f.fullFlow()
		f.ts.Close()
		f.srv.Close()
		return f
	}
	expectFail := func(t *testing.T, f *fx) {
		t.Helper()
		if s, err := logserver.Open(f.cfg); err == nil {
			s.Close()
			t.Fatal("opened a damaged store")
		}
	}
	t.Run("flipped entry byte", func(t *testing.T) {
		f := setup(t)
		p := filepath.Join(f.dir, "entries.bin")
		b, _ := os.ReadFile(p)
		b[ledger.EntrySize*2+10] ^= 1
		os.WriteFile(p, b, 0o600)
		expectFail(t, f)
	})
	t.Run("misnamed blob", func(t *testing.T) {
		f := setup(t)
		des, _ := os.ReadDir(filepath.Join(f.dir, "blobs"))
		p := filepath.Join(f.dir, "blobs", des[0].Name())
		b, _ := os.ReadFile(p)
		b = append(b, 'x')
		os.WriteFile(p, b, 0o600)
		expectFail(t, f)
	})
	t.Run("misnamed supporting blob", func(t *testing.T) {
		f := newFx(t, nil)
		f.sendAll(0)
		p := f.propose("s")
		_ = p
		e := f.l.Entries[len(f.l.Entries)-1]
		extra := []byte("content s")
		if r := f.do("POST", "/v1/append", logserver.EncodeAppend(e, f.payloadOf(e), extra)); r.Status != 201 {
			t.Fatalf("%d %s", r.Status, r.Body)
		}
		f.ts.Close()
		f.srv.Close()
		h := ledger.BlobHash(extra)
		os.WriteFile(filepath.Join(f.dir, "blobs", hex.EncodeToString(h[:])), []byte("tampered"), 0o600)
		expectFail(t, f)
	})
	t.Run("missing payload blob", func(t *testing.T) {
		f := setup(t)
		h := f.l.Entries[1].PayloadHash
		os.Remove(filepath.Join(f.dir, "blobs", hex.EncodeToString(h[:])))
		expectFail(t, f)
	})
	t.Run("bad checkpoint", func(t *testing.T) {
		f := setup(t)
		os.WriteFile(filepath.Join(f.dir, "checkpoint.bin"), []byte("junk"), 0o600)
		expectFail(t, f)
	})
}

func (f *fx) sigReq(size uint64, k ed25519.PrivateKey, cp ledger.Checkpoint) []byte {
	sc := ledger.SignedCheckpoint{Checkpoint: cp}
	sc.Cosign(k)
	out := make([]byte, 8, 104)
	binary.BigEndian.PutUint64(out, size)
	out = append(out, sc.Sigs[0].Public[:]...)
	return append(out, sc.Sigs[0].Signature[:]...)
}

func TestCheckpointAggregation(t *testing.T) {
	f := newFx(t, nil)
	f.fullFlow()
	n := uint64(len(f.l.Entries))

	if r := f.do("GET", "/v1/checkpoint", nil); r.Status != 404 {
		t.Fatalf("checkpoint before signing: %d", r.Status)
	}
	body := f.do("GET", "/v1/checkpoint/body", nil)
	cp := ledger.NewCheckpoint(0, f.l.Entries)
	if body.Status != 200 || !bytes.Equal(body.Body, cp.Body()) {
		t.Fatalf("body: %d", body.Status)
	}

	// Strangers and non-signing roles are refused; a bad signature is refused.
	if r := f.do("POST", "/v1/checkpoint/signature", f.sigReq(n, key("stranger"), cp)); r.Status != 403 {
		t.Fatalf("stranger: %d %s", r.Status, r.Body)
	}
	if r := f.do("POST", "/v1/checkpoint/signature", f.sigReq(n, f.r1, cp)); r.Status != 403 {
		t.Fatalf("reviewer: %d %s", r.Status, r.Body)
	}
	bad := f.sigReq(n, f.val, cp)
	bad[60] ^= 1
	if r := f.do("POST", "/v1/checkpoint/signature", bad); r.Status != 400 || r.code() != ledger.CodeBadSignature {
		t.Fatalf("bad sig: %d %s", r.Status, r.Body)
	}
	if r := f.do("POST", "/v1/checkpoint/signature", []byte("short")); r.Status != 400 {
		t.Fatalf("short: %d", r.Status)
	}
	// A signature over the wrong content is a bad signature, not a stored one.
	other := cp
	other.Root[0] ^= 1
	if r := f.do("POST", "/v1/checkpoint/signature", f.sigReq(n, f.val, other)); r.Status != 400 {
		t.Fatalf("wrong content: %d", r.Status)
	}

	// The validator alone is below the witness threshold.
	r := f.do("POST", "/v1/checkpoint/signature", f.sigReq(n, f.val, cp))
	if r.Status != 202 || !bytes.Contains(r.Body, []byte("false")) {
		t.Fatalf("validator: %d %s", r.Status, r.Body)
	}
	if r := f.do("GET", "/v1/checkpoint", nil); r.Status != 404 {
		t.Fatalf("checkpoint at partial quorum: %d", r.Status)
	}
	r = f.do("POST", "/v1/checkpoint/signature", f.sigReq(n, f.wit, cp))
	if r.Status != 202 || !bytes.Contains(r.Body, []byte("true")) {
		t.Fatalf("witness: %d %s", r.Status, r.Body)
	}
	c := f.do("GET", "/v1/checkpoint", nil)
	if c.Status != 200 {
		t.Fatalf("checkpoint: %d", c.Status)
	}
	sc, err := ledger.DecodeSignedCheckpoint(c.Body)
	if err != nil {
		t.Fatal(err)
	}
	tr := f.trust
	if err := ledger.VerifyLog(f.l.Entries, &sc, &tr); err != nil {
		t.Fatalf("served checkpoint does not verify: %v", err)
	}

	// It survives a restart, and a checkpoint for an older size does not replace it.
	f.reopen()
	if r := f.do("GET", "/v1/checkpoint", nil); r.Status != 200 || !bytes.Equal(r.Body, c.Body) {
		t.Fatalf("after restart: %d", r.Status)
	}
	old := ledger.NewCheckpoint(0, f.l.Entries[:3])
	f.do("POST", "/v1/checkpoint/signature", f.sigReq(3, f.val, old))
	f.do("POST", "/v1/checkpoint/signature", f.sigReq(3, f.wit, old))
	if r := f.do("GET", "/v1/checkpoint", nil); !bytes.Equal(r.Body, c.Body) {
		t.Fatal("an older checkpoint replaced a newer one")
	}
	if got := f.srv.Status().CheckpointSize; got != n {
		t.Fatalf("checkpoint size %d", got)
	}
	if r := f.do("GET", "/v1/checkpoint/body?size="+strconv.Itoa(int(n)+1), nil); r.Status != 400 {
		t.Fatalf("size beyond log: %d", r.Status)
	}
}

func TestQueryValidation(t *testing.T) {
	f := newFx(t, nil)
	f.sendAll(0)
	for _, p := range []string{
		"/v1/entries?start=-1", "/v1/entries?limit=x", "/v1/proof/inclusion?index=0&size=0",
		"/v1/proof/inclusion?index=1&size=1", "/v1/proof/consistency?first=2&second=1",
		"/v1/proof/consistency?first=0&second=1", "/v1/proof/inclusion?index=0&size=99",
	} {
		if r := f.do("GET", p, nil); r.Status != 400 {
			t.Errorf("%s: %d", p, r.Status)
		}
	}
	if r := f.do("GET", "/v1/entries?start=5", nil); r.Status != 200 || len(r.Body) != 0 {
		t.Errorf("past end: %d %d", r.Status, len(r.Body))
	}
}

func TestStoreAndLogCaps(t *testing.T) {
	f := newFx(t, func(c *logserver.Config) { c.Limits.MaxEntries = 3; c.Limits.MaxStoreBytes = 4 << 10 })
	f.sendAll(0)
	f.propose("one")
	f.propose("two")
	f.propose("three")
	if r := f.submit(f.l.Entries[1]); r.Status != 201 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if r := f.submit(f.l.Entries[2]); r.Status != 201 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if r := f.submit(f.l.Entries[3]); r.Status != 507 || r.code() != logserver.CodeLogFull {
		t.Fatalf("%d %s", r.Status, r.Body)
	}

	g := newFx(t, func(c *logserver.Config) { c.Limits.MaxStoreBytes = 600 })
	g.sendAll(0)
	g.propose("big")
	e := g.l.Entries[len(g.l.Entries)-1]
	r := g.do("POST", "/v1/append", logserver.EncodeAppend(e, g.payloadOf(e), make([]byte, 900)))
	if r.Status != 507 || r.code() != logserver.CodeStoreFull {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	if g.srv.Status().Entries != 1 {
		t.Fatal("log grew past the store cap")
	}
}

func TestConcurrentAppendsExactlyOneWins(t *testing.T) {
	f := newFx(t, nil)
	f.sendAll(0)
	f.propose("race")
	e := f.l.Entries[len(f.l.Entries)-1]
	body := logserver.EncodeAppend(e, f.payloadOf(e))
	var wg sync.WaitGroup
	var mu sync.Mutex
	codes := map[int]int{}
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := f.do("POST", "/v1/append", body)
			mu.Lock()
			codes[r.Status]++
			mu.Unlock()
		}()
	}
	wg.Wait()
	if codes[201] != 1 || codes[409] != 15 {
		t.Fatalf("outcomes %v", codes)
	}
	if f.srv.Status().Entries != 2 {
		t.Fatal("wrong length")
	}
}

func FuzzAppend(fz *testing.F) {
	dir := fz.TempDir()
	val := key("val")
	var ga [32]byte
	copy(ga[:], val.Public().(ed25519.PublicKey))
	srv, err := logserver.Open(logserver.Config{Dir: dir, GenesisAuthor: ga, Now: func() time.Time { return time.Unix(2_000_000, 0) }})
	if err != nil {
		fz.Fatal(err)
	}
	defer srv.Close()
	fz.Add([]byte{})
	fz.Add(make([]byte, ledger.EntrySize+1))
	fz.Add(append(make([]byte, ledger.EntrySize), 1, 0, 0, 0, 0))
	fz.Fuzz(func(t *testing.T, b []byte) {
		before := srv.Status().Entries
		_, rj := srv.Append(b)
		if rj == nil && srv.Status().Entries != before+1 {
			t.Fatal("accepted without growing")
		}
		if rj != nil && (rj.Code == "" || rj.Status < 400) {
			t.Fatalf("bad reject %+v", rj)
		}
		if rj != nil && srv.Status().Entries != before {
			t.Fatal("rejected but grew")
		}
	})
}

func TestInterruptedAppendIsSettledOnRestart(t *testing.T) {
	stage := func(f *fx, height int, blob []byte) string {
		d := filepath.Join(f.dir, "staging")
		os.MkdirAll(d, 0o700)
		os.WriteFile(filepath.Join(d, "height"), []byte(strconv.Itoa(height)), 0o600)
		h := ledger.BlobHash(blob)
		os.WriteFile(filepath.Join(d, hex.EncodeToString(h[:])), blob, 0o600)
		return hex.EncodeToString(h[:])
	}
	exists := func(f *fx, name string) bool {
		_, err := os.Stat(filepath.Join(f.dir, "blobs", name))
		return err == nil
	}

	t.Run("entry never committed: staged blobs are dropped", func(t *testing.T) {
		f := newFx(t, nil)
		f.sendAll(0)
		name := stage(f, f.srv.Status().Entries, []byte("orphan"))
		f.reopen()
		if exists(f, name) {
			t.Fatal("an unreferenced blob was kept")
		}
		if _, err := os.Stat(filepath.Join(f.dir, "staging")); !os.IsNotExist(err) {
			t.Fatal("staging not cleared")
		}
	})
	t.Run("entry committed: staged blobs are finished", func(t *testing.T) {
		f := newFx(t, nil)
		f.sendAll(0)
		name := stage(f, f.srv.Status().Entries-1, []byte("kept"))
		f.reopen()
		if !exists(f, name) {
			t.Fatal("a blob of a committed entry was lost")
		}
	})
	t.Run("junk height file is treated as uncommitted", func(t *testing.T) {
		f := newFx(t, nil)
		f.sendAll(0)
		name := stage(f, 0, []byte("x"))
		os.WriteFile(filepath.Join(f.dir, "staging", "height"), []byte("not a number"), 0o600)
		f.reopen()
		if exists(f, name) {
			t.Fatal("kept a blob on an unreadable marker")
		}
	})
	t.Run("a normal append leaves no staging behind", func(t *testing.T) {
		f := newFx(t, nil)
		f.fullFlow()
		if _, err := os.Stat(filepath.Join(f.dir, "staging")); !os.IsNotExist(err) {
			t.Fatal("staging left behind")
		}
	})
}

func TestHugeBlobLengthIsRefusedNotPanicked(t *testing.T) {
	f := newFx(t, nil)
	f.sendAll(0)
	f.propose("h")
	e := f.l.Entries[len(f.l.Entries)-1]
	body := append(e.Encode(), 1, 0x80, 0, 0, 0)
	if r := f.do("POST", "/v1/append", body); r.Status != 413 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
	body = append(e.Encode(), 1, 0xff, 0xff, 0xff, 0xff)
	if r := f.do("POST", "/v1/append", body); r.Status != 413 {
		t.Fatalf("%d %s", r.Status, r.Body)
	}
}

func TestSpecListsEveryPackageCode(t *testing.T) {
	b, err := os.ReadFile("../docs/LOG-SERVER.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range logserver.AllCodes {
		if !bytes.Contains(b, []byte("`"+c+"`")) {
			t.Errorf("docs/LOG-SERVER.md does not mention %q", c)
		}
	}
}
