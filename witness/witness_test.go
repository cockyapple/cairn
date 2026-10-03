package witness_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
	"github.com/cockyapple/cairn/logserver"
	"github.com/cockyapple/cairn/review"
	"github.com/cockyapple/cairn/witness"
)

func key(name string) ed25519.PrivateKey {
	s := sha256.Sum256([]byte("cairn-witness-test-" + name))
	return ed25519.NewKeyFromSeed(s[:])
}

func pub(p ed25519.PrivateKey) (o [32]byte) { copy(o[:], p.Public().(ed25519.PublicKey)); return }

// world is one authoring log and a log server holding it. Two worlds built by
// newWorld share a genesis, so one can serve as a fork of the other.
type world struct {
	t                               *testing.T
	srv                             *logserver.Server
	l                               *review.Log
	val, wit, r1, r2, r3, sec, prop ed25519.PrivateKey
	trust                           ledger.TrustConfig
	sent                            int
	now                             int64
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, now: 2_000_000, val: key("val"), wit: key("wit"), r1: key("r1"), r2: key("r2"), r3: key("r3"), sec: key("sec"), prop: key("prop")}
	w.trust = ledger.TrustConfig{WitnessThreshold: 1, Keys: []ledger.Key{
		{Role: ledger.RoleValidator, Public: pub(w.val)}, {Role: ledger.RoleWitness, Public: pub(w.wit)},
		{Role: ledger.RoleReviewer, Public: pub(w.r1)}, {Role: ledger.RoleReviewer, Public: pub(w.r2)},
		{Role: ledger.RoleReviewer, Public: pub(w.r3)}, {Role: ledger.RoleSecurityReviewer, Public: pub(w.sec)},
		{Role: ledger.RoleProposer, Public: pub(w.prop)},
	}}
	clk := uint64(1_000_000)
	l, err := review.New(w.val, ledger.BlobHash([]byte("c")), w.trust, func() uint64 { clk++; return clk })
	if err != nil {
		t.Fatal(err)
	}
	w.l = l
	srv, err := logserver.Open(logserver.Config{
		Dir: t.TempDir(), GenesisAuthor: pub(w.val), Now: func() time.Time { return time.Unix(w.now, 0) },
		Limits: logserver.Limits{Default: 1000},
	})
	if err != nil {
		t.Fatal(err)
	}
	w.srv = srv
	t.Cleanup(func() { srv.Close() })
	return w
}

func (w *world) send() {
	w.t.Helper()
	for _, e := range w.l.Entries[w.sent:] {
		if _, rj := w.srv.Append(logserver.EncodeAppend(e, w.l.Blobs[e.PayloadHash])); rj != nil {
			w.t.Fatalf("entry %d: %v", e.Height, rj)
		}
	}
	w.sent = len(w.l.Entries)
}

func (w *world) propose(name string) ledger.Hash {
	w.t.Helper()
	p, err := w.l.Propose(w.prop, ledger.T2, "prompt/"+name, []byte("content "+name), []byte("why"), nil)
	if err != nil {
		w.t.Fatal(err)
	}
	return p
}

// activated authors a full proposal-to-activation flow (6 entries after genesis).
func (w *world) activated(name string) {
	w.t.Helper()
	p := w.propose(name)
	for _, k := range []ed25519.PrivateKey{w.r1, w.r2, w.sec} {
		if _, err := w.l.Vote(k, p, ledger.VerdictApprove, []byte("ok")); err != nil {
			w.t.Fatal(err)
		}
	}
	if _, err := w.l.Activate(w.val, p); err != nil {
		w.t.Fatal(err)
	}
}

// front is what the witness talks to. It can be pointed at any handler, wraps
// requests with a hook, and records what was asked.
type front struct {
	mu   sync.Mutex
	h    http.Handler
	hook func(http.ResponseWriter, *http.Request) bool
	reqs []string
}

func (f *front) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.reqs = append(f.reqs, r.Method+" "+r.URL.RequestURI())
	h, hook := f.h, f.hook
	f.mu.Unlock()
	if hook != nil && hook(rw, r) {
		return
	}
	h.ServeHTTP(rw, r)
}

func (f *front) set(h http.Handler) { f.mu.Lock(); f.h = h; f.mu.Unlock() }
func (f *front) setHook(h func(http.ResponseWriter, *http.Request) bool) {
	f.mu.Lock()
	f.hook = h
	f.mu.Unlock()
}
func (f *front) clear() { f.mu.Lock(); f.reqs = nil; f.mu.Unlock() }
func (f *front) count(prefix string) (n int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, r := range f.reqs {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return
}

type rig struct {
	t     *testing.T
	w     *world
	front *front
	ts    *httptest.Server
	state string
	cfg   witness.Config
}

func newRig(t *testing.T, mod func(*witness.Config)) *rig {
	t.Helper()
	w := newWorld(t)
	fr := &front{h: w.srv.Handler()}
	ts := httptest.NewServer(fr)
	t.Cleanup(ts.Close)
	r := &rig{t: t, w: w, front: fr, ts: ts, state: filepath.Join(t.TempDir(), "state.json")}
	r.cfg = witness.Config{Server: ts.URL, Key: w.wit, StatePath: r.state}
	if mod != nil {
		mod(&r.cfg)
	}
	return r
}

func (r *rig) witness() *witness.Witness {
	r.t.Helper()
	wi, err := witness.New(r.cfg)
	if err != nil {
		r.t.Fatal(err)
	}
	return wi
}

func (r *rig) cycle(wi *witness.Witness, size uint64) (witness.Result, error) {
	return wi.Cycle(context.Background(), size)
}

func wantCode(t *testing.T, err error, code string) {
	t.Helper()
	if got := witness.Code(err); got != code {
		t.Fatalf("code = %q (%v), want %q", got, err, code)
	}
}

func (r *rig) noState() {
	r.t.Helper()
	if _, err := os.Stat(r.state); !os.IsNotExist(err) {
		r.t.Fatalf("a state file exists (%v) though nothing should have been signed", err)
	}
}

func TestCosignCompletesCheckpoint(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	n := uint64(len(r.w.l.Entries))
	wi := r.witness()

	res, err := r.cycle(wi, 0)
	if err != nil {
		t.Fatal(err)
	}
	if res.Size != n || res.Complete {
		t.Fatalf("result %+v: want size %d and not complete (no validator yet)", res, n)
	}
	if _, ok := r.w.srv.Checkpoint(); ok {
		t.Fatal("a checkpoint was served on a witness signature alone")
	}

	cp := ledger.NewCheckpoint(0, r.w.l.Entries)
	sc := ledger.SignedCheckpoint{Checkpoint: cp}
	sc.Cosign(r.w.val)
	if complete, rj := r.w.srv.AddSignature(n, sc.Sigs[0].Public, sc.Sigs[0].Signature); rj != nil || !complete {
		t.Fatalf("validator signature: complete=%v %v", complete, rj)
	}
	raw, ok := r.w.srv.Checkpoint()
	if !ok {
		t.Fatal("no checkpoint after validator and witness signed")
	}
	got, err := ledger.DecodeSignedCheckpoint(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := ledger.VerifyLog(r.w.l.Entries, &got, &r.w.trust); err != nil {
		t.Fatalf("the served checkpoint does not verify: %v", err)
	}
	var sawWitness bool
	for _, s := range got.Sigs {
		sawWitness = sawWitness || s.Public == pub(r.w.wit)
	}
	if !sawWitness {
		t.Fatal("the witness's signature is not in the checkpoint")
	}
}

func TestValidatorFirstThenWitnessCompletes(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	n := uint64(len(r.w.l.Entries))
	sc := ledger.SignedCheckpoint{Checkpoint: ledger.NewCheckpoint(0, r.w.l.Entries)}
	sc.Cosign(r.w.val)
	r.w.srv.AddSignature(n, sc.Sigs[0].Public, sc.Sigs[0].Signature)
	res, err := r.cycle(r.witness(), 0)
	if err != nil || !res.Complete {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestSignsAnEarlierPrefixOnRequest(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	wi := r.witness()
	res, err := r.cycle(wi, 3)
	if err != nil || res.Size != 3 {
		t.Fatalf("%+v %v", res, err)
	}
	want := ledger.NewCheckpoint(0, r.w.l.Entries[:3])
	if res.Root != want.Root {
		t.Fatal("root differs from the prefix's root")
	}
	if size, root := wi.Seen(); size != 3 || root != want.Root {
		t.Fatalf("seen %d %x", size, root[:4])
	}
	_, err = r.cycle(wi, 2)
	wantCode(t, err, witness.CodeStaleSize)
	_, err = r.cycle(wi, 999)
	wantCode(t, err, witness.CodeBadRequest)
}

func TestGrowthReusesWhatItHolds(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	wi := r.witness()
	if _, err := r.cycle(wi, 0); err != nil {
		t.Fatal(err)
	}
	if r.front.count("GET /v1/blob/") == 0 {
		t.Fatal("the first cycle fetched no blobs, so governance was not really checked")
	}
	var first []string
	for _, q := range r.front.reqs {
		if strings.HasPrefix(q, "GET /v1/blob/") {
			first = append(first, q)
		}
	}
	r.front.clear()
	r.w.activated("y")
	r.w.send()
	res, err := r.cycle(wi, 0)
	if err != nil || res.Size != uint64(len(r.w.l.Entries)) {
		t.Fatalf("%+v %v", res, err)
	}
	if n := r.front.count("GET /v1/entries?start=0"); n != 0 {
		t.Fatalf("the second cycle re-read the log from the start (%d times)", n)
	}
	if n := r.front.count("GET /v1/entries?start=6&limit=1&"); n != 0 {
		t.Log("unexpected overlap query form")
	}
	var overlap bool
	for _, q := range r.front.reqs {
		overlap = overlap || strings.HasPrefix(q, "GET /v1/entries?start=6&limit=1")
	}
	if !overlap {
		t.Fatalf("no overlap read of the last held entry: %v", r.front.reqs)
	}
	for _, q := range r.front.reqs {
		for _, f := range first {
			if q == f {
				t.Fatalf("blob fetched again though it was already held: %s", q)
			}
		}
	}
}

func TestAColdCycleReadsTheLogOnce(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	if _, err := r.cycle(r.witness(), 0); err != nil {
		t.Fatal(err)
	}
	if n := r.front.count("GET /v1/entries"); n != 1 {
		t.Fatalf("a log that fits one page took %d reads: %v", n, r.front.reqs)
	}
}

func TestARollbackIsAnAlarmEvenWhenMoreIsRequested(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	full := uint64(len(r.w.l.Entries))
	if _, err := r.cycle(r.witness(), 0); err != nil {
		t.Fatal(err)
	}
	short := newWorld(t)
	short.send()
	r.front.set(short.srv.Handler())
	_, err := r.cycle(r.witness(), full)
	wantCode(t, err, witness.CodeShrank)
}

func TestIdempotentAtSameSize(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	wi := r.witness()
	for i := 0; i < 2; i++ {
		if _, err := r.cycle(wi, 0); err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
	}
	wi2 := r.witness()
	if _, err := r.cycle(wi2, 0); err != nil {
		t.Fatalf("after restart: %v", err)
	}
}

func TestRefusesAForkAtTheSameSize(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	wi := r.witness()
	if _, err := r.cycle(wi, 0); err != nil {
		t.Fatal(err)
	}
	size, root := wi.Seen()

	fork := newWorld(t)
	fork.activated("y")
	fork.send()
	if uint64(len(fork.l.Entries)) != size {
		t.Fatalf("test setup: fork has %d entries, want %d", len(fork.l.Entries), size)
	}
	r.front.set(fork.srv.Handler())

	_, err := r.cycle(wi, 0)
	wantCode(t, err, witness.CodeDiverged)
	fresh := r.witness()
	_, err = r.cycle(fresh, 0)
	wantCode(t, err, witness.CodeDiverged)
	if s, rt := wi.Seen(); s != size || rt != root {
		t.Fatal("the witness's memory changed after a refusal")
	}
}

func TestRefusesAForkThatGrewLonger(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	wi := r.witness()
	if _, err := r.cycle(wi, 0); err != nil {
		t.Fatal(err)
	}
	fork := newWorld(t)
	fork.activated("y")
	fork.activated("z")
	fork.send()
	r.front.set(fork.srv.Handler())
	_, err := r.cycle(wi, 0)
	wantCode(t, err, witness.CodeDiverged)
	_, err = r.cycle(r.witness(), 0)
	wantCode(t, err, witness.CodeDiverged)
}

func TestRefusesAShrunkLog(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	wi := r.witness()
	if _, err := r.cycle(wi, 0); err != nil {
		t.Fatal(err)
	}
	short := newWorld(t)
	short.send()
	r.front.set(short.srv.Handler())
	_, err := r.cycle(wi, 0)
	wantCode(t, err, witness.CodeShrank)
	if !witness.Alarm(witness.CodeShrank) || !witness.Alarm(witness.CodeDiverged) || witness.Alarm(witness.CodeUnavailable) {
		t.Fatal("Alarm classification is wrong")
	}
	_, err = r.cycle(r.witness(), 0)
	wantCode(t, err, witness.CodeShrank)
}

func TestRecoversWhenTheServerReturnsToTheTruth(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	wi := r.witness()
	if _, err := r.cycle(wi, 0); err != nil {
		t.Fatal(err)
	}
	fork := newWorld(t)
	fork.activated("y")
	fork.send()
	r.front.set(fork.srv.Handler())
	if _, err := r.cycle(wi, 0); err == nil {
		t.Fatal("signed a fork")
	}
	r.front.set(r.w.srv.Handler())
	if _, err := r.cycle(wi, 0); err != nil {
		t.Fatalf("did not resume once the server told the truth: %v", err)
	}
}

// stranger builds a chain that is well formed (hashes and signatures verify)
// but breaks the rules: the second entry is written by a key nobody admitted.
func strangerHandler(t *testing.T, w *world) http.Handler {
	t.Helper()
	g := w.l.Entries[0]
	payload := []byte("not allowed")
	e := ledger.Entry{Height: 1, PrevHash: g.Hash(), Kind: ledger.KindProposal, PayloadHash: ledger.BlobHash(payload), Author: pub(key("stranger")), Time: g.Time + 1}
	e.Sign(key("stranger"))
	raw := append(g.Encode(), e.Encode()...)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/entries", func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("X-Cairn-Size", "2")
		rw.Write(raw)
	})
	mux.HandleFunc("/v1/blob/", func(rw http.ResponseWriter, r *http.Request) {
		for h, b := range w.l.Blobs {
			if strings.HasSuffix(r.URL.Path, hexOf(h)) {
				rw.Write(b)
				return
			}
		}
		rw.Write(payload)
	})
	mux.HandleFunc("/v1/checkpoint/signature", func(rw http.ResponseWriter, r *http.Request) {
		t.Error("a signature was submitted for an unlawful log")
	})
	return mux
}

func hexOf(h ledger.Hash) string {
	const d = "0123456789abcdef"
	b := make([]byte, 64)
	for i, c := range h {
		b[2*i], b[2*i+1] = d[c>>4], d[c&15]
	}
	return string(b)
}

func TestRefusesALogThatBreaksTheRules(t *testing.T) {
	r := newRig(t, nil)
	r.front.set(strangerHandler(t, r.w))
	_, err := r.cycle(r.witness(), 0)
	wantCode(t, err, witness.CodeInvalidLog)
	r.noState()
}

func TestRefusesFutureDatedEntriesByItsOwnClock(t *testing.T) {
	r := newRig(t, func(c *witness.Config) { c.Clock = func() time.Time { return time.Unix(900_000, 0) } })
	r.w.activated("x")
	r.w.send()
	_, err := r.cycle(r.witness(), 0)
	wantCode(t, err, witness.CodeInvalidLog)
	r.noState()

	ok := newRig(t, func(c *witness.Config) { c.Clock = func() time.Time { return time.Unix(1_100_000, 0) } })
	ok.w.activated("x")
	ok.w.send()
	if _, err := ok.cycle(ok.witness(), 0); err != nil {
		t.Fatal(err)
	}
}

func TestBlobProblemsAreTheServersFaultNotTheLogs(t *testing.T) {
	for name, hook := range map[string]func(http.ResponseWriter, *http.Request) bool{
		"missing": func(rw http.ResponseWriter, r *http.Request) bool {
			if strings.HasPrefix(r.URL.Path, "/v1/blob/") {
				http.NotFound(rw, r)
				return true
			}
			return false
		},
		"altered": func(rw http.ResponseWriter, r *http.Request) bool {
			if strings.HasPrefix(r.URL.Path, "/v1/blob/") {
				rw.Write([]byte("not what you asked for"))
				return true
			}
			return false
		},
		"oversized": func(rw http.ResponseWriter, r *http.Request) bool {
			if strings.HasPrefix(r.URL.Path, "/v1/blob/") {
				rw.Write(bytes.Repeat([]byte("x"), 5000))
				return true
			}
			return false
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, func(c *witness.Config) { c.MaxBlob = 4096 })
			r.w.activated("x")
			r.w.send()
			r.front.setHook(hook)
			_, err := r.cycle(r.witness(), 0)
			wantCode(t, err, witness.CodeUnavailable)
			r.noState()
		})
	}
}

func TestBlobCountAndSizeLimits(t *testing.T) {
	r := newRig(t, func(c *witness.Config) { c.MaxBlobs = 1 })
	r.w.activated("x")
	r.w.send()
	_, err := r.cycle(r.witness(), 0)
	wantCode(t, err, witness.CodeUnavailable)

	r2 := newRig(t, func(c *witness.Config) { c.MaxBlobSum = 10 })
	r2.w.activated("x")
	r2.w.send()
	_, err = r2.cycle(r2.witness(), 0)
	wantCode(t, err, witness.CodeUnavailable)
}

func TestOnlyAnAdmittedWitnessSigns(t *testing.T) {
	r := newRig(t, func(c *witness.Config) { c.Key = key("someone else") })
	r.w.activated("x")
	r.w.send()
	_, err := r.cycle(r.witness(), 0)
	wantCode(t, err, witness.CodeNotWitness)
	r.noState()

	v := newRig(t, func(c *witness.Config) { c.Key = key("val") })
	v.w.activated("x")
	v.w.send()
	_, err = v.cycle(v.witness(), 0)
	wantCode(t, err, witness.CodeNotWitness)
}

func TestGenesisPin(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	h := r.w.l.Entries[0].Hash()
	r.cfg.Genesis = &h
	if _, err := r.cycle(r.witness(), 0); err != nil {
		t.Fatal(err)
	}
	other := newRig(t, nil)
	other.w.activated("x")
	other.w.send()
	bad := ledger.Hash{1}
	other.cfg.Genesis = &bad
	_, err := other.cycle(other.witness(), 0)
	wantCode(t, err, witness.CodeWrongGenesis)
	other.noState()
}

func TestMemoryIsWrittenBeforeTheSignatureIsSent(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	n := uint64(len(r.w.l.Entries))
	var stateAtPost int64 = -1
	r.front.setHook(func(rw http.ResponseWriter, q *http.Request) bool {
		if q.Method == "POST" {
			if b, err := os.ReadFile(r.state); err == nil {
				stateAtPost = int64(len(b))
			}
			http.Error(rw, "down", http.StatusServiceUnavailable)
			return true
		}
		return false
	})
	wi := r.witness()
	_, err := r.cycle(wi, 0)
	wantCode(t, err, witness.CodeSubmit)
	if stateAtPost <= 0 {
		t.Fatal("the state file did not exist when the signature was sent")
	}
	if s, _ := wi.Seen(); s != n {
		t.Fatalf("seen %d want %d", s, n)
	}
	r.front.setHook(nil)
	res, err := r.cycle(r.witness(), 0)
	if err != nil || res.Size != n {
		t.Fatalf("retry after restart: %+v %v", res, err)
	}
}

func TestServerRefusalIsReported(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	r.front.setHook(func(rw http.ResponseWriter, q *http.Request) bool {
		if q.Method == "POST" {
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(429)
			rw.Write([]byte(`{"error":"rate_limited","detail":"slow down"}`))
			return true
		}
		return false
	})
	_, err := r.cycle(r.witness(), 0)
	wantCode(t, err, witness.CodeSubmit)
	if !strings.Contains(err.Error(), "rate_limited") {
		t.Fatalf("the server's code is not in the error: %v", err)
	}
	r.front.setHook(func(rw http.ResponseWriter, q *http.Request) bool {
		if q.Method == "POST" {
			rw.WriteHeader(http.StatusAccepted)
			rw.Write([]byte("not json"))
			return true
		}
		return false
	})
	_, err = r.cycle(r.witness(), 0)
	wantCode(t, err, witness.CodeSubmit)
}

func TestHostileServerResponses(t *testing.T) {
	good := func(rw http.ResponseWriter, size string, body []byte) {
		if size != "" {
			rw.Header().Set("X-Cairn-Size", size)
		}
		rw.Write(body)
	}
	cases := map[string]func(*rig) func(http.ResponseWriter, *http.Request) bool{
		"no size header": func(*rig) func(http.ResponseWriter, *http.Request) bool {
			return func(rw http.ResponseWriter, q *http.Request) bool { good(rw, "", nil); return true }
		},
		"size not a number": func(*rig) func(http.ResponseWriter, *http.Request) bool {
			return func(rw http.ResponseWriter, q *http.Request) bool { good(rw, "-3", nil); return true }
		},
		"huge size": func(*rig) func(http.ResponseWriter, *http.Request) bool {
			return func(rw http.ResponseWriter, q *http.Request) bool { good(rw, "99999999999", nil); return true }
		},
		"size overflows": func(*rig) func(http.ResponseWriter, *http.Request) bool {
			return func(rw http.ResponseWriter, q *http.Request) bool {
				good(rw, "99999999999999999999999", nil)
				return true
			}
		},
		"claims entries, sends none": func(*rig) func(http.ResponseWriter, *http.Request) bool {
			return func(rw http.ResponseWriter, q *http.Request) bool { good(rw, "5", nil); return true }
		},
		"partial entry": func(*rig) func(http.ResponseWriter, *http.Request) bool {
			return func(rw http.ResponseWriter, q *http.Request) bool { good(rw, "1", []byte("short")); return true }
		},
		"garbage entry": func(*rig) func(http.ResponseWriter, *http.Request) bool {
			return func(rw http.ResponseWriter, q *http.Request) bool {
				good(rw, "1", bytes.Repeat([]byte{0xff}, ledger.EntrySize))
				return true
			}
		},
		"body over the page limit": func(*rig) func(http.ResponseWriter, *http.Request) bool {
			return func(rw http.ResponseWriter, q *http.Request) bool {
				good(rw, "1", bytes.Repeat([]byte{0}, 1000*ledger.EntrySize+1))
				return true
			}
		},
		"server error": func(*rig) func(http.ResponseWriter, *http.Request) bool {
			return func(rw http.ResponseWriter, q *http.Request) bool { http.Error(rw, "boom", 500); return true }
		},
		"redirect": func(r *rig) func(http.ResponseWriter, *http.Request) bool {
			return func(rw http.ResponseWriter, q *http.Request) bool {
				http.Redirect(rw, q, "http://127.0.0.1:1/elsewhere", http.StatusFound)
				return true
			}
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, func(c *witness.Config) { c.MaxEntries = 1000 })
			r.w.activated("x")
			r.w.send()
			r.front.setHook(mk(r))
			_, err := r.cycle(r.witness(), 0)
			if err == nil {
				t.Fatal("signed against a hostile server")
			}
			if c := witness.Code(err); c != witness.CodeUnavailable && c != witness.CodeInvalidLog {
				t.Fatalf("code %q (%v)", c, err)
			}
			r.noState()
		})
	}
}

func TestUnreachableServer(t *testing.T) {
	r := newRig(t, nil)
	r.ts.Close()
	_, err := r.cycle(r.witness(), 0)
	wantCode(t, err, witness.CodeUnavailable)
}

func TestEmptyLog(t *testing.T) {
	r := newRig(t, nil)
	_, err := r.cycle(r.witness(), 0)
	wantCode(t, err, witness.CodeUnavailable)
	r.noState()
}

func TestStateFileIsNotIgnoredWhenDamaged(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	good := `{"version":1,"size":3,"root":"` + strings.Repeat("ab", 32) + `","head":"` + strings.Repeat("cd", 32) + `"}`
	for name, content := range map[string]string{
		"not json":      "garbage",
		"empty":         "",
		"zero size":     strings.Replace(good, `"size":3`, `"size":0`, 1),
		"wrong version": strings.Replace(good, `"version":1`, `"version":2`, 1),
		"bad root":      strings.Replace(good, strings.Repeat("ab", 32), "xyz", 1),
		"bad head":      strings.Replace(good, strings.Repeat("cd", 32), "00", 1),
		"unknown field": strings.Replace(good, `"size"`, `"extra":1,"size"`, 1),
		"trailing data": good + good,
	} {
		if err := os.WriteFile(r.state, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := witness.New(r.cfg); witness.Code(err) != witness.CodeState {
			t.Errorf("%s: err = %v, want a state_error", name, err)
		}
	}
	if err := os.WriteFile(r.state, []byte(good), 0o600); err != nil {
		t.Fatal(err)
	}
	wi, err := witness.New(r.cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.cycle(wi, 0); witness.Code(err) != witness.CodeDiverged {
		t.Fatalf("a remembered root that matches nothing must refuse: %v", err)
	}
}

func TestStateFileWithLooseModeIsRefused(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	if _, err := r.cycle(r.witness(), 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(r.state, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := witness.New(r.cfg); witness.Code(err) != witness.CodeState {
		t.Fatalf("a world-writable state file could let anyone rewrite what the witness remembers: %v", err)
	}
	if err := os.Chmod(r.state, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := witness.New(r.cfg); err != nil {
		t.Fatal(err)
	}
}

func TestADrippingServerIsRefusedNotFollowed(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	r.front.setHook(func(rw http.ResponseWriter, q *http.Request) bool {
		if !strings.HasPrefix(q.URL.Path, "/v1/entries") {
			return false
		}
		start, _ := strconv.Atoi(q.URL.Query().Get("start"))
		rw.Header().Set("X-Cairn-Size", strconv.Itoa(len(r.w.l.Entries)))
		rw.Write(r.w.l.Entries[start].Encode())
		return true
	})
	_, err := r.cycle(r.witness(), 0)
	wantCode(t, err, witness.CodeUnavailable)
	if !strings.Contains(err.Error(), "short page") {
		t.Fatalf("wrong reason: %v", err)
	}
	r.noState()
}

func TestStateIsPrivateAndAtomic(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	if _, err := r.cycle(r.witness(), 0); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(r.state)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Fatalf("state file mode %v is readable by others", fi.Mode().Perm())
	}
	if _, err := os.Stat(r.state + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("a temporary file was left behind")
	}
}

func TestStateWriteFailureStopsSigning(t *testing.T) {
	r := newRig(t, nil)
	r.cfg.StatePath = filepath.Join(t.TempDir(), "no-such-dir", "state.json")
	r.w.activated("x")
	r.w.send()
	r.front.setHook(func(rw http.ResponseWriter, q *http.Request) bool {
		if q.Method == "POST" {
			t.Error("a signature was sent although the state could not be saved")
		}
		return false
	})
	_, err := r.cycle(r.witness(), 0)
	wantCode(t, err, witness.CodeState)
}

func TestNewValidatesConfig(t *testing.T) {
	good := witness.Config{Server: "http://127.0.0.1:1", Key: key("wit"), StatePath: filepath.Join(t.TempDir(), "s")}
	for name, mod := range map[string]func(*witness.Config){
		"short key":  func(c *witness.Config) { c.Key = ed25519.PrivateKey("short") },
		"no state":   func(c *witness.Config) { c.StatePath = "" },
		"no scheme":  func(c *witness.Config) { c.Server = "127.0.0.1:8480" },
		"ftp scheme": func(c *witness.Config) { c.Server = "ftp://x" },
	} {
		c := good
		mod(&c)
		if _, err := witness.New(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := witness.New(good); err != nil {
		t.Fatal(err)
	}
	c := good
	c.Server = "http://127.0.0.1:1///"
	if _, err := witness.New(c); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentCyclesAreSerialised(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	wi := r.witness()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := r.cycle(wi, 0); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func TestRunSignsAndReportsOnce(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	sc := ledger.SignedCheckpoint{Checkpoint: ledger.NewCheckpoint(0, r.w.l.Entries)}
	sc.Cosign(r.w.val)
	r.w.srv.AddSignature(uint64(len(r.w.l.Entries)), sc.Sigs[0].Public, sc.Sigs[0].Signature)

	var mu sync.Mutex
	var lines []string
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.witness().Run(ctx, 5*time.Millisecond, func(f string, a ...any) {
			mu.Lock()
			lines = append(lines, fmt.Sprintf(f, a...))
			mu.Unlock()
		})
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := r.w.srv.Checkpoint(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no checkpoint from the run loop")
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(60 * time.Millisecond)
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(lines) != 1 {
		t.Fatalf("an unchanged log should be reported once, got %d lines: %v", len(lines), lines)
	}
}

func TestCodesAreDocumented(t *testing.T) {
	b, err := os.ReadFile("../docs/WITNESS.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range witness.AllCodes {
		if !bytes.Contains(b, []byte("`"+c+"`")) {
			t.Errorf("docs/WITNESS.md does not mention %q", c)
		}
	}
}

var _ = governance.Options{}

// A log whose second entry has the right height but does not point at the
// first is a fork or a corruption; the witness must say so before replaying.
func TestRefusesAChainThatDoesNotLink(t *testing.T) {
	r := newRig(t, nil)
	g := r.w.l.Entries[0]
	e := ledger.Entry{Height: 1, PrevHash: ledger.Hash{9}, Kind: ledger.KindProposal, PayloadHash: ledger.BlobHash([]byte("x")), Time: g.Time + 1}
	e.Sign(r.w.val)
	raw := append(g.Encode(), e.Encode()...)
	r.front.set(http.HandlerFunc(func(rw http.ResponseWriter, q *http.Request) {
		rw.Header().Set("X-Cairn-Size", "2")
		rw.Write(raw)
	}))
	_, err := r.cycle(r.witness(), 0)
	wantCode(t, err, witness.CodeDiverged)
	r.noState()
}

func TestRefusesALogOverItsEntryLimit(t *testing.T) {
	r := newRig(t, func(c *witness.Config) { c.MaxEntries = 3 })
	r.w.activated("x")
	r.w.send()
	_, err := r.cycle(r.witness(), 0)
	wantCode(t, err, witness.CodeUnavailable)
	if !strings.Contains(err.Error(), "limit") {
		t.Fatalf("not refused for its size: %v", err)
	}
	r.noState()
}

func TestAResponseThatIsNotWholeEntriesIsUnavailable(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	r.front.setHook(func(rw http.ResponseWriter, q *http.Request) bool {
		if strings.HasPrefix(q.URL.Path, "/v1/entries") {
			rw.Header().Set("X-Cairn-Size", "1")
			rw.Write([]byte("short"))
			return true
		}
		return false
	})
	_, err := r.cycle(r.witness(), 0)
	wantCode(t, err, witness.CodeUnavailable)
	if !strings.Contains(err.Error(), "whole number") {
		t.Fatalf("wrong reason: %v", err)
	}
}

// After a VALIDATORS change the epoch is 1. A witness that signed epoch 0
// would produce a signature the checkpoint rule rejects.
func TestSignsTheEpochInForce(t *testing.T) {
	r := newRig(t, nil)
	w := r.w
	w.now = 5_000_000
	next := w.trust
	next.Epoch = 1
	enc := next.Encode()
	p, err := w.l.Propose(w.prop, ledger.T4, "cairn/validators", enc, []byte("rotate"), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []ed25519.PrivateKey{w.r1, w.r2, w.sec} {
		if _, err := w.l.Vote(k, p, ledger.VerdictApprove, []byte("ok")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.l.Activate(w.val, p); err != nil {
		t.Fatal(err)
	}
	last := w.l.Entries[len(w.l.Entries)-1]
	v := ledger.Entry{Height: last.Height + 1, PrevHash: last.Hash(), Kind: ledger.KindValidators, PayloadHash: ledger.BlobHash(enc), Time: last.Time + 14*24*3600 + 1}
	v.Sign(w.val)
	w.l.Entries = append(w.l.Entries, v)
	w.l.Blobs[v.PayloadHash] = enc
	w.send()

	n := uint64(len(w.l.Entries))
	res, err := r.cycle(r.witness(), 0)
	if err != nil || res.Size != n {
		t.Fatalf("%+v %v", res, err)
	}
	sc := ledger.SignedCheckpoint{Checkpoint: ledger.NewCheckpoint(1, w.l.Entries)}
	sc.Cosign(w.val)
	if complete, rj := w.srv.AddSignature(n, sc.Sigs[0].Public, sc.Sigs[0].Signature); rj != nil || !complete {
		t.Fatalf("validator signature at epoch 1: complete=%v %v", complete, rj)
	}
	raw, ok := w.srv.Checkpoint()
	if !ok {
		t.Fatal("no checkpoint")
	}
	got, err := ledger.DecodeSignedCheckpoint(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Epoch != 1 {
		t.Fatalf("epoch %d", got.Epoch)
	}
	if err := ledger.VerifyLog(w.l.Entries, &got, &next); err != nil {
		t.Fatalf("checkpoint with the witness's signature does not verify at epoch 1: %v", err)
	}
}

func TestRunReportsWhenTheCheckpointBecomesComplete(t *testing.T) {
	r := newRig(t, nil)
	r.w.activated("x")
	r.w.send()
	var mu sync.Mutex
	var lines []string
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.witness().Run(ctx, 5*time.Millisecond, func(f string, a ...any) {
			mu.Lock()
			lines = append(lines, fmt.Sprintf(f, a...))
			mu.Unlock()
		})
		close(done)
	}()
	wait := func(want int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			mu.Lock()
			n := len(lines)
			mu.Unlock()
			if n >= want {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("expected %d log lines, have %d", want, n)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	wait(1)
	sc := ledger.SignedCheckpoint{Checkpoint: ledger.NewCheckpoint(0, r.w.l.Entries)}
	sc.Cosign(r.w.val)
	r.w.srv.AddSignature(uint64(len(r.w.l.Entries)), sc.Sigs[0].Public, sc.Sigs[0].Signature)
	wait(2)
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(lines[0], "complete: false") || !strings.Contains(lines[1], "complete: true") {
		t.Fatalf("lines: %q", lines)
	}
}
