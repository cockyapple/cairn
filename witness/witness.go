// Package witness is an independent cosigner for a Cairn log. It runs on a
// different machine from the log server, holds its own key, downloads the log,
// checks all of it itself (chain, governance rules, the checkpoint it is about
// to sign) and signs only a checkpoint that extends what it signed before.
// A log server, or whoever controls it, that rewrites history, forks it or
// shrinks it therefore cannot obtain this witness's signature on the new view.
package witness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
)

// Stable codes for why a cycle did not sign.
const (
	CodeUnavailable  = "unavailable"      // the server could not be read, or sent something unusable
	CodeShrank       = "log_shrank"       // the log is shorter than what this witness has already seen
	CodeDiverged     = "history_diverged" // the log no longer extends what this witness has seen
	CodeInvalidLog   = "invalid_log"      // the chain or the governance rules fail
	CodeNotWitness   = "not_a_witness"    // this key is not an admitted witness at that size
	CodeWrongGenesis = "wrong_genesis"    // the first entry is not the pinned one
	CodeStaleSize    = "stale_size"       // asked to sign a size below one already signed
	CodeBadRequest   = "bad_request"      // the requested size is beyond the log
	CodeState        = "state_error"      // the state file cannot be read or written
	CodeSubmit       = "submit_failed"    // the server refused the signature
)

// AllCodes lists the codes this package defines; a test requires
// docs/WITNESS.md to list the same ones.
var AllCodes = []string{
	CodeUnavailable, CodeShrank, CodeDiverged, CodeInvalidLog, CodeNotWitness,
	CodeWrongGenesis, CodeStaleSize, CodeBadRequest, CodeState, CodeSubmit,
}

// Refusal is the reason a cycle did not produce a signature.
type Refusal struct {
	Code   string
	Detail string
}

func (r *Refusal) Error() string { return r.Code + ": " + r.Detail }

func refuse(code, format string, a ...any) *Refusal {
	return &Refusal{Code: code, Detail: fmt.Sprintf(format, a...)}
}

// Code returns the stable code of err, or "" if it is not a Refusal.
func Code(err error) string {
	var r *Refusal
	if errors.As(err, &r) {
		return r.Code
	}
	return ""
}

// Alarm reports whether the code means the server showed this witness a log
// that contradicts what it saw before, as opposed to a transient problem.
func Alarm(code string) bool { return code == CodeShrank || code == CodeDiverged }

type Config struct {
	Server    string // base URL of cairn-logd
	Key       ed25519.PrivateKey
	StatePath string // file this witness keeps what it has signed in; must be on durable storage
	// Options are the governance options the log is held to. Now and MaxSkew
	// are set from Clock and MaxSkew below, not here.
	Options governance.Options
	// Genesis, when set, pins the hash of the first entry. Without it the
	// first log this witness sees is trusted, and the state file pins it from
	// then on.
	Genesis *ledger.Hash
	// Clock, when set, makes entries dated more than MaxSkew seconds ahead of
	// it invalid, so delays cannot be satisfied by backdating-forwards.
	Clock      func() time.Time
	MaxSkew    uint64 // default 300
	HTTP       *http.Client
	MaxEntries int // default 1048576
	MaxBlob    int // default 1 MiB
	MaxBlobs   int // default 65536
	MaxBlobSum int64
}

type state struct {
	Version int    `json:"version"`
	Size    uint64 `json:"size"`
	Root    string `json:"root"`
	Head    string `json:"head"`
}

// Witness is safe for use by one goroutine at a time (Cycle holds a lock).
type Witness struct {
	cfg     Config
	pub     [32]byte
	mu      sync.Mutex
	seen    *state
	entries []ledger.Entry
	blobs   governance.MapBlobs
	blobSum int64
}

// Result describes a cycle that signed.
type Result struct {
	Size     uint64
	Root     ledger.Hash
	Complete bool // the server now holds a checkpoint that meets quorum
}

const (
	pageSize     = 1000
	maxBodyJSON  = 1 << 16
	stateVersion = 1
)

// New loads the witness state, if any. A state file that exists but cannot be
// read is an error: starting from nothing would discard the memory that makes
// a witness worth having.
func New(cfg Config) (*Witness, error) {
	if len(cfg.Key) != ed25519.PrivateKeySize {
		return nil, errors.New("witness: key must be an Ed25519 private key")
	}
	if cfg.StatePath == "" {
		return nil, errors.New("witness: a state path is required")
	}
	u := strings.TrimRight(cfg.Server, "/")
	if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
		return nil, errors.New("witness: server must be an http or https URL")
	}
	cfg.Server = u
	if cfg.MaxSkew == 0 {
		cfg.MaxSkew = 300
	}
	if cfg.MaxEntries == 0 {
		cfg.MaxEntries = 1 << 20
	}
	if cfg.MaxBlob == 0 {
		cfg.MaxBlob = 1 << 20
	}
	if cfg.MaxBlobs == 0 {
		cfg.MaxBlobs = 1 << 16
	}
	if cfg.MaxBlobSum == 0 {
		cfg.MaxBlobSum = 256 << 20
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 30 * time.Second}
	}
	hc := *cfg.HTTP
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cfg.HTTP = &hc
	w := &Witness{cfg: cfg, blobs: governance.MapBlobs{}}
	copy(w.pub[:], cfg.Key.Public().(ed25519.PublicKey))
	st, err := loadState(cfg.StatePath)
	if err != nil {
		return nil, err
	}
	w.seen = st
	return w, nil
}

// Public returns the key this witness cosigns with.
func (w *Witness) Public() [32]byte { return w.pub }

// Seen returns the size and root of the last checkpoint this witness committed
// to signing, or size 0 if none.
func (w *Witness) Seen() (uint64, ledger.Hash) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.seen == nil {
		return 0, ledger.Hash{}
	}
	r, _ := parseHash(w.seen.Root)
	return w.seen.Size, r
}

func parseHash(s string) (h ledger.Hash, ok bool) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return h, false
	}
	copy(h[:], b)
	return h, true
}

func loadState(path string) (*state, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, refuse(CodeState, "%v", err)
	}
	var st state
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&st); err != nil {
		return nil, refuse(CodeState, "%s: %v", path, err)
	}
	if dec.More() || st.Version != stateVersion || st.Size == 0 {
		return nil, refuse(CodeState, "%s is not a version %d state file", path, stateVersion)
	}
	if _, ok := parseHash(st.Root); !ok {
		return nil, refuse(CodeState, "%s: bad root", path)
	}
	if _, ok := parseHash(st.Head); !ok {
		return nil, refuse(CodeState, "%s: bad head", path)
	}
	return &st, nil
}

func saveState(path string, st *state) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (w *Witness) get(ctx context.Context, path string, max int64) ([]byte, http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, w.cfg.Server+path, nil)
	if err != nil {
		return nil, nil, err
	}
	res, err := w.cfg.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("GET %s: HTTP %d", path, res.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(res.Body, max+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(b)) > max {
		return nil, nil, fmt.Errorf("GET %s: response over %d bytes", path, max)
	}
	return b, res.Header, nil
}

// page reads up to limit entries from start and the log size the server
// reports. It decodes them but checks nothing about how they fit together.
func (w *Witness) page(ctx context.Context, start, limit int) ([]ledger.Entry, uint64, error) {
	raw, hdr, err := w.get(ctx, fmt.Sprintf("/v1/entries?start=%d&limit=%d", start, limit), int64(limit)*ledger.EntrySize)
	if err != nil {
		return nil, 0, refuse(CodeUnavailable, "%v", err)
	}
	size, err := strconv.ParseUint(hdr.Get("X-Cairn-Size"), 10, 64)
	if err != nil {
		return nil, 0, refuse(CodeUnavailable, "server sent no valid X-Cairn-Size")
	}
	if size < uint64(len(w.entries)) {
		return nil, 0, refuse(CodeShrank, "server reports %d entries; this witness has seen %d", size, len(w.entries))
	}
	if size > uint64(w.cfg.MaxEntries) {
		return nil, 0, refuse(CodeUnavailable, "server reports %d entries, over the limit of %d", size, w.cfg.MaxEntries)
	}
	if len(raw)%ledger.EntrySize != 0 {
		return nil, 0, refuse(CodeUnavailable, "entries response is not a whole number of entries")
	}
	out := make([]ledger.Entry, 0, len(raw)/ledger.EntrySize)
	for off := 0; off < len(raw); off += ledger.EntrySize {
		e, err := ledger.DecodeEntry(raw[off : off+ledger.EntrySize])
		if err != nil {
			return nil, 0, refuse(CodeInvalidLog, "%v", err)
		}
		out = append(out, e)
	}
	return out, size, nil
}

// fetch returns the log as the server shows it now (or its first want entries),
// reusing what this witness already holds. It first re-reads the last entry it
// holds, which must be identical: that entry's hash commits to everything
// before it, so a server that has changed history cannot slip past. New entries
// must then continue the chain from it.
func (w *Witness) fetch(ctx context.Context, want uint64) ([]ledger.Entry, error) {
	have := w.entries
	entries := have[:len(have):len(have)]
	if len(have) > 0 {
		got, _, err := w.page(ctx, len(have)-1, 1)
		if err != nil {
			return nil, err
		}
		if len(got) != 1 {
			return nil, refuse(CodeUnavailable, "server did not return entry %d", len(have)-1)
		}
		if got[0] != have[len(have)-1] {
			return nil, refuse(CodeDiverged, "entry %d is not the entry this witness saw", len(have)-1)
		}
	}
	for {
		got, size, err := w.page(ctx, len(entries), pageSize)
		if err != nil {
			return nil, err
		}
		if w.seen != nil && size < w.seen.Size {
			return nil, refuse(CodeShrank, "log has %d entries; this witness signed %d", size, w.seen.Size)
		}
		if want > size {
			return nil, refuse(CodeBadRequest, "size %d requested but the log has %d entries", want, size)
		}
		target := size
		if want != 0 {
			target = want
		}
		if uint64(len(entries)) >= target {
			return entries[:target], nil
		}
		if len(got) == 0 {
			return nil, refuse(CodeUnavailable, "server returned no entries at %d of %d", len(entries), size)
		}
		for _, e := range got {
			if uint64(len(entries)) >= target {
				break
			}
			if e.Height != uint64(len(entries)) {
				return nil, refuse(CodeDiverged, "entry has height %d where %d was expected", e.Height, len(entries))
			}
			if len(entries) > 0 && e.PrevHash != entries[len(entries)-1].Hash() {
				return nil, refuse(CodeDiverged, "entry %d does not follow the entry this witness saw", e.Height)
			}
			entries = append(entries, e)
		}
		if uint64(len(entries)) >= target {
			return entries[:target], nil
		}
	}
}

// blobFetcher resolves payloads from the server, checking each against the hash
// it was asked for. Anything it cannot fetch or that does not match is recorded
// so that a failed replay is reported as the server's fault, not the log's.
type blobFetcher struct {
	w   *Witness
	ctx context.Context
	err error
}

func (b *blobFetcher) Get(h ledger.Hash) ([]byte, bool) {
	if v, ok := b.w.blobs[h]; ok {
		return v, true
	}
	if len(b.w.blobs) >= b.w.cfg.MaxBlobs {
		b.err = fmt.Errorf("more than %d blobs", b.w.cfg.MaxBlobs)
		return nil, false
	}
	raw, _, err := b.w.get(b.ctx, "/v1/blob/"+hex.EncodeToString(h[:]), int64(b.w.cfg.MaxBlob))
	if err != nil {
		b.err = err
		return nil, false
	}
	if ledger.BlobHash(raw) != h {
		b.err = fmt.Errorf("blob %x does not match its hash", h[:4])
		return nil, false
	}
	if b.w.blobSum+int64(len(raw)) > b.w.cfg.MaxBlobSum {
		b.err = fmt.Errorf("blobs exceed %d bytes", b.w.cfg.MaxBlobSum)
		return nil, false
	}
	b.w.blobSum += int64(len(raw))
	b.w.blobs[h] = raw
	return raw, true
}

// Cycle checks the log and, if everything holds, signs its checkpoint for the
// first size entries (0 means the whole log) and submits the signature.
//
// The witness records what it is about to sign before it sends the signature,
// so a crash cannot leave it having signed something it does not remember.
func (w *Witness) Cycle(ctx context.Context, size uint64) (Result, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	var res Result

	entries, err := w.fetch(ctx, size)
	if err != nil {
		return res, err
	}
	n := uint64(len(entries))
	if n == 0 {
		return res, refuse(CodeUnavailable, "the log is empty")
	}

	if w.seen != nil {
		if n < w.seen.Size {
			if size == 0 {
				return res, refuse(CodeShrank, "log has %d entries; this witness signed %d", n, w.seen.Size)
			}
			return res, refuse(CodeStaleSize, "asked for size %d; this witness already signed %d", n, w.seen.Size)
		}
		root, _ := parseHash(w.seen.Root)
		head, _ := parseHash(w.seen.Head)
		if ledger.LogRoot(entries[:w.seen.Size]) != root || entries[w.seen.Size-1].Hash() != head {
			return res, refuse(CodeDiverged, "the first %d entries differ from the ones this witness signed", w.seen.Size)
		}
	}
	if w.cfg.Genesis != nil && entries[0].Hash() != *w.cfg.Genesis {
		return res, refuse(CodeWrongGenesis, "first entry is not the pinned genesis")
	}

	opt := w.cfg.Options
	if w.cfg.Clock != nil {
		opt.Now, opt.MaxSkew = uint64(w.cfg.Clock().Unix()), w.cfg.MaxSkew
	}
	bf := &blobFetcher{w: w, ctx: ctx}
	st, err := governance.Replay(entries, bf, opt)
	if err != nil {
		if bf.err != nil {
			return res, refuse(CodeUnavailable, "could not check the log: %v", bf.err)
		}
		return res, refuse(CodeInvalidLog, "%s: %v", governance.ErrCode(err), err)
	}
	w.entries = entries

	trust, _ := st.TrustForSize(n)
	if role, ok := trust.RoleOf(w.pub); !ok || role != ledger.RoleWitness {
		return res, refuse(CodeNotWitness, "key %x is not an admitted witness at size %d", w.pub[:4], n)
	}
	cp := ledger.NewCheckpoint(trust.Epoch, entries)
	res.Size, res.Root = n, cp.Root

	if w.seen == nil || n > w.seen.Size {
		next := &state{Version: stateVersion, Size: n, Root: hex.EncodeToString(cp.Root[:]), Head: hex.EncodeToString(cp.Head[:])}
		if err := saveState(w.cfg.StatePath, next); err != nil {
			return res, refuse(CodeState, "%v", err)
		}
		w.seen = next
	}

	sc := ledger.SignedCheckpoint{Checkpoint: cp}
	sc.Cosign(w.cfg.Key)
	complete, err := w.submit(ctx, n, sc.Sigs[0])
	if err != nil {
		return res, err
	}
	res.Complete = complete
	return res, nil
}

func (w *Witness) submit(ctx context.Context, size uint64, cs ledger.CheckpointSig) (bool, error) {
	body := make([]byte, 0, 104)
	body = binary.BigEndian.AppendUint64(body, size)
	body = append(body, cs.Public[:]...)
	body = append(body, cs.Signature[:]...)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.Server+"/v1/checkpoint/signature", bytes.NewReader(body))
	if err != nil {
		return false, refuse(CodeSubmit, "%v", err)
	}
	res, err := w.cfg.HTTP.Do(req)
	if err != nil {
		return false, refuse(CodeSubmit, "%v", err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(res.Body, maxBodyJSON))
	if res.StatusCode != http.StatusAccepted {
		var m map[string]string
		json.Unmarshal(b, &m)
		return false, refuse(CodeSubmit, "HTTP %d %s %s", res.StatusCode, m["error"], m["detail"])
	}
	var ok struct {
		Complete bool `json:"complete"`
	}
	if err := json.Unmarshal(b, &ok); err != nil {
		return false, refuse(CodeSubmit, "unreadable reply: %v", err)
	}
	return ok.Complete, nil
}

// Run cycles every interval until ctx ends. Refusals are reported through
// logf; the witness keeps trying, since a server that contradicts itself may
// correct itself, and nothing here ever signs without the full set of checks.
func (w *Witness) Run(ctx context.Context, interval time.Duration, logf func(format string, a ...any)) {
	var lastSize uint64
	var lastErr string
	var lastComplete bool
	for {
		res, err := w.Cycle(ctx, 0)
		if ctx.Err() != nil {
			return
		}
		switch {
		case err != nil:
			code := Code(err)
			msg := err.Error()
			if msg != lastErr {
				if Alarm(code) {
					logf("ALARM %s", msg)
				} else {
					logf("not signed: %s", msg)
				}
			}
			lastErr = msg
		case res.Size != lastSize || lastErr != "" || res.Complete != lastComplete:
			logf("signed size %d root %x (checkpoint complete: %v)", res.Size, res.Root[:6], res.Complete)
			lastSize, lastErr, lastComplete = res.Size, "", res.Complete
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}
