// Package logserver is the append-only log server: the one place that decides
// the order of entries. It admits an entry only if the whole log would still
// replay cleanly with it, writes it to disk before acknowledging, and
// aggregates checkpoint signatures from the validators and witnesses without
// ever holding a signing key. It is outside the verifier budget on purpose:
// nothing here needs to be trusted, because everything it serves can be
// re-checked with cairn-verify.
package logserver

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
)

// Stable codes this package adds to the ledger and governance codes.
const (
	CodeMalformed      = "malformed_request"
	CodeNotGenesisAuth = "not_genesis_author"
	CodeUninitialised  = "log_uninitialised"
	CodeRateLimited    = "rate_limited"
	CodeBlobTooLarge   = "blob_too_large"
	CodeTooManyBlobs   = "too_many_blobs"
	CodeStoreFull      = "store_full"
	CodeLogFull        = "log_full"
	CodeLogBroken      = "log_broken"
	CodeOutOfRange     = "out_of_range"
	CodeNotFound       = "not_found"
)

// AllCodes lists the codes this package defines; a test requires
// docs/LOG-SERVER.md to list the same ones.
var AllCodes = []string{
	CodeMalformed, CodeNotGenesisAuth, CodeUninitialised, CodeRateLimited,
	CodeBlobTooLarge, CodeTooManyBlobs, CodeStoreFull, CodeLogFull, CodeLogBroken,
	CodeOutOfRange, CodeNotFound,
}

const (
	maxBlobsPerAppend = 16
	maxPendingSizes   = 16
	defaultSkew       = 300
)

// Limits bound what one author, and the log as a whole, may consume. The
// defaults for the store match what cairn-verify will agree to load, so a log
// this server accepts is one an outside verifier can still check.
type Limits struct {
	Window        time.Duration // default 1 minute
	Default       int           // submissions per key per window; 0 means unlimited
	PerRole       map[ledger.Role]int
	MaxBlobBytes  int   // default 1 MiB
	MaxStoreBytes int64 // default 256 MiB
	MaxBlobs      int   // default 65536
	MaxEntries    int   // default 1048576
}

type Config struct {
	Dir string
	// GenesisAuthor is the only key that may write the first entry. Without it
	// an empty log refuses everything, so a stranger cannot claim it first.
	GenesisAuthor [32]byte
	// Options are the governance options the log is held to (constitution
	// hash, tier floors). The server never sets Now; it checks the clock itself.
	Options governance.Options
	MaxSkew uint64 // seconds an entry may be dated ahead of the server clock; default 300
	Limits  Limits
	Now     func() time.Time
}

// Reject is a refused request with the HTTP status and stable code that
// describe it.
type Reject struct {
	Status int
	Code   string
	Detail string
}

func (r *Reject) Error() string {
	if r.Detail == "" {
		return r.Code
	}
	return r.Code + ": " + r.Detail
}

func reject(status int, code, detail string) *Reject { return &Reject{status, code, detail} }

type window struct {
	start time.Time
	n     int
}

type Server struct {
	cfg Config

	mu        sync.RWMutex
	entries   []ledger.Entry
	leaves    [][]byte
	blobs     governance.MapBlobs
	blobBytes int64
	st        *governance.State
	broken    error
	efile     *os.File
	elen      int64
	rate      map[[32]byte]*window
	pending   map[uint64]map[[32]byte][64]byte
	latest    *ledger.SignedCheckpoint
}

// Open loads (or creates) the log in cfg.Dir and checks all of it before
// serving: a log that does not replay, a blob that does not match its name, or
// a checkpoint that does not verify stops the server rather than being served.
// A torn final entry from a crash is cut off, since it was never acknowledged.
func Open(cfg Config) (*Server, error) {
	if cfg.Dir == "" {
		return nil, fmt.Errorf("logserver: no directory")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MaxSkew == 0 {
		cfg.MaxSkew = defaultSkew
	}
	l := &cfg.Limits
	if l.Window <= 0 {
		l.Window = time.Minute
	}
	if l.MaxBlobBytes <= 0 {
		l.MaxBlobBytes = 1 << 20
	}
	if l.MaxStoreBytes <= 0 {
		l.MaxStoreBytes = 256 << 20
	}
	if l.MaxBlobs <= 0 {
		l.MaxBlobs = 1 << 16
	}
	if l.MaxEntries <= 0 {
		l.MaxEntries = 1 << 20
	}
	if err := os.MkdirAll(filepath.Join(cfg.Dir, "blobs"), 0o700); err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, blobs: governance.MapBlobs{}, rate: map[[32]byte]*window{}, pending: map[uint64]map[[32]byte][64]byte{}}
	f, err := os.OpenFile(filepath.Join(cfg.Dir, "entries.bin"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	s.efile = f
	raw, err := s.trimTail()
	if err == nil {
		err = s.recoverStaging(len(raw) / ledger.EntrySize)
	}
	if err == nil {
		err = s.loadBlobs()
	}
	if err == nil {
		err = s.loadEntries(raw)
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	if err := s.loadCheckpoint(); err != nil {
		f.Close()
		return nil, err
	}
	return s, nil
}

func (s *Server) Close() error { return s.efile.Close() }

func (s *Server) loadBlobs() error {
	dir := filepath.Join(s.cfg.Dir, "blobs")
	des, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, de := range des {
		name := de.Name()
		if strings.HasSuffix(name, ".tmp") {
			os.Remove(filepath.Join(dir, name))
			continue
		}
		raw, err := hex.DecodeString(name)
		if err != nil || len(raw) != 32 || strings.ToLower(name) != name {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		var h ledger.Hash
		copy(h[:], raw)
		if ledger.BlobHash(b) != h {
			return fmt.Errorf("logserver: blob %s does not match its name", name)
		}
		if len(b) > s.cfg.Limits.MaxBlobBytes || len(s.blobs) >= s.cfg.Limits.MaxBlobs || s.blobBytes+int64(len(b)) > s.cfg.Limits.MaxStoreBytes {
			return fmt.Errorf("logserver: blob store exceeds the configured limits")
		}
		s.blobs[h] = b
		s.blobBytes += int64(len(b))
	}
	return nil
}

// trimTail reads the entry file and cuts off a torn final entry.
func (s *Server) trimTail() ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(s.cfg.Dir, "entries.bin"))
	if err != nil {
		return nil, err
	}
	if rem := len(raw) % ledger.EntrySize; rem != 0 {
		raw = raw[:len(raw)-rem]
		if err := s.efile.Truncate(int64(len(raw))); err != nil {
			return nil, err
		}
		if err := s.efile.Sync(); err != nil {
			return nil, err
		}
	}
	return raw, nil
}

// recoverStaging settles an append that was interrupted. New blobs are staged
// with the height of the entry they belong to, the entry is made durable, and
// only then are the blobs moved into blobs/. If the log now has that entry the
// move is finished; if not, the staged blobs belong to an append that was never
// acknowledged and are dropped, so a crash cannot leave unreferenced blobs
// behind to eat the store cap.
func (s *Server) recoverStaging(entries int) error {
	stage := filepath.Join(s.cfg.Dir, "staging")
	hb, err := os.ReadFile(filepath.Join(stage, "height"))
	if os.IsNotExist(err) {
		return os.RemoveAll(stage)
	}
	if err != nil {
		return err
	}
	if h, perr := strconv.ParseUint(string(hb), 10, 64); perr == nil && h < uint64(entries) {
		des, err := os.ReadDir(stage)
		if err != nil {
			return err
		}
		for _, de := range des {
			if raw, err := hex.DecodeString(de.Name()); err != nil || len(raw) != 32 {
				continue
			}
			if err := os.Rename(filepath.Join(stage, de.Name()), filepath.Join(s.cfg.Dir, "blobs", de.Name())); err != nil {
				return err
			}
		}
		if err := syncDir(filepath.Join(s.cfg.Dir, "blobs")); err != nil {
			return err
		}
	}
	return os.RemoveAll(stage)
}

func (s *Server) loadEntries(raw []byte) error {
	s.elen = int64(len(raw))
	if len(raw) == 0 {
		return nil
	}
	for i := 0; i < len(raw); i += ledger.EntrySize {
		e, err := ledger.DecodeEntry(raw[i : i+ledger.EntrySize])
		if err != nil {
			return fmt.Errorf("logserver: stored entry %d: %w", i/ledger.EntrySize, err)
		}
		s.entries = append(s.entries, e)
		s.leaves = append(s.leaves, e.Encode())
	}
	st, err := governance.Replay(s.entries, s.blobs, s.cfg.Options)
	if err != nil {
		return fmt.Errorf("logserver: stored log does not replay: %w", err)
	}
	s.st = st
	return nil
}

func (s *Server) loadCheckpoint() error {
	b, err := os.ReadFile(filepath.Join(s.cfg.Dir, "checkpoint.bin"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	sc, err := ledger.DecodeSignedCheckpoint(b)
	if err != nil {
		return fmt.Errorf("logserver: stored checkpoint: %w", err)
	}
	if s.st == nil || sc.Size == 0 || sc.Size > uint64(len(s.entries)) {
		return fmt.Errorf("logserver: stored checkpoint does not fit the log")
	}
	trust, _ := s.st.TrustForSize(sc.Size)
	if err := ledger.VerifyCheckpoint(&sc, s.entries[:sc.Size], &trust); err != nil {
		return fmt.Errorf("logserver: stored checkpoint does not verify: %w", err)
	}
	s.latest = &sc
	return nil
}

// allow counts one submission by key and reports whether it is within budget.
// It runs only after the signature has been checked, so nobody can spend
// another key's budget by claiming it.
func (s *Server) allow(pub [32]byte, role ledger.Role) *Reject {
	limit := s.cfg.Limits.Default
	if v, ok := s.cfg.Limits.PerRole[role]; ok {
		limit = v
	}
	if limit <= 0 {
		return nil
	}
	now := s.cfg.Now()
	w := s.rate[pub]
	if w == nil || now.Sub(w.start) >= s.cfg.Limits.Window {
		w = &window{start: now}
		s.rate[pub] = w
	}
	if w.n >= limit {
		return reject(http.StatusTooManyRequests, CodeRateLimited, "this key has used its submissions for the current window")
	}
	w.n++
	return nil
}

func (s *Server) failed() *Reject {
	if s.broken != nil {
		return reject(http.StatusServiceUnavailable, CodeLogBroken, "storage failed; the log is read-only until it is restarted and rechecked")
	}
	return nil
}

// EncodeAppend builds the body of an append request: the encoded entry, a blob
// count, then each blob with a four-byte length. One of the blobs must be the
// entry's payload.
func EncodeAppend(e ledger.Entry, blobs ...[]byte) []byte {
	out := append([]byte(nil), e.Encode()...)
	out = append(out, byte(len(blobs)))
	for _, b := range blobs {
		out = append(out, byte(len(b)>>24), byte(len(b)>>16), byte(len(b)>>8), byte(len(b)))
		out = append(out, b...)
	}
	return out
}

func (s *Server) parseAppend(body []byte) (ledger.Entry, [][]byte, *Reject) {
	var e ledger.Entry
	if len(body) < ledger.EntrySize+1 {
		return e, nil, reject(http.StatusBadRequest, CodeMalformed, "request is shorter than an entry and a blob count")
	}
	e, err := ledger.DecodeEntry(body[:ledger.EntrySize])
	if err != nil {
		return e, nil, reject(http.StatusBadRequest, ledger.ErrCode(err), err.Error())
	}
	n := int(body[ledger.EntrySize])
	if n == 0 || n > maxBlobsPerAppend {
		return e, nil, reject(http.StatusBadRequest, CodeTooManyBlobs, fmt.Sprintf("send between 1 and %d blobs", maxBlobsPerAppend))
	}
	rest := body[ledger.EntrySize+1:]
	var blobs [][]byte
	for i := 0; i < n; i++ {
		if len(rest) < 4 {
			return e, nil, reject(http.StatusBadRequest, CodeMalformed, "truncated blob length")
		}
		n32 := uint64(binary.BigEndian.Uint32(rest))
		rest = rest[4:]
		if n32 > uint64(s.cfg.Limits.MaxBlobBytes) {
			return e, nil, reject(http.StatusRequestEntityTooLarge, CodeBlobTooLarge, "a blob exceeds the size limit")
		}
		l := int(n32)
		if l > len(rest) {
			return e, nil, reject(http.StatusBadRequest, CodeMalformed, "truncated blob")
		}
		blobs = append(blobs, rest[:l])
		rest = rest[l:]
	}
	if len(rest) != 0 {
		return e, nil, reject(http.StatusBadRequest, CodeMalformed, "trailing bytes after the last blob")
	}
	return e, blobs, nil
}

// Append admits one entry. The checks run in a fixed order: who the author
// is, then the signature, then the author is charged against its rate limit
// (so a refused submission still costs the signer, and nobody can spend a key
// they cannot sign with), then position, clock, caps and finally the full replay.
func (s *Server) Append(body []byte) (ledger.Hash, *Reject) {
	e, blobs, rj := s.parseAppend(body)
	if rj != nil {
		return ledger.Hash{}, rj
	}
	found := false
	for _, b := range blobs {
		if ledger.BlobHash(b) == e.PayloadHash {
			found = true
			break
		}
	}
	if !found {
		return ledger.Hash{}, reject(http.StatusBadRequest, ledger.CodeBadPayload, "none of the blobs hashes to the entry's payload_hash")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if rj := s.failed(); rj != nil {
		return ledger.Hash{}, rj
	}
	n := len(s.entries)
	role := ledger.Role(0)
	if n == 0 {
		if s.cfg.GenesisAuthor == ([32]byte{}) {
			return ledger.Hash{}, reject(http.StatusServiceUnavailable, CodeUninitialised, "no genesis author is configured")
		}
		if e.Author != s.cfg.GenesisAuthor {
			return ledger.Hash{}, reject(http.StatusForbidden, CodeNotGenesisAuth, "only the configured genesis author may start this log")
		}
	} else {
		trust := s.st.Trust()
		r, ok := trust.RoleOf(e.Author)
		if !ok {
			return ledger.Hash{}, reject(http.StatusForbidden, governance.CodeUnauthorizedAuthor, "author is not in the trust configuration")
		}
		role = r
	}
	if !e.VerifySignature() {
		return ledger.Hash{}, reject(http.StatusBadRequest, ledger.CodeBadSignature, "signature does not verify")
	}
	if n > 0 {
		if rj := s.allow(e.Author, role); rj != nil {
			return ledger.Hash{}, rj
		}
	}
	if e.Height != uint64(n) {
		return ledger.Hash{}, reject(http.StatusConflict, ledger.CodeBadHeight, fmt.Sprintf("the log is at %d entries; sign height %d", n, n))
	}
	if n > 0 && e.PrevHash != s.entries[n-1].Hash() {
		return ledger.Hash{}, reject(http.StatusConflict, ledger.CodeBadPrevHash, "prev_hash is not the current head")
	}
	if e.Time > uint64(s.cfg.Now().Unix())+s.cfg.MaxSkew {
		return ledger.Hash{}, reject(http.StatusUnprocessableEntity, governance.CodeFutureEntry, "entry is dated ahead of the server clock")
	}
	if n >= s.cfg.Limits.MaxEntries {
		return ledger.Hash{}, reject(http.StatusInsufficientStorage, CodeLogFull, "the log has reached its entry limit")
	}

	var fresh []ledger.Hash
	seen := map[ledger.Hash]bool{}
	var added int64
	for _, b := range blobs {
		h := ledger.BlobHash(b)
		if _, ok := s.blobs[h]; ok || seen[h] {
			continue
		}
		seen[h] = true
		fresh = append(fresh, h)
		added += int64(len(b))
	}
	if len(s.blobs)+len(fresh) > s.cfg.Limits.MaxBlobs || s.blobBytes+added > s.cfg.Limits.MaxStoreBytes {
		return ledger.Hash{}, reject(http.StatusInsufficientStorage, CodeStoreFull, "the blob store is full")
	}

	byHash := map[ledger.Hash][]byte{}
	for _, b := range blobs {
		byHash[ledger.BlobHash(b)] = b
	}
	for _, h := range fresh {
		s.blobs[h] = byHash[h]
	}
	cand := make([]ledger.Entry, n+1)
	copy(cand, s.entries)
	cand[n] = e
	st, err := governance.Replay(cand, s.blobs, s.cfg.Options)
	if err != nil {
		for _, h := range fresh {
			delete(s.blobs, h)
		}
		return ledger.Hash{}, reject(http.StatusUnprocessableEntity, governance.ErrCode(err), err.Error())
	}

	if err := s.persist(&e, fresh, byHash); err != nil {
		for _, h := range fresh {
			delete(s.blobs, h)
		}
		return ledger.Hash{}, reject(http.StatusServiceUnavailable, CodeLogBroken, "could not write the entry to disk")
	}
	s.entries, s.st = cand, st
	s.leaves = append(s.leaves, e.Encode())
	s.blobBytes += added
	return e.Hash(), nil
}

// persist makes one accepted entry durable: stage the new blobs, append and
// sync the entry (the commit point), then move the blobs into place. A crash
// at any step is settled by recoverStaging on the next start.
func (s *Server) persist(e *ledger.Entry, fresh []ledger.Hash, byHash map[ledger.Hash][]byte) error {
	dir := filepath.Join(s.cfg.Dir, "blobs")
	stage := filepath.Join(s.cfg.Dir, "staging")
	if len(fresh) > 0 {
		if err := os.MkdirAll(stage, 0o700); err != nil {
			return err
		}
		err := writeFileSync(filepath.Join(stage, "height"), []byte(strconv.FormatUint(e.Height, 10)))
		for i := 0; err == nil && i < len(fresh); i++ {
			err = writeFileSync(filepath.Join(stage, hex.EncodeToString(fresh[i][:])), byHash[fresh[i]])
		}
		if err == nil {
			err = syncDir(stage)
		}
		if err != nil {
			os.RemoveAll(stage)
			return err
		}
	}
	if _, err := s.efile.WriteAt(e.Encode(), s.elen); err != nil {
		if terr := s.efile.Truncate(s.elen); terr != nil {
			s.broken = terr
		}
		os.RemoveAll(stage)
		return err
	}
	if err := s.efile.Sync(); err != nil {
		s.broken = err
		return err
	}
	s.elen += ledger.EntrySize
	for _, h := range fresh {
		name := hex.EncodeToString(h[:])
		if err := os.Rename(filepath.Join(stage, name), filepath.Join(dir, name)); err != nil {
			s.broken = err
			return nil
		}
	}
	if len(fresh) > 0 {
		if err := syncDir(dir); err != nil {
			s.broken = err
			return nil
		}
		os.RemoveAll(stage)
	}
	return nil
}

func writeFileSync(path string, b []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
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
	return os.Rename(tmp, path)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// Status is a snapshot of the log's head.
type Status struct {
	Entries        int    `json:"entries"`
	Root           string `json:"root"`
	Head           string `json:"head"`
	Epoch          uint64 `json:"epoch"`
	Frozen         bool   `json:"frozen"`
	CheckpointSize uint64 `json:"checkpoint_size"`
}

func (s *Server) Status() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st := Status{Entries: len(s.entries)}
	if len(s.entries) > 0 {
		root := ledger.MerkleRoot(s.leaves)
		head := s.entries[len(s.entries)-1].Hash()
		st.Root, st.Head = hex.EncodeToString(root[:]), hex.EncodeToString(head[:])
		st.Epoch, st.Frozen = s.st.Trust().Epoch, s.st.Frozen
	}
	if s.latest != nil {
		st.CheckpointSize = s.latest.Size
	}
	return st
}

// Entries returns up to limit encoded entries starting at start, and the log size.
func (s *Server) Entries(start, limit int) ([]byte, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := len(s.entries)
	if start < 0 || start >= n || limit <= 0 {
		return nil, n
	}
	end := start + limit
	if end > n || end < start {
		end = n
	}
	var out bytes.Buffer
	for _, l := range s.leaves[start:end] {
		out.Write(l)
	}
	return out.Bytes(), n
}

func (s *Server) Blob(h ledger.Hash) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, ok := s.blobs[h]
	return b, ok
}

func hashesBytes(hs []ledger.Hash) []byte {
	out := make([]byte, 0, 32*len(hs))
	for _, h := range hs {
		out = append(out, h[:]...)
	}
	return out
}

// InclusionProof proves entry index is in the tree of the first size entries.
func (s *Server) InclusionProof(index, size int) ([]byte, *Reject) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if size < 1 || size > len(s.entries) || index < 0 || index >= size {
		return nil, reject(http.StatusBadRequest, CodeOutOfRange, "need 0 <= index < size <= log size")
	}
	p, err := ledger.InclusionProof(s.leaves[:size], index)
	if err != nil {
		return nil, reject(http.StatusBadRequest, CodeOutOfRange, err.Error())
	}
	return hashesBytes(p), nil
}

// ConsistencyProof proves the first-entry tree is a prefix of the second-entry tree.
func (s *Server) ConsistencyProof(first, second int) ([]byte, *Reject) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if first < 1 || first > second || second > len(s.entries) {
		return nil, reject(http.StatusBadRequest, CodeOutOfRange, "need 1 <= first <= second <= log size")
	}
	p, err := ledger.ConsistencyProof(s.leaves[:second], first)
	if err != nil {
		return nil, reject(http.StatusBadRequest, CodeOutOfRange, err.Error())
	}
	return hashesBytes(p), nil
}

// CheckpointBody is the 81-byte body validators and witnesses sign for the
// first size entries (0 means the whole log), under the trust configuration
// in force at that size.
func (s *Server) CheckpointBody(size uint64) ([]byte, *Reject) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	cp, _, rj := s.checkpointAt(size)
	if rj != nil {
		return nil, rj
	}
	return cp.Body(), nil
}

func (s *Server) checkpointAt(size uint64) (ledger.Checkpoint, ledger.TrustConfig, *Reject) {
	var cp ledger.Checkpoint
	if size == 0 {
		size = uint64(len(s.entries))
	}
	if size == 0 || size > uint64(len(s.entries)) {
		return cp, ledger.TrustConfig{}, reject(http.StatusBadRequest, CodeOutOfRange, "need 1 <= size <= log size")
	}
	trust, _ := s.st.TrustForSize(size)
	return ledger.NewCheckpoint(trust.Epoch, s.entries[:size]), trust, nil
}

// AddSignature records one validator or witness signature over the checkpoint
// for the first size entries. When the signatures held for that size meet the
// quorum and the witness threshold, the result becomes the served checkpoint.
// Partial sets are kept in memory only; a signer whose set was lost to a
// restart simply signs again.
func (s *Server) AddSignature(size uint64, pub [32]byte, sig [64]byte) (complete bool, rj *Reject) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rj := s.failed(); rj != nil {
		return false, rj
	}
	cp, trust, rj := s.checkpointAt(size)
	if rj != nil {
		return false, rj
	}
	role, ok := trust.RoleOf(pub)
	if !ok || (role != ledger.RoleValidator && role != ledger.RoleWitness) {
		return false, reject(http.StatusForbidden, ledger.CodeUnknownSigner, "key is not a validator or witness for this size")
	}
	if !cp.VerifySig(pub, sig) {
		return false, reject(http.StatusBadRequest, ledger.CodeBadSignature, "signature does not verify")
	}
	if rj := s.allow(pub, role); rj != nil {
		return false, rj
	}
	size = cp.Size
	set := s.pending[size]
	if set == nil {
		if len(s.pending) >= maxPendingSizes {
			var oldest uint64
			first := true
			for k := range s.pending {
				if first || k < oldest {
					oldest, first = k, false
				}
			}
			delete(s.pending, oldest)
		}
		set = map[[32]byte][64]byte{}
		s.pending[size] = set
	}
	set[pub] = sig

	sc := ledger.SignedCheckpoint{Checkpoint: cp}
	keys := make([][32]byte, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })
	for _, k := range keys {
		sc.Sigs = append(sc.Sigs, ledger.CheckpointSig{Public: k, Signature: set[k]})
	}
	if ledger.VerifyCheckpoint(&sc, s.entries[:size], &trust) != nil {
		return false, nil
	}
	better := s.latest == nil || size > s.latest.Size || (size == s.latest.Size && len(sc.Sigs) > len(s.latest.Sigs))
	if better {
		if err := writeFileSync(filepath.Join(s.cfg.Dir, "checkpoint.bin"), sc.Encode()); err != nil {
			s.broken = err
			return false, reject(http.StatusServiceUnavailable, CodeLogBroken, "could not store the checkpoint")
		}
		s.latest = &sc
	}
	for k := range s.pending {
		if k < size {
			delete(s.pending, k)
		}
	}
	return true, nil
}

// Checkpoint returns the newest fully signed checkpoint, if there is one.
func (s *Server) Checkpoint() ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.latest == nil {
		return nil, false
	}
	return s.latest.Encode(), true
}
