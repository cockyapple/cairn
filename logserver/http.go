package logserver

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/cockyapple/cairn/ledger"
)

const maxEntriesPerRead = 1000

// Handler serves the log over HTTP. All bodies are binary except status and
// errors, which are JSON. The log is public data: bind it to a private address
// or put TLS and authentication in front of it.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/append", s.hAppend)
	mux.HandleFunc("POST /v1/checkpoint/signature", s.hSignature)
	mux.HandleFunc("GET /v1/checkpoint/body", s.hBody)
	mux.HandleFunc("GET /v1/checkpoint", s.hCheckpoint)
	mux.HandleFunc("GET /v1/status", s.hStatus)
	mux.HandleFunc("GET /v1/entries", s.hEntries)
	mux.HandleFunc("GET /v1/blob/{hash}", s.hBlob)
	mux.HandleFunc("GET /v1/proof/inclusion", s.hInclusion)
	mux.HandleFunc("GET /v1/proof/consistency", s.hConsistency)
	return mux
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeReject(w http.ResponseWriter, r *Reject) {
	if r.Status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "60")
	}
	writeJSON(w, r.Status, map[string]string{"error": r.Code, "detail": r.Detail})
}

func writeBin(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(b)
}

func (s *Server) readBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, bool) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
	if err != nil {
		writeReject(w, reject(http.StatusRequestEntityTooLarge, CodeBlobTooLarge, "request body too large"))
		return nil, false
	}
	return b, true
}

func (s *Server) hAppend(w http.ResponseWriter, r *http.Request) {
	max := int64(ledger.EntrySize+1) + int64(maxBlobsPerAppend)*int64(s.cfg.Limits.MaxBlobBytes+4)
	body, ok := s.readBody(w, r, max)
	if !ok {
		return
	}
	h, rj := s.Append(body)
	if rj != nil {
		writeReject(w, rj)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"hash": hex.EncodeToString(h[:])})
}

// A signature request is size (8 bytes, big endian) || public key (32) || signature (64).
func (s *Server) hSignature(w http.ResponseWriter, r *http.Request) {
	body, ok := s.readBody(w, r, 104)
	if !ok {
		return
	}
	if len(body) != 104 {
		writeReject(w, reject(http.StatusBadRequest, CodeMalformed, "send size(8) || public key(32) || signature(64)"))
		return
	}
	var pub [32]byte
	var sig [64]byte
	copy(pub[:], body[8:40])
	copy(sig[:], body[40:])
	complete, rj := s.AddSignature(binary.BigEndian.Uint64(body[:8]), pub, sig)
	if rj != nil {
		writeReject(w, rj)
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]bool{"complete": complete})
}

func queryInt(r *http.Request, name string, def int) (int, bool) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, true
	}
	n, err := strconv.Atoi(v)
	return n, err == nil && n >= 0
}

func badQuery(w http.ResponseWriter) {
	writeReject(w, reject(http.StatusBadRequest, CodeMalformed, "bad query parameter"))
}

func (s *Server) hBody(w http.ResponseWriter, r *http.Request) {
	size, ok := queryInt(r, "size", 0)
	if !ok {
		badQuery(w)
		return
	}
	b, rj := s.CheckpointBody(uint64(size))
	if rj != nil {
		writeReject(w, rj)
		return
	}
	writeBin(w, b)
}

func (s *Server) hCheckpoint(w http.ResponseWriter, r *http.Request) {
	b, ok := s.Checkpoint()
	if !ok {
		writeReject(w, reject(http.StatusNotFound, CodeNotFound, "no checkpoint has met quorum yet"))
		return
	}
	writeBin(w, b)
}

func (s *Server) hStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.Status())
}

func (s *Server) hEntries(w http.ResponseWriter, r *http.Request) {
	start, ok1 := queryInt(r, "start", 0)
	limit, ok2 := queryInt(r, "limit", 100)
	if !ok1 || !ok2 {
		badQuery(w)
		return
	}
	if limit > maxEntriesPerRead {
		limit = maxEntriesPerRead
	}
	b, n := s.Entries(start, limit)
	w.Header().Set("X-Cairn-Size", strconv.Itoa(n))
	writeBin(w, b)
}

func (s *Server) hBlob(w http.ResponseWriter, r *http.Request) {
	raw, err := hex.DecodeString(r.PathValue("hash"))
	if err != nil || len(raw) != 32 {
		badQuery(w)
		return
	}
	var h ledger.Hash
	copy(h[:], raw)
	b, ok := s.Blob(h)
	if !ok {
		writeReject(w, reject(http.StatusNotFound, CodeNotFound, "no such blob"))
		return
	}
	writeBin(w, b)
}

func (s *Server) hInclusion(w http.ResponseWriter, r *http.Request) {
	i, ok1 := queryInt(r, "index", -1)
	n, ok2 := queryInt(r, "size", 0)
	if !ok1 || !ok2 {
		badQuery(w)
		return
	}
	b, rj := s.InclusionProof(i, n)
	if rj != nil {
		writeReject(w, rj)
		return
	}
	writeBin(w, b)
}

func (s *Server) hConsistency(w http.ResponseWriter, r *http.Request) {
	a, ok1 := queryInt(r, "first", 0)
	b, ok2 := queryInt(r, "second", 0)
	if !ok1 || !ok2 {
		badQuery(w)
		return
	}
	p, rj := s.ConsistencyProof(a, b)
	if rj != nil {
		writeReject(w, rj)
		return
	}
	writeBin(w, p)
}
