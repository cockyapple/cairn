package review

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
)

// maxBlobTotal bounds what a bundle may make a reader hold in memory.
var maxBlobTotal int64 = 256 << 20

const (
	maxBlobBytes = 16 << 20 // the wire format's own ceiling for one payload
	maxBlobs     = 1 << 16
)

// maxLogBytes bounds log.bin: 2^20 entries, the log server's default limit.
var maxLogBytes int64 = (1 << 20) * ledger.EntrySize

// SaveBundle writes the layout cairn-verify reads: dir/log.bin holds the
// entries back to back, dir/blobs/ holds one file per blob named by its hash.
func SaveBundle(dir string, entries []ledger.Entry, blobs governance.MapBlobs) error {
	if err := os.MkdirAll(filepath.Join(dir, "blobs"), 0o755); err != nil {
		return err
	}
	var raw []byte
	for i := range entries {
		raw = append(raw, entries[i].Encode()...)
	}
	if err := os.WriteFile(filepath.Join(dir, "log.bin"), raw, 0o644); err != nil {
		return err
	}
	for h, b := range blobs {
		if err := os.WriteFile(filepath.Join(dir, "blobs", hex.EncodeToString(h[:])), b, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// LoadBundle reads a bundle. Blobs are matched by content hash, never by file
// name, and the chain is verified as it is decoded.
func LoadBundle(dir string) ([]ledger.Entry, governance.MapBlobs, error) {
	f, err := os.Open(filepath.Join(dir, "log.bin"))
	if err != nil {
		return nil, nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxLogBytes+1))
	f.Close()
	if err != nil {
		return nil, nil, err
	}
	if int64(len(raw)) > maxLogBytes {
		return nil, nil, fmt.Errorf("log.bin is larger than %d bytes", maxLogBytes)
	}
	if len(raw) == 0 || len(raw)%ledger.EntrySize != 0 {
		return nil, nil, fmt.Errorf("log.bin is %d bytes, not a multiple of %d", len(raw), ledger.EntrySize)
	}
	var enc [][]byte
	for i := 0; i < len(raw); i += ledger.EntrySize {
		enc = append(enc, raw[i:i+ledger.EntrySize])
	}
	entries, err := ledger.DecodeChain(enc)
	if err != nil {
		return nil, nil, err
	}
	files, err := os.ReadDir(filepath.Join(dir, "blobs"))
	if err != nil {
		return nil, nil, err
	}
	blobs := governance.MapBlobs{}
	var total int64
	seen := 0
	for _, f := range files {
		if !f.Type().IsRegular() {
			continue
		}
		if seen++; seen > maxBlobs {
			return nil, nil, fmt.Errorf("more than %d blobs", maxBlobs)
		}
		p := filepath.Join(dir, "blobs", f.Name())
		b, err := readCapped(p)
		if err != nil {
			return nil, nil, err
		}
		if total += int64(len(b)); total > maxBlobTotal {
			return nil, nil, fmt.Errorf("the blobs add up to more than %d bytes", maxBlobTotal)
		}
		blobs[ledger.BlobHash(b)] = b
	}
	return entries, blobs, nil
}

// readCapped opens a file once and reads at most maxBlobBytes of it, so a file
// that grows or is swapped after a size check cannot make the loader hold more.
func readCapped(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxBlobBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBlobBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(p), maxBlobBytes)
	}
	return b, nil
}
