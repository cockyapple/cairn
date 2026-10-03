// Command cairn-verify checks a Cairn log from files, trusting nothing the
// log's operator says: the chain, the governance rules, and optionally a
// signed checkpoint against the trust configuration the log itself established.
//
//	cairn-verify -entries log.bin [-blobs DIR] [-checkpoint cp.bin] [-constitution HEX]
//	cairn-verify -entries log.bin -blobs DIR -note cp.note -origin NAME [-witness NAME=PUBHEX]...
//
// log.bin is the 178-byte entries back to back. DIR holds payload blobs as
// files; they are matched by content hash, so file names do not matter.
// Exit status: 0 verified, 1 verification failed, 2 bad usage or unreadable input.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
	"github.com/cockyapple/cairn/note"
)

const (
	maxBlobBytes = 16 << 20 // the wire format's own ceiling for one payload
	maxBlobs     = 1 << 16
	maxNoteBytes = 1 << 20 // a checkpoint or note carries at most 1024 signatures
)

// maxBlobTotal bounds what a bundle may make the verifier hold in memory.
var maxBlobTotal int64 = 256 << 20

// maxEntriesBytes bounds the entries file: 2^20 entries, the log server's default limit.
var maxEntriesBytes int64 = (1 << 20) * ledger.EntrySize

// readCapped reads a whole file but refuses one larger than max, so a hostile
// bundle cannot make the verifier allocate without limit.
func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, max)
	}
	return b, nil
}

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("cairn-verify", flag.ContinueOnError)
	fs.SetOutput(errw)
	entriesPath := fs.String("entries", "", "file of concatenated 178-byte entries (required)")
	blobsDir := fs.String("blobs", "", "directory of payload blobs (needed for governance checks)")
	cpPath := fs.String("checkpoint", "", "signed checkpoint file to verify")
	constHex := fs.String("constitution", "", "expected constitution hash, 64 hex characters")
	notePath := fs.String("note", "", "C2SP signed note to verify (needs -origin)")
	origin := fs.String("origin", "", "log origin the note must carry; validators sign under it")
	var witnesses witnessFlag
	fs.Var(&witnesses, "witness", "NAME=PUBHEX a witness key and the name it cosigns under (repeatable)")
	useClock := fs.Bool("use-clock", false, "reject entries dated more than 5 minutes after this machine's clock (makes delays checkable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *entriesPath == "" {
		fmt.Fprintln(errw, "cairn-verify: -entries is required")
		return 2
	}

	raw, err := readCapped(*entriesPath, maxEntriesBytes)
	if err != nil {
		fmt.Fprintln(errw, "cairn-verify:", err)
		return 2
	}
	if len(raw) == 0 || len(raw)%ledger.EntrySize != 0 {
		fmt.Fprintf(out, "FAIL %s: entries file is %d bytes, not a multiple of %d\n", ledger.CodeBadLength, len(raw), ledger.EntrySize)
		return 1
	}
	var encoded [][]byte
	for i := 0; i < len(raw); i += ledger.EntrySize {
		encoded = append(encoded, raw[i:i+ledger.EntrySize])
	}
	entries, err := ledger.DecodeChain(encoded)
	if err != nil {
		return failed(out, err)
	}
	fmt.Fprintf(out, "ok chain: %d entries, hashes link and signatures verify\n", len(entries))

	if *blobsDir == "" {
		fmt.Fprintln(out, "skipped governance: no -blobs given, so payloads were not checked")
		if *cpPath != "" || *notePath != "" {
			fmt.Fprintln(errw, "cairn-verify: -checkpoint and -note need -blobs to learn the trust configuration")
			return 2
		}
		return 0
	}
	blobs, err := loadBlobs(*blobsDir)
	if err != nil {
		fmt.Fprintln(errw, "cairn-verify:", err)
		return 2
	}
	var opt governance.Options
	if *useClock {
		opt.Now, opt.MaxSkew = uint64(time.Now().Unix()), 300
	}
	if *constHex != "" {
		b, err := hex.DecodeString(*constHex)
		if err != nil || len(b) != 32 {
			fmt.Fprintln(errw, "cairn-verify: -constitution must be 64 hex characters")
			return 2
		}
		var h ledger.Hash
		copy(h[:], b)
		opt.ConstitutionHash = &h
	}
	st, err := governance.Replay(entries, blobs, opt)
	if err != nil {
		return failed(out, err)
	}
	fmt.Fprintf(out, "ok governance: epoch %d, frozen=%t, %d activations, %d actions completed, %d open intents, %d revoked keys\n",
		st.Trust().Epoch, st.Frozen, len(st.Activations), st.Completed, len(st.OpenIntents), len(st.Revocations))

	if *cpPath != "" {
		cb, err := readCapped(*cpPath, maxNoteBytes)
		if err != nil {
			fmt.Fprintln(errw, "cairn-verify:", err)
			return 2
		}
		sc, err := ledger.DecodeSignedCheckpoint(cb)
		if err != nil {
			return failed(out, err)
		}
		trust, ok := st.TrustForSize(sc.Size)
		if !ok {
			fmt.Fprintf(out, "FAIL %s: checkpoint covers %d entries, the log has %d\n", ledger.CodeSizeMismatch, sc.Size, len(entries))
			return 1
		}
		if err := ledger.VerifyCheckpoint(&sc, entries[:sc.Size], &trust); err != nil {
			return failed(out, err)
		}
		fmt.Fprintf(out, "ok checkpoint: size %d, epoch %d, %d signatures meet quorum and witness threshold\n", sc.Size, sc.Epoch, len(sc.Sigs))
	}
	if *notePath != "" {
		return verifyNote(out, errw, *notePath, *origin, witnesses, st, entries)
	}
	return 0
}

func verifyNote(out, errw io.Writer, path, origin string, witnesses witnessFlag, st *governance.State, entries []ledger.Entry) int {
	if origin == "" {
		fmt.Fprintln(errw, "cairn-verify: -note needs -origin")
		return 2
	}
	raw, err := readCapped(path, maxNoteBytes)
	if err != nil {
		fmt.Fprintln(errw, "cairn-verify:", err)
		return 2
	}
	_, size, _, err := note.Peek(raw)
	if err != nil {
		return failed(out, err)
	}
	trust, ok := st.TrustForSize(size)
	if !ok || size > uint64(len(entries)) {
		fmt.Fprintf(out, "FAIL %s: note covers %d entries, the log has %d\n", ledger.CodeSizeMismatch, size, len(entries))
		return 1
	}
	res, err := note.VerifyLog(entries[:size], raw, note.Config{Origin: origin, WitnessNames: witnesses}, &trust)
	if err != nil {
		return failed(out, err)
	}
	fmt.Fprintf(out, "ok note: size %d, %d validator signatures and %d witness cosignatures meet quorum and threshold\n", res.Size, res.Validators, res.Witnesses)
	return 0
}

// witnessFlag collects repeated -witness NAME=PUBHEX values.
type witnessFlag map[[32]byte]string

func (w *witnessFlag) String() string { return "" }

func (w *witnessFlag) Set(v string) error {
	i := strings.LastIndex(v, "=")
	if i < 1 {
		return fmt.Errorf("want NAME=PUBHEX")
	}
	b, err := hex.DecodeString(v[i+1:])
	if err != nil || len(b) != 32 {
		return fmt.Errorf("public key must be 64 hex characters")
	}
	if *w == nil {
		*w = witnessFlag{}
	}
	var k [32]byte
	copy(k[:], b)
	(*w)[k] = v[:i]
	return nil
}

func failed(out io.Writer, err error) int {
	fmt.Fprintf(out, "FAIL %s: %v\n", governance.ErrCode(err), err)
	return 1
}

func loadBlobs(dir string) (governance.MapBlobs, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	m := governance.MapBlobs{}
	var total int64
	for _, f := range files {
		if !f.Type().IsRegular() {
			continue
		}
		if len(m) >= maxBlobs {
			return nil, fmt.Errorf("more than %d blobs in %s", maxBlobs, dir)
		}
		p := filepath.Join(dir, f.Name())
		fi, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if fi.Size() > maxBlobBytes {
			return nil, fmt.Errorf("%s is larger than %d bytes", f.Name(), maxBlobBytes)
		}
		if total += fi.Size(); total > maxBlobTotal {
			return nil, fmt.Errorf("the blobs in %s add up to more than %d bytes", dir, maxBlobTotal)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		m[ledger.BlobHash(b)] = b
	}
	return m, nil
}
