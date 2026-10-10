// Command cairn-verify checks a Cairn log from files, trusting nothing the
// log's operator says: the chain, the governance rules, and optionally a
// signed checkpoint against the trust configuration the log itself established.
//
//	cairn-verify -entries log.bin [-blobs DIR] [-checkpoint cp.bin] [-constitution HEX] [-genesis HEX] [-max-age 24h]
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
	maxNoteBytes = 1 << 20  // a checkpoint or note carries at most 1024 signatures
)

// maxBlobs bounds how many files a blob directory may hold.
var maxBlobs = 1 << 16

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
	genesisHex := fs.String("genesis", "", "expected hash of the first entry, 64 hex characters; pins which log this is")
	maxAge := fs.Duration("max-age", 0, "refuse a checkpoint or note whose newest covered entry is older than this by this machine's clock (e.g. 24h)")
	minTier := fs.Int("min-tier", 0, "refuse any proposal below this tier (0 to 4) whatever its target; the log cannot enforce a floor itself")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *entriesPath == "" {
		fmt.Fprintln(errw, "cairn-verify: -entries is required")
		return 2
	}
	if *minTier < 0 || *minTier > int(ledger.T4) {
		fmt.Fprintln(errw, "cairn-verify: -min-tier must be 0 to 4")
		return 2
	}

	if *maxAge < 0 || (*maxAge > 0 && *cpPath == "" && *notePath == "") {
		fmt.Fprintln(errw, "cairn-verify: -max-age must be positive and needs -checkpoint or -note")
		return 2
	}
	var pin *ledger.Hash
	if *genesisHex != "" {
		h, err := parseGenesisPin(*genesisHex)
		if err != nil {
			fmt.Fprintln(errw, "cairn-verify:", err)
			return 2
		}
		pin = &h
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
	if pin != nil {
		if got := entries[0].Hash(); got != *pin {
			fmt.Fprintf(out, "FAIL %s: the first entry is %x, not the pinned %x\n", codeWrongGenesis, got[:], pin[:])
			return 1
		}
		fmt.Fprintln(out, "ok genesis: the first entry is the one you pinned")
	}

	if *blobsDir == "" {
		fmt.Fprintln(out, "skipped governance: no -blobs given, so payloads were not checked")
		if *cpPath != "" || *notePath != "" {
			fmt.Fprintln(errw, "cairn-verify: -checkpoint and -note need -blobs to learn the trust configuration")
			return 2
		}
		return scopeNotice(out, false, false, pin != nil)
	}
	blobs, err := loadBlobs(*blobsDir)
	if err != nil {
		fmt.Fprintln(errw, "cairn-verify:", err)
		return 2
	}
	var opt governance.Options
	if *useClock {
		opt.Now, opt.MaxSkew = governance.NowSeconds(time.Now()), 300
	}
	if *minTier > 0 {
		floor := ledger.Tier(*minTier)
		opt.MinTier = func(string) ledger.Tier { return floor }
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

	var covered uint64
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
		covered = sc.Size
	}
	if *notePath != "" {
		size, code := verifyNote(out, errw, *notePath, *origin, witnesses, st, entries)
		if code != 0 {
			return code
		}
		if size > covered {
			covered = size
		}
	}
	if *maxAge > 0 {
		if covered == 0 {
			fmt.Fprintf(out, "FAIL %s: the checkpoint covers no entries, so there is nothing to date\n", codeStale)
			return 1
		}
		code, msg := checkAge(entries[covered-1], *maxAge)
		if code != "" {
			fmt.Fprintf(out, "FAIL %s: %s\n", code, msg)
			return 1
		}
		fmt.Fprintln(out, "ok age:", msg)
	}
	for _, w := range trustWarnings(st.Trust()) {
		fmt.Fprintln(out, "warn:", w)
	}
	return scopeNotice(out, true, *cpPath != "" || *notePath != "", pin != nil)
}

func verifyNote(out, errw io.Writer, path, origin string, witnesses witnessFlag, st *governance.State, entries []ledger.Entry) (uint64, int) {
	if origin == "" {
		fmt.Fprintln(errw, "cairn-verify: -note needs -origin")
		return 0, 2
	}
	raw, err := readCapped(path, maxNoteBytes)
	if err != nil {
		fmt.Fprintln(errw, "cairn-verify:", err)
		return 0, 2
	}
	_, size, _, err := note.Peek(raw)
	if err != nil {
		return 0, failed(out, err)
	}
	trust, ok := st.TrustForSize(size)
	if !ok || size > uint64(len(entries)) {
		fmt.Fprintf(out, "FAIL %s: note covers %d entries, the log has %d\n", ledger.CodeSizeMismatch, size, len(entries))
		return 0, 1
	}
	res, err := note.VerifyLog(entries[:size], raw, note.Config{Origin: origin, WitnessNames: witnesses}, &trust)
	if err != nil {
		return 0, failed(out, err)
	}
	fmt.Fprintf(out, "ok note: size %d, %d validator signatures and %d witness cosignatures meet quorum and threshold\n", res.Size, res.Validators, res.Witnesses)
	return res.Size, 0
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
	seen := 0
	for _, f := range files {
		if !f.Type().IsRegular() {
			continue
		}
		if seen++; seen > maxBlobs {
			return nil, fmt.Errorf("more than %d blobs in %s", maxBlobs, dir)
		}
		p := filepath.Join(dir, f.Name())
		b, err := readCapped(p, maxBlobBytes)
		if err != nil {
			return nil, err
		}
		if total += int64(len(b)); total > maxBlobTotal {
			return nil, fmt.Errorf("the blobs add up to more than %d bytes", maxBlobTotal)
		}
		m[ledger.BlobHash(b)] = b
	}
	return m, nil
}

// scopeNotice ends every successful run by saying what a pass does not show,
// so a green result is not read as a verdict on the agent.
func scopeNotice(out io.Writer, governed, anchored, pinned bool) int {
	const tail = " That is not proof of what any agent did, that its payloads are true, or that any agent is safe."
	switch {
	case governed && anchored && pinned:
		fmt.Fprintln(out, "note: this log followed its governance rules, starts at the genesis you pinned, and carries signatures that meet its own rules."+tail)
	case governed && anchored:
		fmt.Fprintln(out, "note: this log followed its governance rules and carries signatures that meet its own rules, but without a genesis you pinned yourself that does not show this is the log you meant to check."+tail)
	case governed && pinned:
		fmt.Fprintln(out, "note: this log followed its governance rules and starts at the genesis you pinned, but no checkpoint or note was verified, so no signed head vouches for how far it runs."+tail)
	case governed:
		fmt.Fprintln(out, "note: this log is internally consistent and followed its governance rules, but no checkpoint or note was verified and no genesis was pinned, so it may be a different log from the one you meant to check."+tail)
	default:
		fmt.Fprintln(out, "note: only the chain's hashes and signatures were checked. That is not proof of lawful governance, of what any agent did, or that any agent is safe.")
	}
	return 0
}
