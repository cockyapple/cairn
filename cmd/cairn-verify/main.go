// Command cairn-verify checks a Cairn log from files, trusting nothing the
// log's operator says: the chain, the governance rules, and optionally a
// signed checkpoint against the trust configuration the log itself established.
//
//	cairn-verify -entries log.bin [-blobs DIR] [-checkpoint cp.bin] [-constitution HEX]
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
	"time"

	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
)

const (
	maxBlobBytes = 1 << 20
	maxBlobs     = 1 << 20
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, errw io.Writer) int {
	fs := flag.NewFlagSet("cairn-verify", flag.ContinueOnError)
	fs.SetOutput(errw)
	entriesPath := fs.String("entries", "", "file of concatenated 178-byte entries (required)")
	blobsDir := fs.String("blobs", "", "directory of payload blobs (needed for governance checks)")
	cpPath := fs.String("checkpoint", "", "signed checkpoint file to verify")
	constHex := fs.String("constitution", "", "expected constitution hash, 64 hex characters")
	useClock := fs.Bool("use-clock", false, "reject entries dated more than 5 minutes after this machine's clock (makes delays checkable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *entriesPath == "" {
		fmt.Fprintln(errw, "cairn-verify: -entries is required")
		return 2
	}

	raw, err := os.ReadFile(*entriesPath)
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
		if *cpPath != "" {
			fmt.Fprintln(errw, "cairn-verify: -checkpoint needs -blobs to learn the trust configuration")
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
	fmt.Fprintf(out, "ok governance: epoch %d, frozen=%t, %d activations, %d actions completed, %d open intents\n",
		st.Trust().Epoch, st.Frozen, len(st.Activations), st.Completed, len(st.OpenIntents))

	if *cpPath != "" {
		cb, err := os.ReadFile(*cpPath)
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
	return 0
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
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		m[ledger.BlobHash(b)] = b
	}
	return m, nil
}
