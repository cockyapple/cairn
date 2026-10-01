// Command cairn-review writes a static HTML page for reviewing the proposals in
// a Cairn bundle: diffs, eval deltas, votes and what the rules require.
//
//	cairn-review -bundle DIR -out review.html [-checkpoint cp.bin] [-constitution HEX]
//
// The page is produced offline from files and contains no script. If the log
// does not verify, the page says so and shows nothing else.
// Exit status: 0 written, 1 the log did not verify (page still written), 2 bad usage.
package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
	"github.com/cockyapple/cairn/review"
)

func main() { os.Exit(run(os.Args[1:], os.Stderr)) }

func run(args []string, errw io.Writer) int {
	fs := flag.NewFlagSet("cairn-review", flag.ContinueOnError)
	fs.SetOutput(errw)
	dir := fs.String("bundle", "", "bundle directory with log.bin and blobs/ (required)")
	out := fs.String("out", "", "HTML file to write (required)")
	cpPath := fs.String("checkpoint", "", "signed checkpoint file to verify and show")
	constHex := fs.String("constitution", "", "expected constitution hash, 64 hex characters")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *dir == "" || *out == "" {
		fmt.Fprintln(errw, "cairn-review: -bundle and -out are required")
		return 2
	}
	entries, blobs, err := review.LoadBundle(*dir)
	if err != nil {
		fmt.Fprintln(errw, "cairn-review:", err)
		return 2
	}
	var opt governance.Options
	if *constHex != "" {
		b, err := hex.DecodeString(*constHex)
		if err != nil || len(b) != 32 {
			fmt.Fprintln(errw, "cairn-review: -constitution must be 64 hex characters")
			return 2
		}
		var h ledger.Hash
		copy(h[:], b)
		opt.ConstitutionHash = &h
	}
	var sc *ledger.SignedCheckpoint
	if *cpPath != "" {
		raw, err := os.ReadFile(*cpPath)
		if err != nil {
			fmt.Fprintln(errw, "cairn-review:", err)
			return 2
		}
		c, err := ledger.DecodeSignedCheckpoint(raw)
		if err != nil {
			fmt.Fprintln(errw, "cairn-review: checkpoint:", err)
			return 2
		}
		sc = &c
	}
	var page bytes.Buffer
	if err := review.Render(&page, entries, blobs, opt, sc); err != nil {
		fmt.Fprintln(errw, "cairn-review:", err)
		return 2
	}
	if err := os.WriteFile(*out, page.Bytes(), 0o644); err != nil {
		fmt.Fprintln(errw, "cairn-review:", err)
		return 2
	}
	if _, err := governance.Replay(entries, blobs, opt); err != nil {
		fmt.Fprintln(errw, "cairn-review: the log does not verify:", err)
		return 1
	}
	return 0
}
