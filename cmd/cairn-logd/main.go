// Command cairn-logd runs the Cairn log server: it accepts signed entries,
// refuses any that would break the log's rules, stores what it accepts in a
// directory cairn-verify can read, and collects checkpoint signatures.
//
// It speaks plain HTTP and serves the log (and its blobs) to anyone who can
// reach it. Bind it to a private address, or put TLS and authentication in
// front of it.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
	"github.com/cockyapple/cairn/logserver"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "cairn-logd:", err)
		os.Exit(2)
	}
}

func parseHash32(name, s string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return out, fmt.Errorf("-%s must be 64 hex characters", name)
	}
	copy(out[:], b)
	return out, nil
}

func run() error {
	dir := flag.String("dir", "", "storage directory (created if missing)")
	listen := flag.String("listen", "127.0.0.1:8480", "address to listen on")
	genesis := flag.String("genesis-author", "", "hex public key allowed to write the first entry (required for an empty log)")
	constitution := flag.String("constitution", "", "hex constitution hash the log must carry (optional)")
	perWindow := flag.Int("rate", 60, "submissions per key per window (0 = unlimited)")
	window := flag.Duration("rate-window", time.Minute, "rate-limit window")
	maxBlob := flag.Int("max-blob", 1<<20, "largest blob in bytes")
	maxStore := flag.Int64("max-store", 256<<20, "total blob bytes to hold")
	maxEntries := flag.Int("max-entries", 1<<20, "most entries the log may hold")
	skew := flag.Uint64("max-skew", 300, "seconds an entry may be dated ahead of this server's clock")
	flag.Parse()
	if *dir == "" {
		return errors.New("-dir is required")
	}
	cfg := logserver.Config{Dir: *dir, MaxSkew: *skew, Limits: logserver.Limits{
		Window: *window, Default: *perWindow, MaxBlobBytes: *maxBlob, MaxStoreBytes: *maxStore, MaxEntries: *maxEntries,
	}}
	var err error
	if *genesis != "" {
		if cfg.GenesisAuthor, err = parseHash32("genesis-author", *genesis); err != nil {
			return err
		}
	}
	if *constitution != "" {
		h, err := parseHash32("constitution", *constitution)
		if err != nil {
			return err
		}
		ch := ledger.Hash(h)
		cfg.Options = governance.Options{ConstitutionHash: &ch}
	}
	srv, err := logserver.Open(cfg)
	if err != nil {
		return err
	}
	defer srv.Close()
	st := srv.Status()
	fmt.Fprintf(os.Stderr, "cairn-logd: %d entries loaded and rechecked from %s; listening on %s\n", st.Entries, *dir, *listen)
	if st.Entries == 0 && *genesis == "" {
		fmt.Fprintln(os.Stderr, "cairn-logd: warning: empty log and no -genesis-author; every append will be refused")
	}

	hs := &http.Server{Addr: *listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return hs.Shutdown(sctx)
	}
}
