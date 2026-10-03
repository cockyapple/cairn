// Command cairn-witness runs a Cairn witness: a separate process, ideally on
// a separate machine, that reads the whole log from a cairn-logd, checks it
// against the governance rules itself, and cosigns a checkpoint only when the
// log extends everything it has signed before.
//
// Run -genkey once to make a key. Put the public key it prints into the
// log's trust configuration as a witness, then run the witness against the
// server. Keep the -state file on durable storage: it is the witness's memory.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/cockyapple/cairn/governance"
	"github.com/cockyapple/cairn/ledger"
	"github.com/cockyapple/cairn/witness"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "cairn-witness:", err)
		os.Exit(2)
	}
}

func parseHash(name, s string) (ledger.Hash, error) {
	var h ledger.Hash
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != len(h) {
		return h, fmt.Errorf("-%s must be 64 hex characters", name)
	}
	copy(h[:], b)
	return h, nil
}

func genKey(path string) error {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(hex.EncodeToString(seed) + "\n"); err != nil {
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
	pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	fmt.Println(hex.EncodeToString(pub))
	return nil
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by group or others (mode %v); chmod 600 it", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("key file must hold a 64-character hex seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func run() error {
	server := flag.String("server", "", "base URL of the cairn-logd to witness, e.g. http://10.0.0.5:8480")
	keyFile := flag.String("key", "", "file holding the witness's hex seed (mode 600)")
	statePath := flag.String("state", "", "file the witness records what it has signed in (durable storage)")
	constitution := flag.String("constitution", "", "hex constitution hash the log must carry (optional)")
	genesis := flag.String("genesis", "", "hex hash of the first entry this witness will accept (recommended)")
	interval := flag.Duration("interval", 30*time.Second, "time between checks")
	once := flag.Bool("once", false, "check and sign once, then exit")
	size := flag.Uint64("size", 0, "with -once: sign this prefix size instead of the whole log")
	useClock := flag.Bool("use-clock", true, "refuse entries dated ahead of this machine's clock")
	skew := flag.Uint64("max-skew", 300, "seconds an entry may be dated ahead of this machine's clock")
	genkey := flag.String("genkey", "", "write a new key to this file, print its public key, and exit")
	flag.Parse()

	if *genkey != "" {
		return genKey(*genkey)
	}
	if *server == "" || *keyFile == "" || *statePath == "" {
		return errors.New("-server, -key and -state are required")
	}
	key, err := loadKey(*keyFile)
	if err != nil {
		return err
	}
	cfg := witness.Config{Server: *server, Key: key, StatePath: *statePath, MaxSkew: *skew}
	if *useClock {
		cfg.Clock = time.Now
	}
	if *constitution != "" {
		h, err := parseHash("constitution", *constitution)
		if err != nil {
			return err
		}
		cfg.Options = governance.Options{ConstitutionHash: &h}
	}
	if *genesis != "" {
		h, err := parseHash("genesis", *genesis)
		if err != nil {
			return err
		}
		cfg.Genesis = &h
	}
	w, err := witness.New(cfg)
	if err != nil {
		return err
	}
	pub := w.Public()
	seen, _ := w.Seen()
	fmt.Fprintf(os.Stderr, "cairn-witness: key %x; has signed up to size %d; watching %s\n", pub[:], seen, *server)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if *once {
		res, err := w.Cycle(ctx, *size)
		if err != nil {
			return err
		}
		fmt.Printf("signed size %d root %x complete %v\n", res.Size, res.Root[:], res.Complete)
		return nil
	}
	w.Run(ctx, *interval, func(f string, a ...any) { fmt.Fprintf(os.Stderr, "cairn-witness: "+f+"\n", a...) })
	return nil
}
