package gatekeeper

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cockyapple/cairn/ledger"
)

var errMismatch = errors.New("gatekeeper: refusing to store an opening that does not match its commitment")

// ErrNoOpening means the store holds no opening for the commitment.
var ErrNoOpening = errors.New("gatekeeper: no opening for that commitment")

// OpeningStore keeps the openings of a hash-only agent's commitments (see
// governance.NewOpening). The log holds only the commitments, so an opening that
// is lost cannot be rebuilt. The gatekeeper calls Put before the entry that
// commits to the opening is appended, and does not append if Put fails; it calls
// Delete when the log then refuses the entry. Put must not return until the
// opening is as durable as the store promises. A store is safe for concurrent
// use, and Get may be called without the gatekeeper's lock held.
type OpeningStore interface {
	Put(commit ledger.Hash, opening []byte) error
	// Get returns ErrNoOpening if there is none, and an error if what it holds does
	// not hash to commit.
	Get(commit ledger.Hash) ([]byte, error)
	Delete(commit ledger.Hash) error
}

// MemoryOpenings is an OpeningStore that forgets everything on restart.
type MemoryOpenings struct {
	mu sync.Mutex
	m  map[ledger.Hash][]byte
}

func (s *MemoryOpenings) Put(c ledger.Hash, o []byte) error {
	if ledger.BlobHash(o) != c {
		return errMismatch
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[ledger.Hash][]byte{}
	}
	s.m[c] = bytes.Clone(o)
	return nil
}

func (s *MemoryOpenings) Get(c ledger.Hash) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.m[c]
	if !ok {
		return nil, ErrNoOpening
	}
	return bytes.Clone(o), nil
}

func (s *MemoryOpenings) Delete(c ledger.Hash) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, c)
	return nil
}

// DirOpenings keeps one file per opening, named by its commitment, in a directory
// only its owner can read. A file is written to a temporary name, synced and
// renamed, and the directory is synced, so a Put that returned survives a crash.
type DirOpenings struct{ dir string }

// NewDirOpenings creates dir (mode 0700) if it does not exist, and syncs the
// directories it created into their parents so the store itself survives a crash.
// An existing dir (a symbolic link is refused: its mode reads 0777) must be one that no
// other user can write or read:
// anyone who can write to it can delete an opening the log already depends on.
func NewDirOpenings(dir string) (*DirOpenings, error) {
	dir = filepath.Clean(dir)
	var created []string // outermost first
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Lstat(d); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		created = append([]string{d}, created...)
		if filepath.Dir(d) == d {
			break
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	for _, d := range created {
		if err := syncDir(d); err != nil {
			return nil, err
		}
		if err := syncDir(filepath.Dir(d)); err != nil {
			return nil, err
		}
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("gatekeeper: %s is accessible to other users (mode %o); it must be 0700", dir, fi.Mode().Perm())
	}
	return &DirOpenings{dir: dir}, nil
}

func syncDir(path string) error {
	d, err := os.Open(path)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (s *DirOpenings) path(c ledger.Hash) string {
	return filepath.Join(s.dir, fmt.Sprintf("%x", c[:]))
}

func (s *DirOpenings) Put(c ledger.Hash, o []byte) error {
	if ledger.BlobHash(o) != c {
		return errMismatch
	}
	f, err := os.CreateTemp(s.dir, "tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, err = f.Write(o)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, s.path(c))
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return syncDir(s.dir)
}

func (s *DirOpenings) Get(c ledger.Hash) ([]byte, error) {
	o, err := os.ReadFile(s.path(c))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoOpening
	}
	if err != nil {
		return nil, err
	}
	if ledger.BlobHash(o) != c {
		return nil, fmt.Errorf("gatekeeper: the stored opening for %x is corrupt", c[:4])
	}
	return o, nil
}

func (s *DirOpenings) Delete(c ledger.Hash) error {
	if err := os.Remove(s.path(c)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
