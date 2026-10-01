// Package eval runs an evaluation suite against a baseline and a candidate
// artifact and produces a canonical result whose hash a proposal records as
// its eval_hash. The ledger stores only that hash: it proves which result
// reviewers were shown, not that the suite was run honestly. Anyone can rerun
// the suite and compare hashes.
package eval

import (
	"errors"
	"fmt"
	"sort"

	"github.com/cockyapple/cairn/ledger"
	"github.com/cockyapple/cairn/wire"
)

const (
	// MaxScore is a perfect score. Scores are integers in 0..MaxScore (basis
	// points) so that a result has one canonical encoding on every platform.
	MaxScore  = 10000
	MaxCases  = 4096
	maxName   = 256
	resultTag = "cairn/eval-result/v1\x00"
)

var (
	ErrBadResult = errors.New("eval: malformed result")
	ErrBadScore  = errors.New("eval: score outside 0..10000")
)

// Case is one test in a suite. Input is handed to the Scorer and is not part
// of the result; the result commits to the suite by name and case names only.
type Case struct {
	Name  string
	Input []byte
}

// Scorer judges one artifact on one case. It may call a model, run a program,
// or do anything else; the only contract is a score in 0..MaxScore.
type Scorer func(artifact []byte, c Case) (int, error)

type CaseScore struct {
	Name      string
	Baseline  int
	Candidate int
}

// Result is what a proposal's eval_hash commits to.
type Result struct {
	Suite         string
	BaselineHash  ledger.Hash // BlobHash of the artifact in force
	CandidateHash ledger.Hash // BlobHash of the proposed artifact
	Cases         []CaseScore
}

// Run scores baseline and candidate on every case. Case names must be unique;
// results are ordered by name so the encoding does not depend on suite order.
func Run(suite string, cases []Case, baseline, candidate []byte, score Scorer) (*Result, error) {
	if len(suite) == 0 || len(suite) > maxName {
		return nil, fmt.Errorf("eval: suite name must be 1..%d bytes", maxName)
	}
	if len(cases) == 0 || len(cases) > MaxCases {
		return nil, fmt.Errorf("eval: a suite needs 1..%d cases", MaxCases)
	}
	r := &Result{Suite: suite, BaselineHash: ledger.BlobHash(baseline), CandidateHash: ledger.BlobHash(candidate)}
	seen := map[string]bool{}
	for _, c := range cases {
		if len(c.Name) == 0 || len(c.Name) > maxName || seen[c.Name] {
			return nil, fmt.Errorf("eval: case name %q is empty, too long or repeated", c.Name)
		}
		seen[c.Name] = true
		b, err := score(baseline, c)
		if err != nil {
			return nil, fmt.Errorf("eval: baseline on %q: %w", c.Name, err)
		}
		n, err := score(candidate, c)
		if err != nil {
			return nil, fmt.Errorf("eval: candidate on %q: %w", c.Name, err)
		}
		if b < 0 || b > MaxScore || n < 0 || n > MaxScore {
			return nil, fmt.Errorf("eval: %q: %w", c.Name, ErrBadScore)
		}
		r.Cases = append(r.Cases, CaseScore{Name: c.Name, Baseline: b, Candidate: n})
	}
	sort.Slice(r.Cases, func(i, j int) bool { return r.Cases[i].Name < r.Cases[j].Name })
	return r, nil
}

// Encode is the canonical encoding. Cases must already be sorted by name.
func (r *Result) Encode() []byte {
	var w wire.Writer
	w.Fixed([]byte(resultTag))
	w.String(r.Suite)
	w.Fixed(r.BaselineHash[:])
	w.Fixed(r.CandidateHash[:])
	w.U32(uint32(len(r.Cases)))
	for _, c := range r.Cases {
		w.String(c.Name)
		w.U32(uint32(c.Baseline))
		w.U32(uint32(c.Candidate))
	}
	return w.Out()
}

// Hash is the value a proposal records as eval_hash.
func (r *Result) Hash() ledger.Hash { return ledger.BlobHash(r.Encode()) }

// Decode parses and validates a result: bounded sizes, scores in range, case
// names strictly ascending (so each result has exactly one encoding).
func Decode(b []byte) (*Result, error) {
	rd := wire.NewReader(b)
	if string(rd.Fixed(len(resultTag))) != resultTag {
		return nil, ErrBadResult
	}
	r := &Result{Suite: rd.String()}
	copy(r.BaselineHash[:], rd.Fixed(32))
	copy(r.CandidateHash[:], rd.Fixed(32))
	n := rd.Count(MaxCases)
	for i := 0; i < n; i++ {
		var c CaseScore
		c.Name = rd.String()
		c.Baseline = int(rd.U32())
		c.Candidate = int(rd.U32())
		r.Cases = append(r.Cases, c)
	}
	if rd.Done() != nil || len(r.Suite) == 0 || len(r.Suite) > maxName || len(r.Cases) == 0 {
		return nil, ErrBadResult
	}
	for i, c := range r.Cases {
		if len(c.Name) == 0 || len(c.Name) > maxName || (i > 0 && c.Name <= r.Cases[i-1].Name) {
			return nil, ErrBadResult
		}
		if c.Baseline < 0 || c.Baseline > MaxScore || c.Candidate < 0 || c.Candidate > MaxScore {
			return nil, ErrBadScore
		}
	}
	return r, nil
}

// Summary is the review view of a result: the change in the mean score, in
// basis points, and the cases where the candidate scored lower.
type Summary struct {
	BaselineMean, CandidateMean int // basis points, rounded down
	Delta                       int
	Regressions                 []CaseScore
}

func (r *Result) Summary() Summary {
	var s Summary
	var b, c int
	for _, cs := range r.Cases {
		b += cs.Baseline
		c += cs.Candidate
		if cs.Candidate < cs.Baseline {
			s.Regressions = append(s.Regressions, cs)
		}
	}
	if n := len(r.Cases); n > 0 {
		s.BaselineMean, s.CandidateMean = b/n, c/n
	}
	s.Delta = s.CandidateMean - s.BaselineMean
	return s
}
