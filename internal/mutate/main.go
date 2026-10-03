// Command mutate checks that the tests can fail. For each mutant in a JSON
// list it copies the repository to a temporary directory, replaces one exact
// piece of source text, and runs the tests of the mutated package. A mutant is
// killed if those tests fail (or hang past the timeout). If they pass, the whole
// repository's tests are run too, because another package's tests may be the
// ones that notice; only if everything passes does the mutant survive, or count
// as "equivalent" when the list says, with a reason, that no test can tell it
// apart. A mutant is invalid if its text is not found exactly once or it does not
// compile. The repository itself is never modified. Exit status is 1 unless every
// mutant was killed or declared equivalent.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Mutant struct {
	Name string `json:"name"`
	File string `json:"file"`
	Old  string `json:"old"`
	New  string `json:"new"`
	// Equivalent, when set, says why no test can tell this mutant from the original.
	Equivalent string `json:"equivalent,omitempty"`
}

type result struct {
	m       Mutant
	verdict string
	detail  string
}

func main() {
	list := flag.String("mutants", "testdata/mutants.json", "mutant list")
	only := flag.String("only", "", "run only mutants whose name contains this")
	jobs := flag.Int("j", 2, "mutants run in parallel")
	timeout := flag.Duration("timeout", 3*time.Minute, "per-run test timeout")
	flag.Parse()

	raw, err := os.ReadFile(*list)
	if err != nil {
		fatal(err)
	}
	var all []Mutant
	if err := json.Unmarshal(raw, &all); err != nil {
		fatal(err)
	}
	var ms []Mutant
	for _, m := range all {
		if strings.Contains(m.Name, *only) {
			ms = append(ms, m)
		}
	}

	root, err := os.MkdirTemp("", "mutate")
	if err != nil {
		fatal(err)
	}
	cleanup := func() { os.RemoveAll(root) }
	defer cleanup()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	go func() {
		<-sig
		cleanup()
		os.Exit(130)
	}()

	// The baseline runs on a copy, so that anything the copy loses shows up here
	// and is not blamed on a mutant.
	base := filepath.Join(root, "baseline")
	if err := copyTree(".", base); err != nil {
		fatal(err)
	}
	if out, ok := run(base, "./...", 3**timeout); !ok {
		fmt.Println("the unmutated tests fail; fix that first")
		fmt.Println(out)
		os.Exit(2)
	}
	os.RemoveAll(base)

	results := make([]result, len(ms))
	sem := make(chan struct{}, *jobs)
	var wg sync.WaitGroup
	for i, m := range ms {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = try(root, i, m, *timeout)
		}()
	}
	wg.Wait()

	count := map[string]int{}
	for _, r := range results {
		count[r.verdict]++
		fmt.Printf("%-10s %-12s %s\n", r.verdict, filepath.Dir(r.m.File), r.m.Name)
		if r.detail != "" {
			fmt.Println("           " + r.detail)
		}
	}
	var kinds []string
	for k := range count {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	fmt.Printf("\n%d mutants:", len(results))
	for _, k := range kinds {
		fmt.Printf(" %d %s", count[k], k)
	}
	fmt.Println()
	if count["killed"]+count["equivalent"] != len(results) {
		os.Exit(1)
	}
}

func try(root string, n int, m Mutant, timeout time.Duration) result {
	tmp := filepath.Join(root, fmt.Sprint("m", n))
	defer os.RemoveAll(tmp)
	if err := copyTree(".", tmp); err != nil {
		return result{m, "error", err.Error()}
	}
	path := filepath.Join(tmp, m.File)
	src, err := os.ReadFile(path)
	if err != nil {
		return result{m, "invalid", err.Error()}
	}
	switch c := strings.Count(string(src), m.Old); {
	case c == 0:
		return result{m, "invalid", "text not found in " + m.File}
	case c > 1:
		return result{m, "invalid", fmt.Sprintf("text found %d times in %s; make it unique", c, m.File)}
	}
	mutated := strings.Replace(string(src), m.Old, m.New, 1)
	if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
		return result{m, "error", err.Error()}
	}

	out, ok := run(tmp, "./"+filepath.Dir(m.File), timeout)
	if !ok {
		return classify(m, out)
	}
	out, ok = run(tmp, "./...", 3*timeout)
	if !ok {
		r := classify(m, out)
		if r.verdict == "killed" {
			r.detail = "caught only by another package's tests"
		}
		return r
	}
	if m.Equivalent != "" {
		return result{m, "equivalent", m.Equivalent}
	}
	return result{m, "survived", "tests still pass with: " + oneLine(m.New)}
}

func classify(m Mutant, out string) result {
	switch {
	case strings.Contains(out, "[build failed]") || strings.Contains(out, "[setup failed]"):
		return result{m, "invalid", "does not compile: " + firstLine(out)}
	case strings.Contains(out, "test timed out"):
		return result{m, "killed", "by the timeout (the mutant makes a test hang)"}
	}
	return result{m, "killed", ""}
}

// run executes go test. The context only backstops go test's own -timeout, so
// that go test has time to stop the test binary it started.
func run(dir, pkg string, timeout time.Duration) (string, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-count=1", "-timeout", timeout.String(), pkg)
	cmd.Dir = dir
	cmd.WaitDelay = 10 * time.Second
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return buf.String(), err == nil
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o700)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			target, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(target, filepath.Join(dst, rel))
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, info.Mode().Perm()|0o600)
	})
}

func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

func firstLine(s string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, ".go:") {
			return l
		}
	}
	return oneLine(s)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}
