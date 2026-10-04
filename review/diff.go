package review

import (
	"bytes"
	"errors"
	"strings"
)

type DiffOp int

const (
	Same DiffOp = iota
	Add
	Del
)

type DiffLine struct {
	Op   DiffOp
	Text string
}

// maxDiffCells bounds the work of the line diff: a proposal whose two sides
// multiply past it is reported as too large rather than diffed.
const maxDiffCells = 4_000_000

var ErrDiffTooLarge = errors.New("review: artifacts are too large to diff")

// lineCount is len(splitLines(b)) without building the slice.
func lineCount(b []byte) int {
	n := bytes.Count(b, []byte("\n"))
	if len(b) > 0 && b[len(b)-1] != '\n' {
		n++
	}
	return n
}

// firstLines returns at most n lines of b, as splitLines would split them.
func firstLines(b []byte, n int) []string {
	var out []string
	for len(b) > 0 && len(out) < n {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			out = append(out, string(b))
			break
		}
		out = append(out, string(b[:i]))
		b = b[i+1:]
	}
	return out
}

func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// Diff is a line diff from old to new. Invalid UTF-8 is carried through as is;
// anything that renders it must escape it.
func Diff(old, new []byte) ([]DiffLine, error) {
	if (lineCount(old)+1)*(lineCount(new)+1) > maxDiffCells {
		return nil, ErrDiffTooLarge
	}
	a, b := splitLines(old), splitLines(new)
	w := len(b) + 1
	lcs := make([]int32, (len(a)+1)*w)
	for i := len(a) - 1; i >= 0; i-- {
		for j := len(b) - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i*w+j] = lcs[(i+1)*w+j+1] + 1
			} else if lcs[(i+1)*w+j] >= lcs[i*w+j+1] {
				lcs[i*w+j] = lcs[(i+1)*w+j]
			} else {
				lcs[i*w+j] = lcs[i*w+j+1]
			}
		}
	}
	var out []DiffLine
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			out = append(out, DiffLine{Same, a[i]})
			i++
			j++
		case lcs[(i+1)*w+j] >= lcs[i*w+j+1]:
			out = append(out, DiffLine{Del, a[i]})
			i++
		default:
			out = append(out, DiffLine{Add, b[j]})
			j++
		}
	}
	for ; i < len(a); i++ {
		out = append(out, DiffLine{Del, a[i]})
	}
	for ; j < len(b); j++ {
		out = append(out, DiffLine{Add, b[j]})
	}
	return out, nil
}

// Unified renders a diff with +/- prefixes and no context trimming.
func Unified(d []DiffLine) string {
	var sb strings.Builder
	for _, l := range d {
		switch l.Op {
		case Add:
			sb.WriteString("+ ")
		case Del:
			sb.WriteString("- ")
		default:
			sb.WriteString("  ")
		}
		sb.WriteString(l.Text)
		sb.WriteByte('\n')
	}
	return sb.String()
}
