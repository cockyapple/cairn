package review

import (
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

func splitLines(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	return strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
}

// Diff is a line diff from old to new. Invalid UTF-8 is carried through as is;
// anything that renders it must escape it.
func Diff(old, new []byte) ([]DiffLine, error) {
	a, b := splitLines(old), splitLines(new)
	if (len(a)+1)*(len(b)+1) > maxDiffCells {
		return nil, ErrDiffTooLarge
	}
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
