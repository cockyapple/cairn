package governance

import (
	"testing"
	"time"
)

func TestSortGrantInfosIsFastAndOrdered(t *testing.T) {
	const n = 200000
	s := make([]GrantInfo, n)
	for i := range s {
		h := uint64(n - i)
		s[i] = GrantInfo{Height: h / 2, Agent: [32]byte{byte(i), byte(i >> 8), byte(i >> 16)}}
	}
	start := time.Now()
	sortGrantInfos(s)
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("sorting %d grants took %v", n, d)
	}
	for i := 1; i < n; i++ {
		a, b := s[i-1], s[i]
		if a.Height > b.Height || (a.Height == b.Height && string(a.Agent[:]) > string(b.Agent[:])) {
			t.Fatalf("out of order at %d", i)
		}
	}
}
