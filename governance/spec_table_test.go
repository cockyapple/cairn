package governance

import (
	"os"
	"regexp"
	"strconv"
	"testing"

	"github.com/cockyapple/cairn/ledger"
)

// The SPEC section 10.2 tier table is the contract; this test reads it from
// the document so the code and the prose cannot drift apart unnoticed.
func TestTierTableMatchesTheSpec(t *testing.T) {
	doc, err := os.ReadFile("../docs/SPEC.md")
	if err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile(`(?m)^\s*\| T([0-4]) \| (\d+) \| (\d+) \| (\d+)(?: (h|d))? \|`)
	rows := row.FindAllStringSubmatch(string(doc), -1)
	if len(rows) != 5 {
		t.Fatalf("expected 5 tier rows in SPEC 10.2, found %d", len(rows))
	}
	for _, m := range rows {
		tier, _ := strconv.Atoi(m[1])
		total, _ := strconv.Atoi(m[2])
		sec, _ := strconv.Atoi(m[3])
		n, _ := strconv.Atoi(m[4])
		delay := uint64(n) * 3600
		if m[5] == "d" {
			delay *= 24
		}
		gt, gs := Required(ledger.Tier(tier))
		if gt != total || gs != sec {
			t.Errorf("T%d approvals: code %d/%d, SPEC %d/%d", tier, gt, gs, total, sec)
		}
		if got := MinDelay(ledger.Tier(tier)); got != delay {
			t.Errorf("T%d delay: code %ds, SPEC %ds", tier, got, delay)
		}
	}
}
