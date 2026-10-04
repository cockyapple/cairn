package witness

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadStateRefusesTrailingData(t *testing.T) {
	p := filepath.Join(t.TempDir(), "state.json")
	good := `{"version":1,"size":1,"root":"` + `0000000000000000000000000000000000000000000000000000000000000000","head":"0000000000000000000000000000000000000000000000000000000000000000"}`
	for name, body := range map[string]string{"second object": good + "\n" + `{"x":1}`, "garbage": good + " junk"} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadState(p); err == nil {
			t.Errorf("%s: trailing data was accepted", name)
		}
	}
}
