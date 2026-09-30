// Command cairn-vectors writes the deterministic test-vector file.
//
//	go run ./cmd/cairn-vectors > testdata/vectors-v1.json
package main

import (
	"os"

	"github.com/cockyapple/cairn/internal/vectorgen"
)

func main() {
	if _, err := os.Stdout.Write(vectorgen.Build().JSON()); err != nil {
		os.Exit(1)
	}
}
