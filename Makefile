# All Go tooling runs in a pinned container so the host needs no toolchain.
GO_IMAGE ?= golang:1.24-alpine
RUN = docker run --rm -v $(CURDIR):/src -w /src -e CGO_ENABLED=0 -e GOFLAGS=-mod=readonly $(GO_IMAGE)

.PHONY: test vet fmt vectors loc
test:
	$(RUN) go test -count=1 ./...
vet:
	$(RUN) go vet ./...
fmt:
	$(RUN) gofmt -l -w .
vectors:
	$(RUN) go run ./cmd/cairn-vectors > testdata/vectors-v1.json.new && mv testdata/vectors-v1.json.new testdata/vectors-v1.json
# The verifier must stay small enough to read in an afternoon (budget: 1,500 lines).
loc:
	@cat wire/wire.go ledger/*.go | grep -v _test | wc -l
