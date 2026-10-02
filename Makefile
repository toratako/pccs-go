.PHONY: build test vet check smoke lint-ci release-check release-snapshot clean

TEST_FLAGS ?= -race

build:
	go build -trimpath -o bin/pccs ./cmd/pccs

test:
	go test $(TEST_FLAGS) ./...

vet:
	go vet ./...

check: test vet
	@test -z "$$(gofmt -l cmd internal)" || { gofmt -l cmd internal; exit 1; }

smoke: build
	bash scripts/smoke-test.sh bin/pccs

lint-ci:
	actionlint
	bash -n scripts/smoke-test.sh
	shellcheck scripts/smoke-test.sh

release-check:
	goreleaser check

release-snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -f bin/pccs
