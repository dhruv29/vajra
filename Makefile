# Common tasks. Everything here is also runnable by hand; see README.md.

BINARY := vajra
GOFLAGS := -trimpath -buildvcs=false
LDFLAGS := -s -w -buildid=

.PHONY: all build test vet fmt check e2e images sbom digests

all: check build

build: ## Build a reproducible binary
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/vajra

test: ## Unit tests with the race detector
	go test ./... -race -cover

vet:
	go vet ./...

fmt: ## Fail if any file is not gofmt-formatted
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "run gofmt -w on the files above" && exit 1)

check: fmt vet test ## Everything CI runs

e2e: ## End-to-end run against a lab target (needs Docker)
	./scripts/e2e.sh

images: ## Build the gate, scanner and analyser images
	docker build -t vajra:local .
	docker build -t vajra-nuclei:local -f deploy/nuclei.Dockerfile deploy
	docker build -t vajra-semgrep:local -f deploy/semgrep.Dockerfile deploy

sbom: build ## Write a software bill of materials for the binary
	./scripts/sbom.sh $(BINARY) > sbom.json

digests: ## Print the current digests of the base images, for updating the pins
	@for image in golang:1.27-alpine gcr.io/distroless/static-debian12:nonroot projectdiscovery/nuclei:latest semgrep/semgrep:latest; do \
		printf '%s ' "$$image"; docker buildx imagetools inspect "$$image" | awk '/^Digest:/ {print $$2; exit}'; \
	done
