# ============================================================
#  whyblock — Makefile
# ============================================================

# Binary name
BINARY     := whyblock

# Module path (matches go.mod)
MODULE     := github.com/chaitanya34/whyblock

# Version — reads from git tag, falls back to "dev"
VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")

# Build metadata
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# ldflags — inject version info into the binary at build time
LDFLAGS    := -ldflags "-X $(MODULE)/pkg/version.Version=$(VERSION) \
                         -X $(MODULE)/pkg/version.Commit=$(COMMIT) \
                         -X $(MODULE)/pkg/version.BuildDate=$(BUILD_DATE)"

# Output directory for built binaries
DIST       := dist

# Go commands
GOCMD      := go
GOBUILD    := $(GOCMD) build
GOTEST     := $(GOCMD) test
GOVET      := $(GOCMD) vet
GOFMT      := gofmt
GOINSTALL  := $(GOCMD) install
GOMOD      := $(GOCMD) mod

# Platforms for cross-compilation
PLATFORMS  := \
	linux/amd64 \
	linux/arm64 \
	darwin/amd64 \
	darwin/arm64 \
	windows/amd64

# Default target — what runs when you just type `make`
.DEFAULT_GOAL := help

# ============================================================
#  HELP
# ============================================================

.PHONY: help
help: ## Show this help message
	@echo ""
	@echo "  whyblock $(VERSION)"
	@echo ""
	@echo "  Usage: make <target>"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)
	@echo ""

# ============================================================
#  BUILD
# ============================================================

.PHONY: build
build: ## Build binary for current platform → ./whyblock
	@echo "→ Building $(BINARY) $(VERSION)..."
	$(GOBUILD) $(LDFLAGS) -o $(BINARY) .
	@echo "✓ Built ./$(BINARY)"

.PHONY: install
install: ## Install binary to GOPATH/bin (makes it available system-wide)
	@echo "→ Installing $(BINARY)..."
	$(GOINSTALL) $(LDFLAGS) .
	@echo "✓ Installed. Run: $(BINARY) --help"

.PHONY: dist
dist: ## Cross-compile for all platforms → ./dist/
	@echo "→ Cross-compiling for all platforms..."
	@mkdir -p $(DIST)
	@$(foreach platform,$(PLATFORMS), \
		$(eval OS   := $(word 1,$(subst /, ,$(platform)))) \
		$(eval ARCH := $(word 2,$(subst /, ,$(platform)))) \
		echo "  Building $(OS)/$(ARCH)..." ; \
		GOOS=$(OS) GOARCH=$(ARCH) $(GOBUILD) $(LDFLAGS) \
			-o $(DIST)/$(BINARY)_$(OS)_$(ARCH)$(if $(filter windows,$(OS)),.exe,) . ; \
	)
	@echo "✓ Binaries in ./$(DIST)/"
	@ls -lh $(DIST)/

# ============================================================
#  TEST
# ============================================================

.PHONY: test
test: ## Run all tests
	@echo "→ Running tests..."
	$(GOTEST) -v -race ./...

.PHONY: test-short
test-short: ## Run tests without race detector (faster)
	$(GOTEST) ./...

.PHONY: coverage
coverage: ## Run tests with coverage report → coverage.html
	@echo "→ Running tests with coverage..."
	$(GOTEST) -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "✓ Coverage report: coverage.html"

# ============================================================
#  CODE QUALITY
# ============================================================

.PHONY: fmt
fmt: ## Format all Go source files
	@echo "→ Formatting..."
	$(GOFMT) -w .
	@echo "✓ Done"

.PHONY: fmt-check
fmt-check: ## Check formatting without changing files (for CI)
	@echo "→ Checking formatting..."
	@test -z "$$($(GOFMT) -l .)" || (echo "✗ Unformatted files:"; $(GOFMT) -l .; exit 1)
	@echo "✓ All files formatted"

.PHONY: vet
vet: ## Run go vet (catches common mistakes)
	@echo "→ Running go vet..."
	$(GOVET) ./...
	@echo "✓ Done"

.PHONY: lint
lint: ## Run golangci-lint (install: brew install golangci-lint)
	@which golangci-lint > /dev/null || (echo "✗ golangci-lint not installed. Run: brew install golangci-lint"; exit 1)
	golangci-lint run ./...

.PHONY: check
check: fmt-check vet test ## Run fmt-check + vet + tests (full pre-commit check)
	@echo "✓ All checks passed"

# ============================================================
#  DEPENDENCIES
# ============================================================

.PHONY: deps
deps: ## Download all dependencies
	@echo "→ Downloading dependencies..."
	$(GOMOD) download
	@echo "✓ Done"

.PHONY: tidy
tidy: ## Tidy go.mod and go.sum
	@echo "→ Tidying modules..."
	$(GOMOD) tidy
	@echo "✓ Done"

# ============================================================
#  CLEAN
# ============================================================

.PHONY: clean
clean: ## Remove built binaries and coverage files
	@echo "→ Cleaning..."
	@rm -f $(BINARY)
	@rm -rf $(DIST)
	@rm -f coverage.out coverage.html
	@echo "✓ Clean"

# ============================================================
#  VERSION
# ============================================================

.PHONY: version
version: ## Print current version
	@echo $(VERSION)