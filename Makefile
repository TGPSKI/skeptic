GOCMD ?= go
PKG := ./cmd/skeptic
BIN_DIR := bin
BIN := $(BIN_DIR)/skeptic

.PHONY: help fmt check test test-race integration integration-fast integration-full integration-scale integration-perf ci coverage coverage-check lint build install install-completions uninstall run scan sarif ingest sign-rulepack gen-rule-keypair serve mcp init version validate-rules validate-rulepacks bench bench-save bench-compare start stop clean profile profile-cpu profile-mem profile-trace perf-debug

help:
	@echo "Targets:"
	@echo "  make fmt      - Format Go sources"
	@echo "  make check    - Pre-commit: fmt (fail on diff) + vet"
	@echo "  make test     - Run unit tests"
	@echo "  make test-race - Run unit tests with race detector"
	@echo "  make integration - Fast integration tests (~10s, small corpus)"
	@echo "  make integration-fast - Small corpus only (~1s)"
	@echo "  make integration-full - All integration tests including MCP/daemon"
	@echo "  make integration-scale - Heavy corpus tests (100k files, CI only)"
	@echo "  make integration-perf - Run integration performance tests"
	@echo "  make ci       - Run unit tests (race) + full integration suite"
	@echo "  make coverage - Run tests with coverage summary"
	@echo "  make coverage-check - Coverage gate (fail if < 60%%)"
	@echo "  make lint     - Run golangci-lint"
	@echo "  make build    - Build scanner binary to $(BIN)"
	@echo "  make install  - Build and install skeptic"
	@echo "  make install-completions - Build and install skeptic and shell completions"
	@echo "  make uninstall - Remove skeptic binary and completions"
	@echo "  make run      - Show scanner help"
	@echo "  make scan     - Run scanner on repo root"
	@echo "  make sarif    - Run scanner and emit SARIF"
	@echo "  make ingest   - Show ingest help"
	@echo "  make sign-rulepack   - Show sign-rulepack help"
	@echo "  make gen-rule-keypair - Show key generation help"
	@echo "  make init     - Bootstrap config files and XDG data directory"
	@echo "  make version  - Print version info"
	@echo "  make validate-rules - Validate built-in rule patterns"
	@echo "  make validate-rulepacks - Run rulepack corpus tests"
	@echo "  make bench    - Run benchmarks"
	@echo "  make bench-save - Run benchmarks; write bench-results.txt at repo root"
	@echo "  make bench-compare - Compare bench-baseline.txt vs bench-results.txt (benchstat)"
	@echo "  make profile  - Run scan with --perf-debug (cpu.prof + mem.prof + trace.out + per-file timing)"
	@echo "  make profile-cpu - Open cpu.prof in pprof interactive mode"
	@echo "  make profile-mem - Open mem.prof in pprof interactive mode"
	@echo "  make profile-trace - Open trace.out in go tool trace"
	@echo "  make perf-debug  - Run scan with --perf-debug on current directory"
	@echo "  make start    - Start local daemon (background)"
	@echo "  make stop     - Stop local daemon using PID file"
	@echo "  make serve    - Run local daemon scheduler"
	@echo "  make mcp      - Run local MCP stdio server"
	@echo "  make clean    - Remove built artifacts"

fmt:
	$(GOCMD) fmt ./...

check:
	@DIFF=$$($(GOCMD) fmt ./...); if [ -n "$$DIFF" ]; then echo "FAIL: gofmt produced changes:"; echo "$$DIFF"; exit 1; fi
	$(GOCMD) vet ./...

test:
	$(GOCMD) test -v ./...

integration:
	$(GOCMD) test -tags=integration ./cmd/skeptic -run '^TestIntegration(SmallCorpus|FullPipeline|RuleFilter|PathIgnore|WaiverSuppression|Decoders|Provenance|Correlation)' -count=1 -v -timeout 60s

integration-fast:
	$(GOCMD) test -tags=integration ./cmd/skeptic -run '^TestIntegrationSmallCorpus$$' -count=1 -v -timeout 30s

integration-full:
	$(GOCMD) test -tags=integration ./cmd/skeptic -run '^TestIntegration' -count=1 -v

integration-scale:
	CI=1 $(GOCMD) test -tags=integration ./cmd/skeptic -run '^TestIntegration(LargeCorpus|IncrementalStress|ConcurrentScanSafety)' -count=1 -v -timeout 10m

integration-perf:
	$(GOCMD) test -tags=integration ./cmd/skeptic -run '^TestIntegrationPerformance' -count=1 -v

test-race:
	$(GOCMD) test -race -v ./...

ci:
	$(GOCMD) test -race -v ./...
	CI=1 $(GOCMD) test -tags=integration ./cmd/skeptic -run '^TestIntegration' -count=1 -v

coverage:
	$(GOCMD) test -v ./... -coverprofile=coverage.out
	$(GOCMD) tool cover -func=coverage.out

coverage-check:
	$(GOCMD) test ./... -coverprofile=coverage.out
	@TOTAL=$$($(GOCMD) tool cover -func=coverage.out | grep total | awk '{print $$3}' | tr -d '%' | cut -d. -f1); \
	if [ "$$TOTAL" -lt 60 ]; then echo "FAIL: coverage $$TOTAL% < 60%"; exit 1; fi
	@echo "PASS: coverage gate"

lint:
	golangci-lint run ./...

COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
GOVERS  ?= $(shell $(GOCMD) version 2>/dev/null | awk '{print $$3}')
LDFLAGS := -X main.buildCommit=$(COMMIT) -X main.buildDate=$(DATE) -X main.buildGoVersion=$(GOVERS)

build:
	mkdir -p $(BIN_DIR)
	$(GOCMD) build -ldflags '$(LDFLAGS)' -o $(BIN) $(PKG)

INSTALL_DIR ?= /usr/local/bin
BASH_COMPLETION_DIR ?= $(shell pkg-config --variable=completionsdir bash-completion 2>/dev/null || echo /usr/share/bash-completion/completions)
ZSH_COMPLETION_DIR ?= /usr/local/share/zsh/site-functions
FISH_COMPLETION_DIR ?= $(shell pkg-config --variable=completionsdir fish 2>/dev/null || echo /usr/share/fish/vendor_completions.d)

install: build
	install -m 755 $(BIN) $(INSTALL_DIR)/skeptic
	@echo "installed: $(INSTALL_DIR)/skeptic"

install-completions: install
	@mkdir -p $(BASH_COMPLETION_DIR) 2>/dev/null || true
	@./$(BIN) completion bash > $(BASH_COMPLETION_DIR)/skeptic 2>/dev/null && \
		echo "installed: $(BASH_COMPLETION_DIR)/skeptic" || \
		echo "skip: bash completions ($(BASH_COMPLETION_DIR) not writable)"
	@mkdir -p $(ZSH_COMPLETION_DIR) 2>/dev/null || true
	@./$(BIN) completion zsh > $(ZSH_COMPLETION_DIR)/_skeptic 2>/dev/null && \
		echo "installed: $(ZSH_COMPLETION_DIR)/_skeptic" || \
		echo "skip: zsh completions ($(ZSH_COMPLETION_DIR) not writable)"
	@mkdir -p $(FISH_COMPLETION_DIR) 2>/dev/null || true
	@./$(BIN) completion fish > $(FISH_COMPLETION_DIR)/skeptic.fish 2>/dev/null && \
		echo "installed: $(FISH_COMPLETION_DIR)/skeptic.fish" || \
		echo "skip: fish completions ($(FISH_COMPLETION_DIR) not writable)"

uninstall:
	rm -f $(INSTALL_DIR)/skeptic
	rm -f $(BASH_COMPLETION_DIR)/skeptic
	rm -f $(ZSH_COMPLETION_DIR)/_skeptic
	rm -f $(FISH_COMPLETION_DIR)/skeptic.fish
	@echo "uninstalled skeptic"

run:
	$(GOCMD) run $(PKG) --help

scan:
	$(GOCMD) run $(PKG) --path . --fail-on high

sarif:
	$(GOCMD) run $(PKG) --path . --format sarif

ingest:
	$(GOCMD) run $(PKG) ingest --help

sign-rulepack:
	$(GOCMD) run $(PKG) sign-rulepack --help

gen-rule-keypair:
	$(GOCMD) run $(PKG) gen-rule-keypair --help

init:
	$(GOCMD) run $(PKG) init --preset dev

version:
	$(GOCMD) run $(PKG) version

validate-rules:
	$(GOCMD) test ./internal/rules -run 'TestDefaultRulesCompositionIncludesAllGroups|TestAttackTacticsRules|TestBehavioralSignalsRules|TestNonCodeSurfacesRules|TestAgenticSurfacesRules|TestValidateRuleSpecQuality' -v -count=1

validate-rulepacks:
	$(GOCMD) test ./cmd/skeptic -run 'TestRulePackCorpus' -v -count=1

bench:
	$(GOCMD) test ./... -bench=. -benchmem -count=3 -timeout 300s

bench-save:
	$(GOCMD) test ./... -bench=. -benchmem -count=3 -timeout 300s > bench-results.txt 2>&1
	@echo "Saved to bench-results.txt"

bench-compare:
	@if command -v benchstat >/dev/null 2>&1; then \
		benchstat bench-baseline.txt bench-results.txt; \
	else \
		echo "benchstat not installed. Run: go install golang.org/x/perf/cmd/benchstat@latest"; \
	fi

PROFILE_PATH ?= .

profile: build
	./$(BIN) --perf-debug --path $(PROFILE_PATH) --fail-on none --verbose 3 > /dev/null
	@echo "Profiles written: cpu.prof mem.prof trace.out"
	@echo "  make profile-cpu   → interactive CPU flamegraph"
	@echo "  make profile-mem   → interactive heap analysis"
	@echo "  make profile-trace → execution trace viewer"

perf-debug: build
	./$(BIN) --perf-debug --path $(PROFILE_PATH) --fail-on none --verbose 3

profile-cpu:
	$(GOCMD) tool pprof -http=:6060 cpu.prof

profile-mem:
	$(GOCMD) tool pprof -http=:6061 mem.prof

profile-trace:
	$(GOCMD) tool trace trace.out

start:
	command ./scripts/start

stop:
	command ./scripts/stop

serve:
	$(GOCMD) run $(PKG) serve --scan-interval 5m

mcp:
	$(GOCMD) run $(PKG) mcp --help

clean:
	rm -rf $(BIN_DIR)
