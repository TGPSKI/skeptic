// Package main implements the skeptic CLI — a stdlib-only Go security scanner
// that detects supply chain compromise, agentic ecosystem poisoning, CI/CD
// weaponization, and machine-identity abuse.
//
// skeptic ships as a single static binary with zero runtime dependencies. It
// targets the structural trust boundary violations that CVE scanners, SAST
// tools, and secret scanners do not cover: mutable action refs, unsafe
// pull_request_target patterns, MCP tool shadowing, over-permissioned service
// accounts, and similar attack-enabling conditions.
//
// # Subcommands
//
// The binary dispatches to subcommands via the first positional argument:
//
//   - scan (default): scan files for threats
//   - init: bootstrap config files and XDG data directory
//   - config show/use: print resolved config or set the active profile
//   - serve: persistent scheduler with local HTTP API
//   - mcp: stdio MCP JSON-RPC server for agentic tooling
//   - ingest: generate rule packs from threat intel sources
//   - corpus: manage encrypted threat artifact corpus
//   - waive: create SHA256-pinned waivers for findings
//   - bundle/verify-bundle: package and verify distribution bundles
//   - export-evidence: signed evidence bundles for IR handoff
//   - sign-rulepack/verify-rulepack/gen-rule-keypair: Ed25519 rule signing
//   - completion: shell completions (bash, zsh, fish)
//   - version: print build info and rule count
//
// # Usage
//
//	skeptic scan --path . --preset ci --format sarif --fail-on high
//	skeptic mcp
//	skeptic serve --scan-interval 5m
//
// See https://github.com/TGPSKI/skeptic for documentation.
package main
