// Package skeptic is a standalone, stdlib-only Go security scanner that detects
// supply chain compromise, agentic/LLM ecosystem poisoning, CI/CD weaponization,
// and machine-identity abuse. It ships as a single static binary with zero
// runtime dependencies.
//
// skeptic targets structural trust boundary violations — the attack-enabling
// conditions that CVE scanners, SAST tools, and secret scanners do not cover:
// mutable action refs, unsafe pull_request_target patterns, MCP tool shadowing,
// over-permissioned service accounts, and similar misconfigurations.
//
// # Detection domains
//
//   - CI/CD trust boundaries (CI-BUILD, CI-ENV, CI-PRT, CI-SECRET, CI-MUTABLE, ...)
//   - Agentic ecosystem poisoning (AGT-SKL, AGT-MCP, AGT-MEM, AGT-OUT, AGT-TRUST, ...)
//   - Persistence and stealer artifacts (ATK-*, DROP-*, OBF-*, ENC-*)
//   - Machine identity abuse (GRAPH-*, MID-*, CLOUD-ID)
//   - Supply chain structural hygiene (SCM-*, DEP-*, BHV-*)
//
// # Architecture
//
// The CLI entry point lives in [skeptic/cmd/skeptic]. Internal packages under
// [skeptic/internal] implement the scan engine, rule system, configuration,
// reporting, daemon, MCP server, threat-intel ingestion, and supporting
// infrastructure. All packages depend only on the Go standard library.
//
// See https://github.com/TGPSKI/skeptic for full documentation.
package skeptic
