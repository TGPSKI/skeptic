// Package ingest generates signed rule packs from external threat intelligence
// sources. It fetches content from URLs, files, and directories, applies format
// adapters (STIX, Sigma, YARA, URL-based advisories), and produces rule
// specifications that can be signed with Ed25519 and loaded by the scan engine.
package ingest
