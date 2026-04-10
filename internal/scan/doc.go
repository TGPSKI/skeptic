// Package scan implements the core scan engine: file walking, worker pool
// dispatch, pattern matching, payload decoding, and result aggregation.
//
// The engine uses a configurable worker pool for concurrent file scanning,
// an incremental cache (mtime + size + SHA256) for skipping unchanged files,
// and an Aho-Corasick pre-filter for fast literal keyword elimination.
//
// Payload decoders (base64, hex, gzip, zlib, PowerShell, Unicode, and others)
// recursively decode embedded content with entropy-based bonus depth. Additional
// analysis includes Shannon entropy anomaly detection, NFKC normalization for
// homoglyph evasion, XOR brute-force decoding, and polyglot file detection.
package scan
