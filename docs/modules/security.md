# security

> Secret redaction, file hashing, and scanner self-integrity checks.

## Responsibility

`internal/security` provides low-level security primitives used across the project: redacting secrets from finding match text, computing and validating SHA256 file hashes, detecting likely hash/token patterns, and verifying the scanner binary's own integrity. It has zero intra-project dependencies.

## Public API

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `SanitizeMatch` | `(value string, redactSecrets bool) string` | Redacts secrets from finding match text when configured. Primary redaction entry point. |
| `RedactSensitiveText` | `(input string) string` | Replaces secret-like patterns (API keys, tokens, passwords) with `[REDACTED]`. |
| `IsLikelyHash` | `(value string) bool` | Detects hex hash patterns (32, 40, 64 char). |
| `NormalizeSHA256` | `(raw string) (string, error)` | Validates and lowercases a SHA256 hex string. |
| `SHA256FileHex` | `(path string) (string, error)` | Computes SHA256 of a file, returns lowercase hex. |
| `VerifySelfIntegrity` | `(binaryPath, expectedHash string) error` | Compares scanner binary SHA256 against expected value. |
| `CheckWorldWritableArtifacts` | `(paths []string) []string` | Returns world-writable paths from the input list. |
| `ParseEd25519PrivateKeyPEM` | `(data []byte) (ed25519.PrivateKey, error)` | Extracts an Ed25519 private key from PKCS8 PEM data. |
| `ParseEd25519PublicKeyPEM` | `(data []byte) (ed25519.PublicKey, error)` | Extracts an Ed25519 public key from PKIX PEM data. |

## Dependencies

None. stdlib-only (`crypto/sha256`, `encoding/hex`, `fmt`, `io`, `os`, `regexp`, `strings`).

## Test Surface

| File | Tests |
|------|-------|
| `security_test.go` | Redaction, hash detection, SHA256 normalization, sanitize match, file hashing |
| `selfcheck_test.go` | Self-integrity match/mismatch, world-writable detection |

```bash
go test ./internal/security -count=1
```

## Related Docs

- [scan module](scan.md) — uses `SanitizeMatch` for finding redaction, `SHA256FileHex` for incremental cache
- [rules module](rules.md) — uses `SHA256FileHex` for rule-pack integrity, `NormalizeSHA256` for hash validation
- [ARCHITECTURE.md](../ARCHITECTURE.md) — security as foundation-layer leaf
