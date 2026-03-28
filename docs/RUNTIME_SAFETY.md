# Runtime Safety Guide

This guide documents runtime safety recommendations for bare metal, containers, and Kubernetes-style deployments.

## Core Safety Controls in Code

- Bounded worker pools and file size limits (`--workers`, `--max-bytes`, `--max-files`)
- Incremental cache with deterministic ruleset invalidation
- Secret redaction enabled by default (`--redact-secrets`)
- Detached signature verification support for external rule packs
- Daemon API authentication enabled by default (token-based)
- Loopback-only daemon and MCP defaults
- Bounded MCP frame and daemon response sizes
- Graceful signal handling and scheduler shutdown coordination

## Bare Metal

- Start with `--preset dev` and incremental cache enabled.
- Keep daemon bound to loopback unless remote access is required.
- Store daemon token in a file with least-privilege permissions.
- Persist logs under a protected directory owned by scanner operator.

## Container

- Prefer immutable container images and digest-pinned bases.
- Run scanner with read-only root filesystem where practical.
- Mount only required scan targets and output directories.
- Avoid exposing daemon API outside the pod/network namespace.

## Kubernetes

- Deploy daemon as sidecar or dedicated pod with least-privilege service account.
- Keep daemon service internal-only; avoid public ingress.
- Use short-lived tokens/secrets and rotate through platform secret stores.
- Apply CPU/memory requests/limits to avoid noisy-neighbor impact.
- Keep `allow-unauthenticated` disabled.

## MCP Local Development

- Run MCP bridge and daemon on loopback only.
- Use `--daemon-token-file` instead of inline tokens where possible.
- Keep `--allow-remote-daemon` disabled for local development.
- Keep toolset allowlisted; avoid adding generic shell/file execution tools.
