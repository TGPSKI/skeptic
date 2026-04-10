// Package daemon implements the skeptic HTTP daemon and its API client.
//
// The daemon provides scheduled background scans, optional filesystem watch,
// and a local HTTP API with health, status, report, metrics, and triggered-scan
// endpoints. It binds to loopback with token authentication by default.
//
// The client provides a bounded HTTP client for interacting with the daemon API
// from the MCP server and CLI subcommands.
package daemon
