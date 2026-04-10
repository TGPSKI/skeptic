// Package mcp implements a JSON-RPC server that exposes skeptic functionality
// over the Model Context Protocol (MCP) via stdio. It provides tools for
// repository scanning, waiver creation, threat-intel ingestion, and daemon
// bridging. The server supports tool allowlisting, filesystem root restrictions,
// and optional auto-start of the local daemon.
//
// MCP config discovery scans standard editor and IDE configuration paths to
// detect existing MCP server registrations.
package mcp
