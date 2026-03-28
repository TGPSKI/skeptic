# Server Reference

skeptic ships two server modes in the same binary: an HTTP daemon for persistent scanning and a stdio MCP server for agentic integration.

## Daemon (`skeptic serve`)

The daemon runs an HTTP API on loopback, executes scheduled scans, and optionally watches for filesystem changes.

### Starting the daemon

```bash
# Foreground with default 5-minute interval
skeptic serve --scan-interval 5m

# Pass scan args after '--'
skeptic serve --scan-interval 2m -- --preset dev --path . --incremental --state-cache .skeptic-state.json

# With explicit auth token file
skeptic serve --auth-token-file .skeptic/daemon.token --scan-interval 5m
```

### HTTP API endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Returns `{"status":"ok"}` when the daemon is running |
| `/status` | GET | Returns daemon runtime state: uptime, scan count, last scan time, scheduler status |
| `/report` | GET | Returns the most recent scan report (JSON) |
| `/metrics` | GET | Returns runtime metrics: scans completed, findings by severity, cache stats |
| `/scan` | POST | Triggers an immediate scan (subject to backlog limit) |

### Authentication

- On startup, the daemon generates an ephemeral bearer token written to a token file (default `.skeptic/daemon.token`).
- All API requests must include `Authorization: Bearer <token>`.
- Use `--auth-token-file` to control the token file location.
- Use `--allow-unauthenticated` to disable authentication (local development only, not recommended).

### Dry-run mode

- `--dry-run`: print the resolved configuration (scan args, auth mode, bind address, schedule, watch config) and exit without starting the daemon

### Profiling

- `--pprof <addr>`: start a pprof HTTP endpoint (e.g., `localhost:6060`) for runtime profiling

### Scheduling

- `--scan-interval <duration>`: periodic scan interval (e.g., `5m`, `1h`)
- `--cron <expr>`: cron expression (e.g., `@every 5m`)
- `--run-on-start`: execute a scan immediately on daemon startup (default `true`)

### Filesystem watch

- `--watch`: enable polling-based filesystem watch
- `--watch-paths <paths>`: comma-separated paths to watch (defaults to scan path)
- Implementation: polling via `filepath.WalkDir`, not OS-native events (`inotify`/`kqueue`)

### Networking

- Binds to `127.0.0.1:7788` by default
- `--bind <addr>`: override bind address
- HTTP timeouts: read 10s, write 30s, idle 60s
- Graceful shutdown on SIGINT/SIGTERM with 5s drain window

### Scan trigger backlog

Only one pending trigger is queued at a time (`MaxDaemonScanTriggerBacklog = 1`). Additional trigger requests while a scan is running return an error.

## MCP Server (`skeptic mcp`)

The MCP server runs as a stdio JSON-RPC process that bridges MCP clients (Cursor, Claude Desktop, etc.) to skeptic's scanning and ingestion capabilities.

### Starting the MCP server

```bash
# Connect to a running daemon
skeptic mcp --daemon-url http://127.0.0.1:7788

# With token file
skeptic mcp --daemon-url http://127.0.0.1:7788 --daemon-token-file .skeptic/daemon.token
```

### MCP tools

| Tool | Condition | Description |
|------|-----------|-------------|
| `skeptic_daemon_health` | always | Check daemon health (`GET /health`) |
| `skeptic_daemon_status` | always | Get daemon runtime status (`GET /status`) |
| `skeptic_daemon_report` | always | Retrieve latest scan report (`GET /report`) |
| `skeptic_daemon_metrics` | always | Fetch Prometheus-format metrics (`GET /metrics`) |
| `skeptic_scan_repo` | always | Scan a local repository path with configurable profile, mode, preset, and style |
| `skeptic_waive` | always | Create SHA256-pinned waivers. Parameters: `repo_path` (required), `reason` (required), `file`, `rule`. At least one of `file` or `rule` is required. |
| `skeptic_daemon_trigger_scan` | `--allow-trigger` | Trigger an immediate daemon scan with configurable cooldown |
| `skeptic_ingest_url_to_rulepack` | `--allow-ingest` | Ingest a URL into a local rule pack file (host allowlist enforced) |
| `skeptic_approve_ingest` | `--require-ingest-approval` | Approve a pending ingest request |

### `skeptic_scan_repo` parameters and output

**Parameters** (in addition to required `repo_path`):

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `mode` | enum | `developer` | Operating mode: `developer`, `ir`, `deep` |
| `preset` | enum | — | Named preset: `quick`, `dev`, `ci`, `hunt`, `machine-identity`, `ai-workload` |
| `profile` | enum | `repo` | Scan profile: `repo`, `developer`, `container`, `fullfs` |
| `scan_style` | enum | `hybrid` | Scan style: `pattern`, `behavior`, `hybrid` |
| `threat_mode` | enum | `all` | Threat focus: `all`, `machine-identity`, `ai-workload` |
| `fail_on` | enum | `none` | Severity threshold: `none`, `info`, `low`, `medium`, `high`, `critical` |
| `include_rules` | string | — | Comma-separated rule IDs or prefixes to include |
| `exclude_rules` | string | — | Comma-separated rule IDs or prefixes to exclude |
| `incremental` | boolean | `false` | Enable mtime+size scan cache |
| `baseline` | string | — | Path to baseline JSON report for diff scanning |
| `diff_only` | boolean | `false` | Return only new/changed findings when baseline is set |
| `workers` | integer | CPU count | Concurrent scan workers |
| `max_files` | integer | 200000 | Max scanned files |
| `max_findings` | integer | 500 | Max findings retained |
| `sample_limit` | integer | 25 | Sample findings in response (max 200) |
| `require_git` | boolean | `true` | Require `.git` directory to exist |

These map to the same CLI semantics as their `--` equivalents.

**`trust_assessment`** (object): produced by `internal/mcp.BuildTrustAssessment` from the scan report. Fields:

| Field | Meaning |
|-------|---------|
| `verdict` | One of `action_required`, `review_advised`, `no_issues_found` (softened summary for agents) |
| `definitive_count` | Count of findings with confidence class `definitive` |
| `heuristic_count` | Count of findings with confidence class `heuristic` |
| `correlated_count` | Count of findings with confidence class `correlated` |
| `risk_areas` | Array of objects: `category`, `count`, `max_severity`, `confidence` (per-area rollup) |
| `review_priority` | Array of file paths (up to 10) ranked for human review |

**Verdict values:** `action_required` (definitive + gate-eligible + critical in developer framing), `review_advised` (e.g. definitive high gate-eligible, or enough critical heuristics), `no_issues_found` (none of the above).

The tool response also includes `mode`, `risk_score` (0–100), severity histograms, confidence breakdowns, and sample findings with `confidence_class` per finding.

### MCP resources

| URI | Description |
|-----|-------------|
| `skeptic://rules/builtin` | List all built-in rule IDs and descriptions |
| `skeptic://rules/external` | Loaded external rule pack metadata |
| `skeptic://report/latest` | Most recent scan report summary |
| `skeptic://config/active` | Server configuration: enabled tools, scan roots, cooldown, rule count |

### Security controls

- **Loopback enforcement**: MCP server validates daemon URLs are loopback-only by default
- **Bearer token pass-through**: daemon token loaded from file or environment
- **Tool allowlist**: only the tools listed above are accepted; all others are rejected
- **Trigger cooldown**: configurable minimum interval between scan triggers
- **Ingest approval gate**: when `--require-ingest-approval` is set, URL ingestions require explicit human approval via `skeptic_approve_ingest`
- **Audit logging**: all tool invocations are logged with timestamp, tool name, status, duration, and arguments
- **Bounded frames**: MCP message size capped at 8 MiB; daemon response size bounded
- **Response integrity**: tool results include SHA256 hash of response content

### Auto-daemon mode

The MCP server can automatically start and stop a child daemon process, removing the need to manage the daemon separately:

```bash
skeptic mcp --auto-daemon --auto-daemon-args "--scan-interval 5m --auth-token-file .skeptic/daemon.token"
```

When `--auto-daemon` is set, the MCP server:
- Starts a daemon child process on launch using the provided arguments
- Connects to the child daemon via loopback
- Stops the child daemon on MCP server shutdown

This simplifies agentic workflows — a single MCP config entry in Cursor or Claude Desktop is sufficient without a separate daemon terminal.

### IDE integration

Add skeptic as an MCP server in your IDE config:

**Cursor** (`.cursor/mcp.json` in workspace root or `~/.cursor/mcp.json` globally):

```json
{
  "mcpServers": {
    "skeptic": {
      "command": "skeptic",
      "args": [
        "mcp",
        "--auto-daemon",
        "--auto-daemon-args", "--scan-interval 5m --preset dev --path ."
      ]
    }
  }
}
```

**Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "skeptic": {
      "command": "skeptic",
      "args": [
        "mcp",
        "--auto-daemon",
        "--auto-daemon-args", "--scan-interval 5m --preset dev --path ."
      ]
    }
  }
}
```

> **Tip:** If you have `skeptic` installed at a non-standard path, use the full binary path in `"command"`. Use `--auto-daemon-args` to pass any `skeptic serve` flags (schedule, auth, path, preset) to the child daemon.

### MCP client auto-discovery

`skeptic` can auto-discover MCP client configurations across 10 platforms (Cursor, Claude Desktop, VS Code, etc.) to detect risky MCP configurations as scan findings (`DISC-MCP-*`). This is a scan feature (`--auto-discover-mcp`), not an MCP server feature.

## Security posture summary

Both server modes follow the same security philosophy:

- **Loopback by default**: no remote network exposure unless explicitly configured
- **Auth by default**: bearer token authentication enabled out of the box
- **No arbitrary execution**: neither daemon nor MCP server executes arbitrary shell commands
- **Bounded resources**: timeouts, message size limits, and scan backlog limits prevent resource exhaustion
- **Audit trail**: MCP audit log records all tool invocations for security review
