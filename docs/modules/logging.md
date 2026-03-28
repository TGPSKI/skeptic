# logging

> Thread-safe structured logger with verbosity levels and file output.

## Responsibility

`internal/logging` provides a simple, thread-safe structured logger with four verbosity levels. It decouples log output configuration (stderr, file, quiet/verbose) from the packages that emit log messages. The `Logger` type satisfies `model.ScanLogger` for use in scan options.

## Public API

| Symbol | Signature | Description |
|--------|-----------|-------------|
| `NewLogger` | `(level LogLevel, out io.Writer) *Logger` | Creates a logger at the given verbosity writing to `out`. |
| `SetupLogger` | `(stderr io.Writer, logFilePath string, quiet bool, verbosity int) (*Logger, io.Closer, error)` | Resolves log level, opens optional file, returns logger + closer. |
| `ResolveLogLevel` | `(quiet bool, verbosity int) LogLevel` | Maps `--quiet` / `--verbose` flags to a `LogLevel`. |
| `FilepathAbsExpanded` | `(path string) (string, error)` | Expands `~` and resolves absolute path (uses `model.ExpandHomePath`). |
| `(*Logger).Errorf` | `(format, args...)` | Error-level log (always emitted). |
| `(*Logger).Warnf` | `(format, args...)` | Warning-level log (`LogWarn` and above). |
| `(*Logger).Infof` | `(format, args...)` | Info-level log (`LogInfo` and above). |
| `(*Logger).Debugf` | `(format, args...)` | Debug-level log (`LogDebug` only). |

### Constants

| Name | Value | Description |
|------|-------|-------------|
| `LogError` | 0 | Errors only (default for `--quiet`). |
| `LogWarn` | 1 | Errors + warnings (default). |
| `LogInfo` | 2 | + info messages (`--verbose 1`). |
| `LogDebug` | 3 | + debug messages (`--verbose 2+`). |

## Dependencies

| Package | Why |
|---------|-----|
| `internal/model` | `ExpandHomePath` for `FilepathAbsExpanded` |

## Test Surface

| File | Tests |
|------|-------|
| `logging_test.go` | Level resolution, write filtering, file setup, path expansion |

```bash
go test ./internal/logging -count=1
```

## Related Docs

- [scan module](scan.md) — passes `Logger` to scan engine
- [daemon module](daemon.md) — creates logger for daemon lifecycle
- [CONFIGURATION.md](../CONFIGURATION.md) — `--verbose`, `--quiet`, `--log-file`
