// Package config handles configuration file loading, preset resolution, profile
// management, and CLI flag registration for skeptic.
//
// Configuration sources are resolved in precedence order: mode defaults, preset
// overrides, config file values, and explicit CLI flags. Config files may be
// JSON, YAML, or .env format and are auto-discovered from the scan root or
// XDG config directories.
//
// The package also provides the init, config show, and config use subcommand
// implementations.
package config
