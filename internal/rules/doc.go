// Package rules provides the built-in rule set, external rule pack loading,
// Ed25519 signature verification, and rule quality validation for skeptic.
//
// Rules are organized into group files by detection domain: agentic surfaces,
// attack tactics, behavioral signals, identity exposure, and non-code surfaces.
// Each rule is a [model.Rule] struct with an RE2-compatible pattern, severity,
// MITRE ATT&CK mapping, and file-type targeting.
//
// External rule packs are loaded from signed JSON files and merged with the
// built-in set at scan startup. The [BuildRuleSet] function composes the final
// rule slice from all sources.
package rules
