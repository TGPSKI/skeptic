// Package correlation performs cross-finding analysis after the primary scan
// completes, surfacing composite risk that individual findings cannot express.
//
// Correlation strategies include per-directory clustering, repo-level rollup,
// content-hash deduplication, file-basename grouping, and git-temporal analysis.
// Drift detection compares the current scan against a prior state file to
// identify new, removed, or changed findings. Correlated findings carry the
// COR-* and DRIFT-* rule ID prefixes.
package correlation
