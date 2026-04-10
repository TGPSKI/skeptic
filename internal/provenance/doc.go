// Package provenance verifies dependency provenance by comparing installed
// artifact hashes against expected values from lockfiles and SBOM documents.
// It supports SPDX and CycloneDX SBOM formats and cross-references package
// checksums to detect tampering or substitution.
package provenance
