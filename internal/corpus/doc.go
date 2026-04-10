// Package corpus manages an encrypted-at-rest collection of threat artifact
// files used for agentic rule validation and regression testing.
//
// Files are stored with AES-256-GCM encryption, tracked via a SHA256 manifest,
// and scanned in isolation to verify expected rule detections. The corpus
// supports init, fetch, info, scan (with --learn mode), and purge operations.
package corpus
