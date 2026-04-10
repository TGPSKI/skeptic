// Package checks implements behavioral, dependency, domain, focus, graph, and
// policy analysis passes that run alongside or after pattern matching.
//
// Behavior checks detect multi-step attack chains (ordered and unordered).
// Dependency checks analyze lockfiles and package manifests for supply chain
// indicators. Domain checks perform structural typosquat detection. Graph checks
// build identity graphs across AWS, Azure, GCP, and Kubernetes RBAC configs
// using BFS traversal. Focus checks apply file-type-specific heuristics. Policy
// checks enforce organizational governance rules.
package checks
