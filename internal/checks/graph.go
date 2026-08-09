package checks

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/pathfilter"
	"github.com/TGPSKI/skeptic/internal/security"
)

var testPathPattern = regexp.MustCompile(`(?i)(^|/)(test|tests|testdata|test_data|__tests__|fixtures|test[_-]resources|target|spec|specs|e2e)/`)

func isTestPath(path string) bool {
	return testPathPattern.MatchString(path)
}

// IdentityNode represents a principal or resource in the identity graph.
type IdentityNode struct {
	ID    int
	Kind  string // "principal", "role", "resource", "service-account"
	Name  string
	Props map[string]string
}

// IdentityEdge represents a relationship between identity nodes.
type IdentityEdge struct {
	From   int
	To     int
	Action string // "assume-role", "bind", "impersonate", "access"
}

// IdentityGraph models a unified identity graph for IAM/RBAC/OIDC analysis.
type IdentityGraph struct {
	Nodes []IdentityNode
	Edges []IdentityEdge
	adj   map[int][]int // lazily built adjacency list
}

func (g *IdentityGraph) hasNode(id int) bool {
	for i := range g.Nodes {
		if g.Nodes[i].ID == id {
			return true
		}
	}
	return false
}

func (g *IdentityGraph) ensureAdj() {
	if g.adj != nil {
		return
	}
	g.adj = make(map[int][]int)
	for i := range g.Edges {
		e := &g.Edges[i]
		g.adj[e.From] = append(g.adj[e.From], e.To)
	}
}

// BFS performs breadth-first search from a start node up to maxHops depth.
// Returns all reachable node IDs grouped by hop distance (index i = distance i from start).
func (g *IdentityGraph) BFS(start, maxHops int) [][]int {
	g.ensureAdj()
	if !g.hasNode(start) {
		return nil
	}
	if maxHops < 0 {
		return nil
	}
	visited := make(map[int]bool)
	visited[start] = true
	current := []int{start}
	levels := [][]int{{start}}
	for hop := 0; hop < maxHops; hop++ {
		var next []int
		for _, u := range current {
			for _, v := range g.adj[u] {
				if visited[v] {
					continue
				}
				visited[v] = true
				next = append(next, v)
			}
		}
		if len(next) == 0 {
			break
		}
		levels = append(levels, next)
		current = next
	}
	return levels
}

// BlastRadius returns all nodes reachable from start within maxHops.
func (g *IdentityGraph) BlastRadius(start, maxHops int) []IdentityNode {
	levels := g.BFS(start, maxHops)
	if len(levels) == 0 {
		return nil
	}
	idToNode := make(map[int]IdentityNode, len(g.Nodes))
	for i := range g.Nodes {
		idToNode[g.Nodes[i].ID] = g.Nodes[i]
	}
	var out []IdentityNode
	seen := make(map[int]bool)
	for _, level := range levels {
		for _, id := range level {
			if seen[id] {
				continue
			}
			seen[id] = true
			if n, ok := idToNode[id]; ok {
				out = append(out, n)
			}
		}
	}
	return out
}

var (
	reGraphOIDCFederation = regexp.MustCompile(`(?i)(federation|federated|oidc.*provider|identity.*provider)`)
	reK8sRulesLine        = regexp.MustCompile(`^rules:\s*$`)
)

const defaultMaxIdentityHops = 3

// iamFileResult holds per-file IAM flags and statements for merged graph analysis.
type iamFileResult struct {
	path        string
	hasAssume   bool
	hasWildcard bool
	statements  []iamStatement
}

var reIAMRoleARNName = regexp.MustCompile(`arn:aws:iam::[0-9]+:role/([A-Za-z0-9_+=,.@-]+)`)

// iamPolicyDoc is the structural shape of an AWS IAM JSON policy document.
type iamPolicyDoc struct {
	Statement json.RawMessage `json:"Statement"`
}

type iamStatement struct {
	Effect    string          `json:"Effect"`
	Action    json.RawMessage `json:"Action"`
	Resource  json.RawMessage `json:"Resource"`
	Condition json.RawMessage `json:"Condition,omitempty"`
}

// GraphNode represents a node in the identity attack graph.
type GraphNode struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	File     string `json:"file"`
	HopDepth int    `json:"hop_depth"`
}

// RunIdentityGraphChecks scans IAM, RBAC, and OIDC configs for short paths to sensitive resources.
//
// ignorePaths carries the same --ignore-paths patterns internal/scan applies.
// This walker is independent of that one, so without them a caller who excluded
// a directory would still get GRAPH- findings from it, and those findings would
// still count toward --fail-on.
func RunIdentityGraphChecks(scanRoots []string, maxHops int, redactSecrets bool, ignorePaths []string) []model.Finding {
	if maxHops <= 0 {
		maxHops = defaultMaxIdentityHops
	}
	var findings []model.Finding
	var k8sRBACEntities []RBACEntity
	var iamCollected []iamFileResult
	for _, root := range scanRoots {
		walkErr := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			// Findings report the path relative to the scan root, matching what
			// internal/scan emits. Reporting the walked path put an absolute
			// path in the finding, which no repo-relative ignore pattern could
			// match and which leaked the scanning host's directory layout.
			relPath, relErr := filepath.Rel(root, path)
			if relErr != nil {
				relPath = path
			}
			if d.IsDir() {
				if d.Name() == "node_modules" || d.Name() == ".git" {
					return filepath.SkipDir
				}
				if relPath != "." && pathfilter.Matches(relPath, ignorePaths) {
					return filepath.SkipDir
				}
				return nil
			}
			if pathfilter.Matches(relPath, ignorePaths) {
				return nil
			}
			lower := strings.ToLower(d.Name())
			isRelevant := strings.Contains(lower, "policy") || strings.Contains(lower, "rbac") ||
				strings.Contains(lower, "iam") || strings.Contains(lower, "role") ||
				strings.HasSuffix(lower, ".json") || strings.HasSuffix(lower, ".yaml") ||
				strings.HasSuffix(lower, ".yml")
			if !isRelevant {
				return nil
			}
			info, infoErr := d.Info()
			if infoErr != nil || info.Size() > 2*1024*1024 {
				return nil
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			content := string(data)
			// Read through path, report through relPath.
			if strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml") {
				ents := extractK8sRBACEntities(content)
				for i := range ents {
					ents[i].SourceFile = relPath
				}
				k8sRBACEntities = append(k8sRBACEntities, ents...)
			}
			if r, ok := collectIAMFileResult(relPath, content); ok {
				iamCollected = append(iamCollected, r)
			}
			findings = append(findings, CheckIAMPolicy(relPath, content, maxHops, redactSecrets)...)
			findings = append(findings, CheckOIDCFederation(relPath, content, redactSecrets)...)
			if strings.HasSuffix(lower, ".json") {
				findings = append(findings, CheckAzureRoleAssignment(relPath, content, redactSecrets)...)
				findings = append(findings, CheckGCPIAMBinding(relPath, content, redactSecrets)...)
			}
			return nil
		})
		if walkErr != nil {
			fmt.Fprintf(os.Stderr, "graph_checks: walk error in %s: %v\n", root, walkErr)
		}
	}
	findings = append(findings, crossFileIAMFindings(iamCollected, maxHops, redactSecrets)...)
	findings = append(findings, K8sRBACIdentityGraphFindings(k8sRBACEntities, maxHops, redactSecrets)...)
	findings = append(findings, K8sWebhookFailurePolicyFindings(k8sRBACEntities, redactSecrets)...)
	return findings
}

// collectIAMFileResult parses AWS IAM policy JSON and returns structured per-file IAM data.
func collectIAMFileResult(path, content string) (iamFileResult, bool) {
	var doc iamPolicyDoc
	if json.Unmarshal([]byte(strings.TrimSpace(content)), &doc) != nil {
		return iamFileResult{}, false
	}
	stmts := parseIAMStatements(doc.Statement)
	if len(stmts) == 0 {
		return iamFileResult{}, false
	}
	var r iamFileResult
	r.path = path
	r.statements = stmts
	for i := range stmts {
		st := &stmts[i]
		if !effectIsAllow(st.Effect) {
			continue
		}
		if actionContainsAssumeRole(st.Action) {
			r.hasAssume = true
		}
		if actionMatchesWildcard(st.Action) && resourceIsWildcard(st.Resource) {
			r.hasWildcard = true
		}
	}
	return r, true
}

// crossFileIAMFindings builds a merged identity graph from IAM files and emits GRAPH-005 for multi-file assume-role paths to wildcard resources.
func crossFileIAMFindings(collected []iamFileResult, maxHops int, redact bool) []model.Finding {
	if len(collected) < 2 {
		return nil
	}
	g := buildMergedIAMIdentityGraph(collected)
	if g == nil {
		return nil
	}
	paths := iamCrossFileWildcardPaths(g, maxHops)
	if len(paths) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var findings []model.Finding
	for _, pathIDs := range paths {
		sig := pathSignature(pathIDs)
		if _, dup := seen[sig]; dup {
			continue
		}
		seen[sig] = struct{}{}
		nodes := graphNodesFromIAMPath(g, pathIDs)
		match := encodeGraphNodes(nodes, false)
		if match == "" {
			match = "cross-file iam assume-role chain"
		}
		findings = append(findings, model.Finding{
			RuleID:          "GRAPH-005",
			ConfidenceClass: model.ConfidenceDefinitive,
			Title:           "Cross-file IAM assume-role chain reaches wildcard resources",
			Description:     "Merged identity graph shows principals in one file assuming roles associated with another file that grants wildcard access.",
			Category:        "identity-graph",
			Mitre:           "T1078.004",
			Severity:        model.SeverityCritical,
			File:            representativeIAMPathFile(g, pathIDs),
			Match:           security.SanitizeMatch(match, redact),
		})
	}
	return findings
}

func buildMergedIAMIdentityGraph(collected []iamFileResult) *IdentityGraph {
	b := newK8sGraphBuild()
	for i := range collected {
		c := &collected[i]
		pkey := "iam:P:" + c.path
		pid := b.addNode(pkey, "principal", "principal", map[string]string{"file": c.path})
		rkey := "iam:R:" + c.path
		rid := b.addNode(rkey, "role", "role", map[string]string{"file": c.path})
		if c.hasAssume {
			b.addEdge(pid, rid, "assume-role")
		}
		if c.hasWildcard {
			wkey := "iam:W:" + c.path
			wid := b.addNode(wkey, "wildcard-resource", "*", map[string]string{"file": c.path})
			b.addEdge(rid, wid, "access")
		}
	}
	for i := range collected {
		c := &collected[i]
		pid := b.nodeByKey["iam:P:"+c.path]
		for _, st := range c.statements {
			if !effectIsAllow(st.Effect) {
				continue
			}
			if !actionContainsAssumeRole(st.Action) {
				continue
			}
			for _, roleName := range resourceARNRoleNames(st.Resource) {
				for j := range collected {
					if collected[j].path == c.path {
						continue
					}
					if !iamPathMatchesRoleName(collected[j].path, roleName) {
						continue
					}
					rkey := "iam:R:" + collected[j].path
					if targetR, ok := b.nodeByKey[rkey]; ok {
						b.addEdge(pid, targetR, "cross-assume")
					}
				}
			}
		}
	}
	return b.g
}

func iamPathMatchesRoleName(filePath, roleName string) bool {
	roleName = strings.TrimSpace(roleName)
	if roleName == "" {
		return false
	}
	base := filepath.Base(filePath)
	base = strings.TrimSuffix(base, filepath.Ext(base))
	if strings.EqualFold(base, roleName) {
		return true
	}
	return strings.Contains(strings.ToLower(filePath), strings.ToLower(roleName))
}

// resourceARNRoleNames extracts IAM role name segments from a Resource field for sts:AssumeRole statements.
func resourceARNRoleNames(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var out []string
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return appendRoleNameFromARN(&out, one)
	}
	var arr []string
	if json.Unmarshal(raw, &arr) == nil {
		for _, s := range arr {
			appendRoleNameFromARN(&out, s)
		}
		return out
	}
	return out
}

func appendRoleNameFromARN(out *[]string, s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return *out
	}
	if m := reIAMRoleARNName.FindStringSubmatch(s); len(m) >= 2 {
		*out = append(*out, m[1])
	}
	return *out
}

func iamCrossFileWildcardPaths(g *IdentityGraph, maxHops int) [][]int {
	if g == nil {
		return nil
	}
	var wildcardIDs []int
	var principalIDs []int
	for i := range g.Nodes {
		switch g.Nodes[i].Kind {
		case "wildcard-resource":
			wildcardIDs = append(wildcardIDs, g.Nodes[i].ID)
		case "principal":
			principalIDs = append(principalIDs, g.Nodes[i].ID)
		}
	}
	if len(wildcardIDs) == 0 || len(principalIDs) == 0 {
		return nil
	}
	g.ensureAdj()
	var out [][]int
	seen := make(map[string]struct{})
	for _, start := range principalIDs {
		parent, depth := bfsParents(g, start, maxHops)
		for _, wid := range wildcardIDs {
			if depth[wid] < 0 {
				continue
			}
			path := reconstructPath(parent, start, wid)
			if len(path) < 2 {
				continue
			}
			if !iamPathSpansMultipleFiles(g, path) {
				continue
			}
			sig := pathSignature(path)
			if _, dup := seen[sig]; dup {
				continue
			}
			seen[sig] = struct{}{}
			out = append(out, path)
		}
	}
	return out
}

func iamPathSpansMultipleFiles(g *IdentityGraph, path []int) bool {
	idTo := make(map[int]IdentityNode, len(g.Nodes))
	for i := range g.Nodes {
		idTo[g.Nodes[i].ID] = g.Nodes[i]
	}
	files := make(map[string]struct{})
	for _, id := range path {
		n, ok := idTo[id]
		if !ok {
			continue
		}
		if f := strings.TrimSpace(n.Props["file"]); f != "" {
			files[f] = struct{}{}
		}
	}
	return len(files) >= 2
}

func graphNodesFromIAMPath(g *IdentityGraph, path []int) []GraphNode {
	idTo := make(map[int]IdentityNode, len(g.Nodes))
	for i := range g.Nodes {
		idTo[g.Nodes[i].ID] = g.Nodes[i]
	}
	var nodes []GraphNode
	for hop, id := range path {
		n, ok := idTo[id]
		if !ok {
			continue
		}
		file := strings.TrimSpace(n.Props["file"])
		if file == "" {
			file = "unknown"
		}
		nodes = append(nodes, GraphNode{
			Type:     graphTypeLabel(n),
			Name:     n.Name,
			File:     file,
			HopDepth: hop,
		})
	}
	return nodes
}

func representativeIAMPathFile(g *IdentityGraph, path []int) string {
	idTo := make(map[int]IdentityNode, len(g.Nodes))
	for i := range g.Nodes {
		idTo[g.Nodes[i].ID] = g.Nodes[i]
	}
	for _, id := range path {
		n := idTo[id]
		if f := strings.TrimSpace(n.Props["file"]); f != "" {
			return f
		}
	}
	return "iam-policy.json"
}

func parseIAMStatements(raw json.RawMessage) []iamStatement {
	if len(raw) == 0 {
		return nil
	}
	switch raw[0] {
	case '[':
		var stmts []iamStatement
		if json.Unmarshal(raw, &stmts) != nil {
			return nil
		}
		return stmts
	case '{':
		var one iamStatement
		if json.Unmarshal(raw, &one) != nil {
			return nil
		}
		return []iamStatement{one}
	default:
		return nil
	}
}

func effectIsAllow(effect string) bool {
	return strings.EqualFold(strings.TrimSpace(effect), "Allow")
}

func jsonStringListContainsStar(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return stringIsWildcardToken(s)
	}
	var arr []string
	if json.Unmarshal(raw, &arr) == nil {
		for _, x := range arr {
			if stringIsWildcardToken(x) {
				return true
			}
		}
		return false
	}
	var arrAny []any
	if json.Unmarshal(raw, &arrAny) == nil {
		for _, v := range arrAny {
			if str, ok := v.(string); ok && stringIsWildcardToken(str) {
				return true
			}
		}
	}
	return false
}

func stringIsWildcardToken(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if s == "*" {
		return true
	}
	return strings.Contains(s, "*")
}

func actionMatchesWildcard(raw json.RawMessage) bool {
	return jsonStringListContainsStar(raw)
}

func resourceIsWildcard(raw json.RawMessage) bool {
	return jsonStringListContainsStar(raw)
}

func actionContainsAssumeRole(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return isAssumeRoleAction(s)
	}
	var arr []string
	if json.Unmarshal(raw, &arr) == nil {
		for _, x := range arr {
			if isAssumeRoleAction(x) {
				return true
			}
		}
		return false
	}
	var arrAny []any
	if json.Unmarshal(raw, &arrAny) == nil {
		for _, v := range arrAny {
			if str, ok := v.(string); ok && isAssumeRoleAction(str) {
				return true
			}
		}
	}
	return false
}

func isAssumeRoleAction(s string) bool {
	ls := strings.ToLower(s)
	return strings.Contains(ls, "sts:assumerole") && !strings.Contains(ls, "assumerolepolicy")
}

// iamPathEdges estimates edges from principal to wildcard resource for severity / graph labeling.
func iamWildcardPathEdges(hasAssume, hasWildcard bool) int {
	switch {
	case hasAssume && hasWildcard:
		return 3 // principal → role → permission → resource
	case hasWildcard:
		return 2 // principal → policy grant → resource
	default:
		return 0
	}
}

func graphNodesForIAM(path string, edges int) []GraphNode {
	if edges <= 0 {
		return nil
	}
	names := []struct {
		typ  string
		name string
	}{
		{"principal", "subject"},
		{"role", "assumed-role"},
		{"permission", "policy"},
		{"resource", "*"},
	}
	// Trim chain to match edge count: edges 2 => principal, permission, resource (skip role)
	var nodes []GraphNode
	if edges == 2 {
		nodes = append(nodes,
			GraphNode{Type: "principal", Name: "subject", File: path, HopDepth: 0},
			GraphNode{Type: "permission", Name: "policy", File: path, HopDepth: 1},
			GraphNode{Type: "resource", Name: "*", File: path, HopDepth: 2},
		)
		return nodes
	}
	// edges == 3 full chain
	for i := 0; i < len(names); i++ {
		nodes = append(nodes, GraphNode{Type: names[i].typ, Name: names[i].name, File: path, HopDepth: i})
	}
	return nodes
}

func encodeGraphNodes(nodes []GraphNode, redact bool) string {
	if len(nodes) == 0 {
		return ""
	}
	b, err := json.Marshal(nodes)
	if err != nil {
		return ""
	}
	s := string(b)
	if redact {
		return security.SanitizeMatch(s, true)
	}
	return s
}

// CheckIAMPolicy evaluates AWS IAM JSON policy documents for identity-graph findings.
func CheckIAMPolicy(path string, content string, maxHops int, redact bool) []model.Finding {
	var doc iamPolicyDoc
	if json.Unmarshal([]byte(strings.TrimSpace(content)), &doc) != nil {
		return nil
	}
	stmts := parseIAMStatements(doc.Statement)
	if len(stmts) == 0 {
		return nil
	}

	var findings []model.Finding
	var assumeStmtIdx, wildcardStmtIdx = -1, -1
	hasWildcard := false
	hasAssume := false

	for i := range stmts {
		st := &stmts[i]
		if !effectIsAllow(st.Effect) {
			continue
		}
		if actionContainsAssumeRole(st.Action) {
			hasAssume = true
			if assumeStmtIdx < 0 {
				assumeStmtIdx = i
			}
		}
		if actionMatchesWildcard(st.Action) && resourceIsWildcard(st.Resource) {
			hasWildcard = true
			if wildcardStmtIdx < 0 {
				wildcardStmtIdx = i
			}
		}
	}

	if hasWildcard {
		edges := iamWildcardPathEdges(hasAssume, true)
		sev := model.SeverityCritical
		if edges > 0 && edges >= maxHops {
			sev = model.SeverityHigh
		}
		nodes := graphNodesForIAM(path, edges)
		match := "Action:* Resource:*"
		if len(nodes) > 0 {
			if enc := encodeGraphNodes(nodes, false); enc != "" {
				match = enc
			}
		}
		findings = append(findings, model.Finding{
			RuleID:          "GRAPH-001",
			ConfidenceClass: model.ConfidenceDefinitive,
			Title:           "IAM policy with wildcard action and resource",
			Description:     "Identity can perform any action on any resource, creating a short path to all assets.",
			Category:        "identity-graph",
			Mitre:           "T1078.004",
			Severity:        sev,
			File:            path,
			Match:           security.SanitizeMatch(match, redact),
		})
	}

	// Multi-statement assume-role + wildcard chain
	if hasAssume && hasWildcard && assumeStmtIdx >= 0 && wildcardStmtIdx >= 0 && assumeStmtIdx != wildcardStmtIdx {
		hopCount := 2
		chainNodes := []GraphNode{
			{Type: "principal", Name: "subject", File: path, HopDepth: 0},
			{Type: "role", Name: "assumed-role", File: path, HopDepth: 1},
			{Type: "permission", Name: "policy", File: path, HopDepth: 2},
			{Type: "resource", Name: "*", File: path, HopDepth: 3},
		}
		match := encodeGraphNodes(chainNodes, false)
		if match == "" {
			match = "assume-role chain + wildcard Allow"
		}
		findings = append(findings, model.Finding{
			RuleID:          "GRAPH-004",
			ConfidenceClass: model.ConfidenceDefinitive,
			Title:           "Assume-role chain creates multi-hop access path",
			Description:     "One statement grants sts:AssumeRole while another allows wildcard actions on all resources.",
			Category:        "identity-graph",
			Mitre:           "T1078.004",
			Severity:        model.SeverityCritical,
			File:            path,
			Match:           security.SanitizeMatch(match+" hops="+strconv.Itoa(hopCount), redact),
		})
	}

	return findings
}

// k8sRuleFields holds parsed apiGroups/resources/verbs from a rules: block.
type k8sRuleFields struct {
	apiGroups []string
	resources []string
	verbs     []string
}

// CheckK8sRBAC evaluates Kubernetes RBAC YAML for identity-graph findings using parsed bindings and rules.
func CheckK8sRBAC(path string, content string, maxHops int, redact bool) []model.Finding {
	ents := extractK8sRBACEntities(content)
	for i := range ents {
		ents[i].SourceFile = path
	}
	return K8sRBACIdentityGraphFindings(ents, maxHops, redact)
}

func k8sListHasStar(vals []string) bool {
	for _, v := range vals {
		if stringIsWildcardToken(v) {
			return true
		}
	}
	return false
}

// parseK8sRBACRules performs line-oriented parsing of rules: sections (no YAML library).
func parseK8sRBACRules(lines []string) []k8sRuleFields {
	var out []k8sRuleFields
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		if !isK8sRulesLine(line) {
			continue
		}
		rulesIndent := leadingSpaces(line)
		// Content under rules: until same or lesser indent (non-empty non-comment)
		j := i + 1
		for j < len(lines) {
			l := lines[j]
			if strings.TrimSpace(l) == "" || strings.TrimSpace(strings.Split(l, "#")[0]) == "" {
				j++
				continue
			}
			ls := leadingSpaces(l)
			if ls <= rulesIndent && strings.TrimSpace(l) != "" {
				break
			}
			if k8sLineLooksLikeRuleItem(l, rulesIndent) {
				rule, nextJ := parseK8sRuleBlock(lines, j, rulesIndent)
				if rule != nil {
					out = append(out, *rule)
				}
				j = nextJ
				continue
			}
			j++
		}
	}
	return out
}

func isK8sRulesLine(line string) bool {
	s := strings.TrimSpace(strings.Split(line, "#")[0])
	return reK8sRulesLine.MatchString(s)
}

func leadingSpaces(line string) int {
	n := 0
	for _, r := range line {
		if r == ' ' {
			n++
			continue
		}
		if r == '\t' {
			n += 2
			continue
		}
		break
	}
	return n
}

func k8sLineLooksLikeRuleItem(line string, rulesIndent int) bool {
	ls := leadingSpaces(line)
	if ls <= rulesIndent {
		return false
	}
	s := strings.TrimSpace(strings.Split(line, "#")[0])
	return strings.HasPrefix(s, "- ")
}

func parseK8sRuleBlock(lines []string, start int, rulesIndent int) (*k8sRuleFields, int) {
	itemIndent := leadingSpaces(lines[start])
	var apiGroups, resources, verbs []string
	j := start
	for j < len(lines) {
		l := lines[j]
		if strings.TrimSpace(l) == "" {
			j++
			continue
		}
		ls := leadingSpaces(l)
		trim := strings.TrimSpace(strings.Split(l, "#")[0])
		if j > start && ls == itemIndent && strings.HasPrefix(trim, "- ") {
			break
		}
		if ls < itemIndent && trim != "" {
			break
		}
		key, vals := k8sParseKeyedLine(k8sStripListMarker(l))
		switch key {
		case "apiGroups":
			apiGroups = vals
		case "resources":
			resources = vals
		case "verbs":
			verbs = vals
		}
		j++
	}
	return &k8sRuleFields{apiGroups: apiGroups, resources: resources, verbs: verbs}, j
}

func k8sStripListMarker(line string) string {
	s := strings.TrimSpace(strings.Split(line, "#")[0])
	if strings.HasPrefix(s, "- ") {
		return strings.TrimSpace(s[2:])
	}
	return s
}

func k8sParseKeyedLine(line string) (key string, vals []string) {
	s := strings.TrimSpace(strings.Split(line, "#")[0])
	colon := strings.IndexByte(s, ':')
	if colon < 0 {
		return "", nil
	}
	key = strings.TrimSpace(s[:colon])
	rest := strings.TrimSpace(s[colon+1:])
	if rest == "" || rest == "|" || rest == ">" {
		return key, nil
	}
	if strings.HasPrefix(rest, "[") {
		return key, k8sParseBracketList(rest)
	}
	if strings.HasPrefix(rest, `"`) || strings.HasPrefix(rest, `'`) {
		unq := strings.Trim(rest, `"'`)
		return key, []string{unq}
	}
	return key, []string{rest}
}

func k8sParseBracketList(s string) []string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") {
		return nil
	}
	end := strings.LastIndexByte(s, ']')
	if end < 0 {
		end = len(s)
	}
	inner := s[1:end]
	var out []string
	for _, part := range strings.Split(inner, ",") {
		part = strings.TrimSpace(part)
		part = strings.Trim(part, `"'`)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// CheckOIDCFederation evaluates OIDC federation JSON for audience constraints.
func CheckOIDCFederation(path string, content string, redact bool) []model.Finding {
	if !reGraphOIDCFederation.MatchString(content) {
		return nil
	}
	var parsed map[string]any
	if json.Unmarshal([]byte(content), &parsed) != nil {
		return nil
	}
	var findings []model.Finding
	if _, ok := parsed["audience"]; !ok {
		if _, ok2 := parsed["aud"]; !ok2 {
			severity := model.SeverityHigh
			desc := "Federation config has no audience restriction, allowing broader token acceptance."
			if isTestPath(path) {
				severity = model.SeverityMedium
				desc = "OIDC federation config without audience constraint in test fixture. Bad patterns in test code get copy-pasted into production. Review and add audience binding even in test configs."
			}
			findings = append(findings, model.Finding{
				RuleID:          "GRAPH-003",
				ConfidenceClass: model.ConfidenceDefinitive,
				Title:           "OIDC federation config missing audience constraint",
				Description:     desc,
				Category:        "identity-graph",
				Mitre:           "T1550.001",
				Severity:        severity,
				File:            path,
				Match:           security.SanitizeMatch("missing audience/aud", redact),
			})
		}
	}
	if f := checkGitHubOIDCSubjectCondition(path, content, parsed, redact); f != nil {
		findings = append(findings, *f)
	}
	return findings
}

const githubOIDCSubKey = "token.actions.githubusercontent.com:sub"

// checkGitHubOIDCSubjectCondition emits GRAPH-008 when GitHub Actions OIDC subject conditions are missing or wildcarded.
func checkGitHubOIDCSubjectCondition(path, content string, parsed map[string]any, redact bool) *model.Finding {
	if !githubOIDCFederationContent(content, parsed) {
		return nil
	}
	found, broad := findOIDCConditionSubKeys(any(parsed))
	if !found {
		return &model.Finding{
			RuleID:          "GRAPH-008",
			ConfidenceClass: model.ConfidenceDefinitive,
			Title:           "Overly broad OIDC subject condition",
			Description:     "OIDC federation allows tokens from any repository or branch, enabling cross-repo identity abuse.",
			Category:        "identity-graph",
			Mitre:           "T1550.001",
			Severity:        model.SeverityCritical,
			File:            path,
			Match:           security.SanitizeMatch("missing "+githubOIDCSubKey+" in Condition", redact),
		}
	}
	if broad {
		return &model.Finding{
			RuleID:          "GRAPH-008",
			ConfidenceClass: model.ConfidenceDefinitive,
			Title:           "Overly broad OIDC subject condition",
			Description:     "OIDC federation allows tokens from any repository or branch, enabling cross-repo identity abuse.",
			Category:        "identity-graph",
			Mitre:           "T1550.001",
			Severity:        model.SeverityCritical,
			File:            path,
			Match:           security.SanitizeMatch("wildcard or overly broad "+githubOIDCSubKey, redact),
		}
	}
	return nil
}

func githubOIDCFederationContent(content string, parsed map[string]any) bool {
	lc := strings.ToLower(content)
	if strings.Contains(lc, "token.actions.githubusercontent.com") {
		return true
	}
	if iss, ok := parsed["issuer"].(string); ok && strings.Contains(strings.ToLower(iss), "github") {
		return true
	}
	if iss, ok := parsed["issuerUrl"].(string); ok && strings.Contains(strings.ToLower(iss), "github") {
		return true
	}
	return false
}

// findOIDCConditionSubKeys walks JSON for Condition blocks and inspects StringEquals/StringLike maps for the GitHub Actions subject key.
func findOIDCConditionSubKeys(v any) (foundKey bool, valueIsBroad bool) {
	switch t := v.(type) {
	case map[string]any:
		for _, condKey := range []string{"Condition", "condition"} {
			if raw, ok := t[condKey]; ok {
				f, b := scanOIDCStringEqualsLikeForSub(raw)
				foundKey = foundKey || f
				valueIsBroad = valueIsBroad || b
			}
		}
		for _, child := range t {
			f, b := findOIDCConditionSubKeys(child)
			foundKey = foundKey || f
			valueIsBroad = valueIsBroad || b
		}
	case []any:
		for _, item := range t {
			f, b := findOIDCConditionSubKeys(item)
			foundKey = foundKey || f
			valueIsBroad = valueIsBroad || b
		}
	}
	return foundKey, valueIsBroad
}

func scanOIDCStringEqualsLikeForSub(v any) (foundKey bool, valueIsBroad bool) {
	switch t := v.(type) {
	case map[string]any:
		for _, sk := range []string{"StringEquals", "StringLike", "stringEquals", "stringLike"} {
			if m, ok := t[sk].(map[string]any); ok {
				if val, ok := m[githubOIDCSubKey]; ok {
					foundKey = true
					if stringOrStringSliceIsBroad(val) {
						valueIsBroad = true
					}
				}
			}
		}
		for _, child := range t {
			f, b := scanOIDCStringEqualsLikeForSub(child)
			foundKey = foundKey || f
			valueIsBroad = valueIsBroad || b
		}
	case []any:
		for _, item := range t {
			f, b := scanOIDCStringEqualsLikeForSub(item)
			foundKey = foundKey || f
			valueIsBroad = valueIsBroad || b
		}
	}
	return foundKey, valueIsBroad
}

func stringOrStringSliceIsBroad(v any) bool {
	switch x := v.(type) {
	case string:
		x = strings.TrimSpace(x)
		return x == "" || strings.Contains(x, "*")
	case []any:
		for _, el := range x {
			if s, ok := el.(string); ok && stringOrStringSliceIsBroad(s) {
				return true
			}
		}
		return false
	case []string:
		for _, s := range x {
			if stringOrStringSliceIsBroad(s) {
				return true
			}
		}
		return false
	default:
		return false
	}
}
