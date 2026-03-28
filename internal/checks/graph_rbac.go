package checks

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/security"
)

// RBACSubject is a binding subject (ServiceAccount, User, Group, etc.).
type RBACSubject struct {
	Kind      string
	Name      string
	Namespace string
}

// WebhookPolicyEntry captures a single webhook entry from an admission configuration document.
type WebhookPolicyEntry struct {
	Name          string
	FailurePolicy string
}

// RBACEntity is one Kubernetes RBAC document (split on ---), with optional rules or binding fields.
type RBACEntity struct {
	DocKind       string // Role, ClusterRole, RoleBinding, ClusterRoleBinding, ValidatingWebhookConfiguration, MutatingWebhookConfiguration
	MetaName      string
	MetaNamespace string
	Rules         []k8sRuleFields
	RoleRefKind   string
	RoleRefName   string
	Subjects      []RBACSubject
	Webhooks      []WebhookPolicyEntry
	SourceFile    string
}

var (
	reYAMLKindLine = regexp.MustCompile(`(?m)^kind:\s*([A-Za-z][A-Za-z0-9]*)\s*(?:#.*)?$`)
	reYAMLDocSplit = regexp.MustCompile(`(?m)^---\s*$`)
)

// splitYAMLDocuments splits multi-document YAML on ^---$ lines.
func splitYAMLDocuments(content string) []string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	content = strings.TrimSpace(content)
	if content == "" {
		return nil
	}
	parts := reYAMLDocSplit.Split(content, -1)
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{content}
	}
	return out
}

// extractK8sRBACEntities parses Role, ClusterRole, RoleBinding, and ClusterRoleBinding documents.
func extractK8sRBACEntities(content string) []RBACEntity {
	var entities []RBACEntity
	for _, doc := range splitYAMLDocuments(content) {
		m := reYAMLKindLine.FindStringSubmatch(doc)
		if len(m) < 2 {
			continue
		}
		kind := strings.TrimSpace(m[1])
		switch kind {
		case "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding":
			ent := parseRBACDoc(doc, kind)
			if ent != nil {
				entities = append(entities, *ent)
			}
		case "ValidatingWebhookConfiguration", "MutatingWebhookConfiguration":
			ent := parseWebhookConfigurationDoc(doc, kind)
			if ent != nil {
				entities = append(entities, *ent)
			}
		}
	}
	return entities
}

func parseRBACDoc(doc, kind string) *RBACEntity {
	lines := strings.Split(doc, "\n")
	name, ns := parseK8sMetadataBlock(lines)
	ent := &RBACEntity{
		DocKind:       kind,
		MetaName:      name,
		MetaNamespace: ns,
	}
	switch kind {
	case "Role", "ClusterRole":
		ent.Rules = parseK8sRBACRules(lines)
	case "RoleBinding", "ClusterRoleBinding":
		ent.RoleRefKind, ent.RoleRefName = parseK8sRoleRefBlock(lines)
		ent.Subjects = parseK8sSubjectsBlock(lines, ns)
	}
	return ent
}

// parseWebhookConfigurationDoc parses ValidatingWebhookConfiguration or MutatingWebhookConfiguration documents.
func parseWebhookConfigurationDoc(doc, kind string) *RBACEntity {
	lines := strings.Split(doc, "\n")
	name, ns := parseK8sMetadataBlock(lines)
	return &RBACEntity{
		DocKind:       kind,
		MetaName:      name,
		MetaNamespace: ns,
		Webhooks:      parseK8sWebhooksBlock(lines),
	}
}

func parseK8sWebhooksBlock(lines []string) []WebhookPolicyEntry {
	for i := 0; i < len(lines); i++ {
		trim := strings.TrimSpace(strings.Split(lines[i], "#")[0])
		if trim != "webhooks:" {
			continue
		}
		webhooksIndent := leadingSpaces(lines[i])
		var entries []WebhookPolicyEntry
		j := i + 1
		for j < len(lines) {
			l := lines[j]
			if strings.TrimSpace(l) == "" {
				j++
				continue
			}
			ls := leadingSpaces(l)
			t := strings.TrimSpace(strings.Split(l, "#")[0])
			if ls <= webhooksIndent && t != "" {
				break
			}
			if ls > webhooksIndent && strings.HasPrefix(t, "- ") {
				entry, next := parseK8sWebhookItem(lines, j, webhooksIndent)
				if entry.Name != "" || entry.FailurePolicy != "" {
					entries = append(entries, entry)
				}
				j = next
				continue
			}
			j++
		}
		return entries
	}
	return nil
}

func parseK8sWebhookItem(lines []string, start int, webhooksIndent int) (WebhookPolicyEntry, int) {
	itemIndent := leadingSpaces(lines[start])
	var ent WebhookPolicyEntry
	first := strings.TrimSpace(strings.Split(lines[start], "#")[0])
	rest := strings.TrimSpace(strings.TrimPrefix(first, "-"))
	if rest != "" {
		key, vals := k8sParseKeyedLine(rest)
		switch key {
		case "name":
			if len(vals) > 0 {
				ent.Name = vals[0]
			}
		case "failurePolicy":
			if len(vals) > 0 {
				ent.FailurePolicy = vals[0]
			}
		}
	}
	j := start + 1
	for j < len(lines) {
		l := lines[j]
		if strings.TrimSpace(l) == "" {
			j++
			continue
		}
		ls := leadingSpaces(l)
		t := strings.TrimSpace(strings.Split(l, "#")[0])
		if ls == itemIndent && strings.HasPrefix(t, "- ") {
			break
		}
		if ls < itemIndent && t != "" {
			break
		}
		if ls < itemIndent {
			j++
			continue
		}
		key, vals := k8sParseKeyedLine(l)
		switch key {
		case "name":
			if len(vals) > 0 {
				ent.Name = vals[0]
			}
		case "failurePolicy":
			if len(vals) > 0 {
				ent.FailurePolicy = vals[0]
			}
		}
		j++
	}
	return ent, j
}

func parseK8sMetadataBlock(lines []string) (name, namespace string) {
	for i := 0; i < len(lines); i++ {
		trim := strings.TrimSpace(strings.Split(lines[i], "#")[0])
		if trim != "metadata:" {
			continue
		}
		base := leadingSpaces(lines[i])
		for j := i + 1; j < len(lines); j++ {
			l := lines[j]
			if strings.TrimSpace(l) == "" {
				continue
			}
			ls := leadingSpaces(l)
			t := strings.TrimSpace(strings.Split(l, "#")[0])
			if ls <= base && t != "" {
				break
			}
			key, vals := k8sParseKeyedLine(l)
			switch key {
			case "name":
				if len(vals) > 0 {
					name = vals[0]
				}
			case "namespace":
				if len(vals) > 0 {
					namespace = vals[0]
				}
			}
		}
		return name, namespace
	}
	return "", ""
}

func parseK8sRoleRefBlock(lines []string) (kind, name string) {
	for i := 0; i < len(lines); i++ {
		trim := strings.TrimSpace(strings.Split(lines[i], "#")[0])
		if trim != "roleRef:" {
			continue
		}
		base := leadingSpaces(lines[i])
		for j := i + 1; j < len(lines); j++ {
			l := lines[j]
			if strings.TrimSpace(l) == "" {
				continue
			}
			ls := leadingSpaces(l)
			t := strings.TrimSpace(strings.Split(l, "#")[0])
			if ls <= base && t != "" {
				break
			}
			key, vals := k8sParseKeyedLine(l)
			switch key {
			case "kind":
				if len(vals) > 0 {
					kind = vals[0]
				}
			case "name":
				if len(vals) > 0 {
					name = vals[0]
				}
			}
		}
		return kind, name
	}
	return "", ""
}

func parseK8sSubjectsBlock(lines []string, bindingNS string) []RBACSubject {
	for i := 0; i < len(lines); i++ {
		trim := strings.TrimSpace(strings.Split(lines[i], "#")[0])
		if trim != "subjects:" {
			continue
		}
		subjectsIndent := leadingSpaces(lines[i])
		var subs []RBACSubject
		j := i + 1
		for j < len(lines) {
			l := lines[j]
			if strings.TrimSpace(l) == "" {
				j++
				continue
			}
			ls := leadingSpaces(l)
			t := strings.TrimSpace(strings.Split(l, "#")[0])
			if ls <= subjectsIndent && t != "" {
				break
			}
			if ls > subjectsIndent && strings.HasPrefix(t, "- ") {
				sub, next := parseK8sSubjectItem(lines, j, subjectsIndent)
				if sub != nil {
					subs = append(subs, *sub)
				}
				j = next
				continue
			}
			j++
		}
		if bindingNS != "" {
			for k := range subs {
				if subs[k].Namespace == "" && strings.EqualFold(subs[k].Kind, "ServiceAccount") {
					subs[k].Namespace = bindingNS
				}
			}
		}
		return subs
	}
	return nil
}

func parseK8sSubjectItem(lines []string, start int, subjectsIndent int) (*RBACSubject, int) {
	itemIndent := leadingSpaces(lines[start])
	var sub RBACSubject
	first := strings.TrimSpace(strings.Split(lines[start], "#")[0])
	rest := strings.TrimSpace(strings.TrimPrefix(first, "-"))
	if rest != "" {
		key, vals := k8sParseKeyedLine(rest)
		if key == "kind" && len(vals) > 0 {
			sub.Kind = vals[0]
		}
		if key == "name" && len(vals) > 0 {
			sub.Name = vals[0]
		}
		if key == "namespace" && len(vals) > 0 {
			sub.Namespace = vals[0]
		}
	}
	j := start + 1
	for j < len(lines) {
		l := lines[j]
		if strings.TrimSpace(l) == "" {
			j++
			continue
		}
		ls := leadingSpaces(l)
		t := strings.TrimSpace(strings.Split(l, "#")[0])
		if ls == itemIndent && strings.HasPrefix(t, "- ") {
			break
		}
		if ls < itemIndent && t != "" {
			break
		}
		if ls < itemIndent {
			j++
			continue
		}
		key, vals := k8sParseKeyedLine(l)
		switch key {
		case "kind":
			if len(vals) > 0 {
				sub.Kind = vals[0]
			}
		case "name":
			if len(vals) > 0 {
				sub.Name = vals[0]
			}
		case "namespace":
			if len(vals) > 0 {
				sub.Namespace = vals[0]
			}
		}
		j++
	}
	if sub.Name == "" {
		return nil, j
	}
	return &sub, j
}

func roleEntityStableKey(kind, metaName, metaNamespace string) string {
	switch kind {
	case "ClusterRole":
		return "ClusterRole::" + metaName
	case "Role":
		return "Role:" + metaNamespace + ":" + metaName
	default:
		return ""
	}
}

func resolvedRoleRefKey(bindingKind, bindingNS, roleRefKind, roleRefName string) string {
	rk := strings.TrimSpace(roleRefKind)
	switch rk {
	case "ClusterRole":
		return "ClusterRole::" + roleRefName
	case "Role":
		ns := bindingNS
		if bindingKind == "RoleBinding" {
			return "Role:" + ns + ":" + roleRefName
		}
		// RoleBinding must be namespaced; ClusterRoleBinding + Role ref is invalid in real K8s but keep key consistent
		return "Role:" + ns + ":" + roleRefName
	default:
		return ""
	}
}

func subjectPrincipalKey(sub RBACSubject, bindingNS string) string {
	k := strings.TrimSpace(sub.Kind)
	n := strings.TrimSpace(sub.Name)
	switch strings.ToLower(k) {
	case "serviceaccount":
		ns := strings.TrimSpace(sub.Namespace)
		if ns == "" {
			ns = bindingNS
		}
		return "ServiceAccount:" + ns + ":" + n
	case "user":
		return "User::" + n
	case "group":
		return "Group::" + n
	default:
		return strings.TrimSpace(k) + "::" + n
	}
}

func roleHasWildcardRules(rules []k8sRuleFields) bool {
	for _, rule := range rules {
		if k8sListHasStar(rule.verbs) && k8sListHasStar(rule.resources) {
			return true
		}
	}
	return false
}

type k8sGraphBuild struct {
	g         *IdentityGraph
	nodeByKey map[string]int
	nextID    int
}

func newK8sGraphBuild() *k8sGraphBuild {
	return &k8sGraphBuild{
		g:         &IdentityGraph{},
		nodeByKey: make(map[string]int),
		nextID:    0,
	}
}

func (b *k8sGraphBuild) addNode(key, kind, displayName string, props map[string]string) int {
	if id, ok := b.nodeByKey[key]; ok {
		return id
	}
	id := b.nextID
	b.nextID++
	b.nodeByKey[key] = id
	if props == nil {
		props = map[string]string{}
	}
	b.g.Nodes = append(b.g.Nodes, IdentityNode{
		ID:    id,
		Kind:  kind,
		Name:  displayName,
		Props: props,
	})
	return id
}

func (b *k8sGraphBuild) addEdge(from, to int, action string) {
	if from < 0 || to < 0 {
		return
	}
	b.g.Edges = append(b.g.Edges, IdentityEdge{From: from, To: to, Action: action})
}

// buildIdentityGraphFromRBACEntities merges Role/ClusterRole rules and bindings into one graph.
func buildIdentityGraphFromRBACEntities(entities []RBACEntity) *IdentityGraph {
	b := newK8sGraphBuild()
	// Roles with rules
	for i := range entities {
		e := &entities[i]
		if e.DocKind != "Role" && e.DocKind != "ClusterRole" {
			continue
		}
		key := roleEntityStableKey(e.DocKind, e.MetaName, e.MetaNamespace)
		if key == "" {
			continue
		}
		kind := "cluster-role"
		if e.DocKind == "Role" {
			kind = "role"
		}
		b.addNode(key, kind, e.MetaName, map[string]string{
			"namespace": e.MetaNamespace,
			"source":    e.SourceFile,
		})
		if roleHasWildcardRules(e.Rules) {
			wkey := "Wildcard:" + key
			b.addNode(wkey, "wildcard-resource", "*", map[string]string{"roleKey": key})
			roleID := b.nodeByKey[key]
			wid := b.nodeByKey[wkey]
			b.addEdge(roleID, wid, "access")
		}
	}
	// Bindings
	for i := range entities {
		e := &entities[i]
		if e.DocKind != "RoleBinding" && e.DocKind != "ClusterRoleBinding" {
			continue
		}
		rkey := resolvedRoleRefKey(e.DocKind, e.MetaNamespace, e.RoleRefKind, e.RoleRefName)
		if rkey == "" {
			continue
		}
		roleID, ok := b.nodeByKey[rkey]
		if !ok {
			// Role/ClusterRole not in corpus; still create stub role node so bindings attach
			kind := "cluster-role"
			if strings.HasPrefix(rkey, "Role:") {
				kind = "role"
			}
			parts := strings.SplitN(rkey, ":", 3)
			display := e.RoleRefName
			ns := ""
			if len(parts) >= 3 && parts[0] == "Role" {
				ns = parts[1]
				display = parts[2]
			}
			roleID = b.addNode(rkey, kind, display, map[string]string{"namespace": ns, "stub": "true"})
		}
		for _, sub := range e.Subjects {
			pkey := subjectPrincipalKey(sub, e.MetaNamespace)
			pid := b.addNode(pkey, principalKindForSubject(sub), sub.Name, map[string]string{
				"subjectKind": sub.Kind,
				"namespace":   sub.Namespace,
				"source":      e.SourceFile,
			})
			b.addEdge(pid, roleID, "bind")
		}
	}
	return b.g
}

func principalKindForSubject(sub RBACSubject) string {
	switch strings.ToLower(strings.TrimSpace(sub.Kind)) {
	case "serviceaccount":
		return "service-account"
	default:
		return "principal"
	}
}

// k8sRBACWildcardPaths returns principal-to-wildcard paths using BFS with parent links (edge budget maxHops).
func k8sRBACWildcardPaths(g *IdentityGraph, maxHops int) [][]int {
	if g == nil {
		return nil
	}
	wildcardIDs := make(map[int]struct{})
	for i := range g.Nodes {
		if g.Nodes[i].Kind == "wildcard-resource" {
			wildcardIDs[g.Nodes[i].ID] = struct{}{}
		}
	}
	if len(wildcardIDs) == 0 {
		return nil
	}
	var principalIDs []int
	for i := range g.Nodes {
		n := &g.Nodes[i]
		if n.Kind == "service-account" || n.Kind == "principal" {
			principalIDs = append(principalIDs, n.ID)
		}
	}
	g.ensureAdj()
	var paths [][]int
	seenPath := make(map[string]struct{})
	for _, start := range principalIDs {
		parent, depth := bfsParents(g, start, maxHops)
		for wid := range wildcardIDs {
			if depth[wid] < 0 {
				continue
			}
			path := reconstructPath(parent, start, wid)
			if len(path) == 0 {
				continue
			}
			sig := pathSignature(path)
			if _, dup := seenPath[sig]; dup {
				continue
			}
			seenPath[sig] = struct{}{}
			paths = append(paths, path)
		}
	}
	return paths
}

// bfsParents runs BFS up to maxHops edge traversals; returns parent map and depth (-1 if unreachable).
func bfsParents(g *IdentityGraph, start int, maxHops int) (map[int]int, map[int]int) {
	parent := make(map[int]int)
	depth := make(map[int]int)
	if !g.hasNode(start) {
		return parent, depth
	}
	if maxHops < 0 {
		return parent, depth
	}
	depth[start] = 0
	q := []int{start}
	qi := 0
	for qi < len(q) {
		u := q[qi]
		qi++
		if depth[u] >= maxHops {
			continue
		}
		for _, v := range g.adj[u] {
			if _, seen := depth[v]; seen {
				continue
			}
			depth[v] = depth[u] + 1
			parent[v] = u
			q = append(q, v)
		}
	}
	for _, n := range g.Nodes {
		if _, ok := depth[n.ID]; !ok {
			depth[n.ID] = -1
		}
	}
	return parent, depth
}

func reconstructPath(parent map[int]int, start, end int) []int {
	if start == end {
		return []int{start}
	}
	var path []int
	cur := end
	for cur != start {
		p, ok := parent[cur]
		if !ok {
			return nil
		}
		path = append(path, cur)
		cur = p
	}
	path = append(path, start)
	// reverse
	for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
		path[i], path[j] = path[j], path[i]
	}
	return path
}

func pathSignature(path []int) string {
	var b strings.Builder
	for i, id := range path {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(strconv.Itoa(id))
	}
	return b.String()
}

func graphNodesFromPath(g *IdentityGraph, path []int, file string) []GraphNode {
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
		nodes = append(nodes, GraphNode{
			Type:     graphTypeLabel(n),
			Name:     n.Name,
			File:     file,
			HopDepth: hop,
		})
	}
	return nodes
}

func graphTypeLabel(n IdentityNode) string {
	switch n.Kind {
	case "service-account":
		return "service-account"
	case "role", "cluster-role":
		return n.Kind
	case "wildcard-resource":
		return "resource"
	default:
		return n.Kind
	}
}

// K8sRBACIdentityGraphFindings analyzes merged RBAC entities and emits GRAPH-002 for wildcard reachability.
func K8sRBACIdentityGraphFindings(entities []RBACEntity, maxHops int, redact bool) []model.Finding {
	if len(entities) == 0 {
		return nil
	}
	g := buildIdentityGraphFromRBACEntities(entities)
	paths := k8sRBACWildcardPaths(g, maxHops)
	var findings []model.Finding
	// Pick a representative file from first binding touching the path
	for _, path := range paths {
		file := representativePathFile(g, path, entities)
		nodes := graphNodesFromPath(g, path, file)
		edges := len(path) - 1
		if edges < 0 {
			edges = 0
		}
		sev := model.SeverityHigh
		if edges < maxHops {
			sev = model.SeverityCritical
		}
		match := encodeGraphNodes(nodes, false)
		if match == "" {
			match = "k8s rbac wildcard path"
		}
		apiHint := k8sAPIHintFromPath(g, path)
		if apiHint != "" {
			match = match + " " + apiHint
		}
		findings = append(findings, model.Finding{
			RuleID:          "GRAPH-002",
			ConfidenceClass: model.ConfidenceDefinitive,
			Title:           "K8s RBAC role with wildcard verbs and resources",
			Description:     "RBAC rule grants all verbs on all resources; identity graph shows a path from a bound principal within the configured hop budget.",
			Category:        "identity-graph",
			Mitre:           "T1078.001",
			Severity:        sev,
			File:            file,
			Match:           security.SanitizeMatch(match, redact),
		})
	}
	for _, e := range entities {
		if e.DocKind != "Role" && e.DocKind != "ClusterRole" {
			continue
		}
		for _, rule := range e.Rules {
			if !k8sListHasStar(rule.verbs) {
				continue
			}
			if !k8sResourceListCoversSecrets(rule.resources) {
				continue
			}
			match := e.MetaName + " verbs=* resources=secrets"
			if e.SourceFile != "" {
				match = match + " file=" + e.SourceFile
			}
			findings = append(findings, model.Finding{
				RuleID:      "GRAPH-009",
				Title:       "K8s RBAC role with wildcard verbs on secrets",
				Description: "RBAC rule grants all verbs on Secret objects, enabling broad credential access from bound principals.",
				Category:    "identity-graph",
				Mitre:       "T1078.001",
				Severity:    model.SeverityHigh,
				File:        firstNonEmpty(e.SourceFile, "rbac.yaml"),
				Match:       security.SanitizeMatch(match, redact),
			})
		}
	}
	return findings
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// k8sResourceListCoversSecrets reports whether rules target Secret API resources or all resources.
func k8sResourceListCoversSecrets(resources []string) bool {
	for _, r := range resources {
		rs := strings.TrimSpace(strings.ToLower(r))
		if rs == "" {
			continue
		}
		if stringIsWildcardToken(r) || rs == "secrets" || strings.Contains(rs, "secrets") {
			return true
		}
	}
	return false
}

// K8sWebhookFailurePolicyFindings reports admission webhooks configured with Ignore failure policy.
func K8sWebhookFailurePolicyFindings(entities []RBACEntity, redact bool) []model.Finding {
	var out []model.Finding
	for i := range entities {
		e := &entities[i]
		if e.DocKind != "ValidatingWebhookConfiguration" && e.DocKind != "MutatingWebhookConfiguration" {
			continue
		}
		for _, w := range e.Webhooks {
			if !strings.EqualFold(strings.TrimSpace(w.FailurePolicy), "Ignore") {
				continue
			}
			match := e.DocKind + " name=" + w.Name + " failurePolicy=Ignore"
			out = append(out, model.Finding{
				RuleID:          "GRAPH-010",
				ConfidenceClass: model.ConfidenceDefinitive,
				Title:           "Webhook with Ignore failure policy",
				Description:     "Admission webhook ignores failures, allowing invalid or malicious resources when the webhook endpoint is unavailable or misconfigured.",
				Category:        "identity-graph",
				Mitre:           "",
				Severity:        model.SeverityMedium,
				File:            firstNonEmpty(e.SourceFile, "webhook.yaml"),
				Match:           security.SanitizeMatch(match, redact),
			})
		}
	}
	return out
}

func k8sAPIHintFromPath(g *IdentityGraph, path []int) string {
	idTo := make(map[int]IdentityNode, len(g.Nodes))
	for i := range g.Nodes {
		idTo[g.Nodes[i].ID] = g.Nodes[i]
	}
	for _, id := range path {
		n := idTo[id]
		if n.Kind != "role" && n.Kind != "cluster-role" {
			continue
		}
		if ns := n.Props["namespace"]; ns != "" {
			return "apiGroups:(core) namespace:" + ns
		}
		return "apiGroups:(core)"
	}
	return ""
}

func representativePathFile(g *IdentityGraph, path []int, entities []RBACEntity) string {
	idTo := make(map[int]IdentityNode, len(g.Nodes))
	for i := range g.Nodes {
		idTo[g.Nodes[i].ID] = g.Nodes[i]
	}
	// Prefer binding source for an edge in path
	for _, id := range path {
		n := idTo[id]
		if n.Kind == "service-account" || n.Kind == "principal" {
			if src := strings.TrimSpace(n.Props["source"]); src != "" {
				return src
			}
		}
	}
	for i := range entities {
		if entities[i].DocKind == "RoleBinding" || entities[i].DocKind == "ClusterRoleBinding" {
			if entities[i].SourceFile != "" {
				return entities[i].SourceFile
			}
		}
	}
	for i := range entities {
		if entities[i].SourceFile != "" {
			return entities[i].SourceFile
		}
	}
	return "rbac.yaml"
}
