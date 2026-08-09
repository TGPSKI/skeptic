package checks

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckIAMPolicyWildcard(t *testing.T) {
	content := `{"Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}]}`
	findings := CheckIAMPolicy("policy.json", content, 3, false)
	if len(findings) == 0 {
		t.Fatal("expected GRAPH-001 finding")
	}
	if findings[0].RuleID != "GRAPH-001" {
		t.Fatalf("expected GRAPH-001, got %s", findings[0].RuleID)
	}
}

func TestCheckIAMPolicyAssumeRoleChainGRAPH004(t *testing.T) {
	content := `{"Statement": [
		{"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::123456789012:role/Other"},
		{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}
	]}`
	findings := CheckIAMPolicy("policy.json", content, 3, false)
	var saw004 bool
	for _, f := range findings {
		if f.RuleID == "GRAPH-004" {
			saw004 = true
		}
	}
	if !saw004 {
		t.Fatal("expected GRAPH-004 for assume-role statement plus wildcard Allow statement")
	}
}

func TestCheckK8sRBACWildcard(t *testing.T) {
	content := `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wide
rules:
  - apiGroups: [""]
    verbs: ["*"]
    resources: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bind-wide
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: wide
subjects:
  - kind: ServiceAccount
    name: default
    namespace: default
`
	findings := CheckK8sRBAC("rbac.yaml", content, 3, false)
	if len(findings) == 0 {
		t.Fatal("expected GRAPH-002 finding")
	}
}

func TestCheckOIDCFederationMissingAudience(t *testing.T) {
	content := `{"federation": true, "issuer": "https://auth.example.com"}`
	findings := CheckOIDCFederation("oidc.json", content, false)
	if len(findings) == 0 {
		t.Fatal("expected GRAPH-003 finding")
	}
}

func TestCheckOIDCFederationWithAudience(t *testing.T) {
	content := `{"federation": true, "issuer": "https://auth.example.com", "audience": "my-app"}`
	findings := CheckOIDCFederation("oidc.json", content, false)
	if len(findings) != 0 {
		t.Fatal("expected no findings when audience is set")
	}
}

func TestRunIdentityGraphChecks(t *testing.T) {
	dir := t.TempDir()
	policy := `{"Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}]}`
	os.WriteFile(filepath.Join(dir, "iam-policy.json"), []byte(policy), 0o644)
	findings := RunIdentityGraphChecks([]string{dir}, 3, false, nil)
	if len(findings) == 0 {
		t.Fatal("expected findings from graph check")
	}
}

func TestK8sRBACSecretsGRAPH009(t *testing.T) {
	dir := t.TempDir()
	yaml := `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secrets-star
rules:
  - apiGroups: [""]
    verbs: ["*"]
    resources: ["secrets"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bind-secrets-star
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: secrets-star
subjects:
  - kind: ServiceAccount
    name: app-sa
    namespace: default
`
	path := filepath.Join(dir, "k8s-rbac.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	findings := RunIdentityGraphChecks([]string{dir}, 4, false, nil)
	var saw009 bool
	for _, f := range findings {
		if f.RuleID == "GRAPH-009" {
			saw009 = true
			break
		}
	}
	if !saw009 {
		t.Fatal("expected GRAPH-009 for wildcard verbs on secrets ClusterRole")
	}
}

func TestCrossFileIAMGRAPH005(t *testing.T) {
	dir := t.TempDir()
	assume := `{"Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::123456789012:role/TargetRole"}]}`
	wild := `{"Statement":[{"Effect":"Allow","Action":["*"],"Resource":["*"]}]}`
	os.WriteFile(filepath.Join(dir, "assume-policy.json"), []byte(assume), 0o644)
	os.WriteFile(filepath.Join(dir, "TargetRole.json"), []byte(wild), 0o644)
	findings := RunIdentityGraphChecks([]string{dir}, 4, false, nil)
	var saw005 bool
	for _, f := range findings {
		if f.RuleID == "GRAPH-005" {
			saw005 = true
		}
	}
	if !saw005 {
		t.Fatal("expected GRAPH-005 for cross-file assume-role to wildcard policy")
	}
}

func TestCheckAzureRoleAssignmentGRAPH006(t *testing.T) {
	content := `{"properties":{"roleDefinitionName":"Owner"}}`
	findings := CheckAzureRoleAssignment("az.json", content, false)
	if len(findings) != 1 || findings[0].RuleID != "GRAPH-006" {
		t.Fatalf("expected GRAPH-006, got %#v", findings)
	}
}

func TestCheckGCPIAMBindingGRAPH007(t *testing.T) {
	content := `{"bindings":[{"role":"roles/owner","members":["allUsers"]}]}`
	findings := CheckGCPIAMBinding("gcp.json", content, false)
	if len(findings) != 1 || findings[0].RuleID != "GRAPH-007" {
		t.Fatalf("expected GRAPH-007, got %#v", findings)
	}
}

func TestCheckOIDCFederationGRAPH008MissingSub(t *testing.T) {
	content := `{"federation":true,"issuer":"https://token.actions.githubusercontent.com","audience":"sts.amazonaws.com","Condition":{"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"}}}`
	findings := CheckOIDCFederation("oidc.json", content, false)
	var saw008 bool
	for _, f := range findings {
		if f.RuleID == "GRAPH-008" {
			saw008 = true
		}
	}
	if !saw008 {
		t.Fatal("expected GRAPH-008 when GitHub OIDC lacks subject condition")
	}
}

func TestCheckOIDCFederationGRAPH008WildcardSub(t *testing.T) {
	content := `{"federation":true,"issuer":"https://token.actions.githubusercontent.com","Condition":{"StringLike":{"token.actions.githubusercontent.com:sub":"repo:org/*"}}}`
	findings := CheckOIDCFederation("oidc.json", content, false)
	var saw008 bool
	for _, f := range findings {
		if f.RuleID == "GRAPH-008" {
			saw008 = true
		}
	}
	if !saw008 {
		t.Fatal("expected GRAPH-008 for wildcard GitHub OIDC sub")
	}
}

func TestK8sWebhookIgnoreGRAPH010(t *testing.T) {
	yaml := `apiVersion: admissionregistration.k8s.io/v1
kind: ValidatingWebhookConfiguration
metadata:
  name: ex
webhooks:
  - name: hook1
    failurePolicy: Ignore
`
	ents := extractK8sRBACEntities(yaml)
	findings := K8sWebhookFailurePolicyFindings(ents, false)
	if len(findings) != 1 || findings[0].RuleID != "GRAPH-010" {
		t.Fatalf("expected GRAPH-010, got %#v", findings)
	}
}

func TestIdentityGraphBFS(t *testing.T) {
	g := IdentityGraph{
		Nodes: []IdentityNode{
			{ID: 0, Kind: "principal", Name: "a"},
			{ID: 1, Kind: "role", Name: "b"},
			{ID: 2, Kind: "resource", Name: "c"},
		},
		Edges: []IdentityEdge{
			{From: 0, To: 1, Action: "assume-role"},
			{From: 1, To: 2, Action: "access"},
		},
	}
	levels := g.BFS(0, 2)
	if len(levels) != 3 {
		t.Fatalf("expected 3 distance levels, got %d", len(levels))
	}
	if len(levels[0]) != 1 || levels[0][0] != 0 {
		t.Fatalf("level 0: want [0], got %v", levels[0])
	}
	if len(levels[1]) != 1 || levels[1][0] != 1 {
		t.Fatalf("level 1: want [1], got %v", levels[1])
	}
	if len(levels[2]) != 1 || levels[2][0] != 2 {
		t.Fatalf("level 2: want [2], got %v", levels[2])
	}
}

func TestIdentityGraphBlastRadius(t *testing.T) {
	g := IdentityGraph{
		Nodes: []IdentityNode{
			{ID: 0, Kind: "principal", Name: "p"},
			{ID: 1, Kind: "role", Name: "r"},
			{ID: 2, Kind: "resource", Name: "x"},
		},
		Edges: []IdentityEdge{
			{From: 0, To: 1, Action: "bind"},
			{From: 1, To: 2, Action: "access"},
		},
	}
	nodes := g.BlastRadius(0, 3)
	if len(nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(nodes))
	}
	want := []int{0, 1, 2}
	for i, n := range nodes {
		if n.ID != want[i] {
			t.Fatalf("node %d: want id %d, got %d", i, want[i], n.ID)
		}
	}
}

func TestIdentityGraphBFSDisconnected(t *testing.T) {
	g := IdentityGraph{
		Nodes: []IdentityNode{
			{ID: 0, Kind: "principal", Name: "a"},
			{ID: 1, Kind: "role", Name: "b"},
			{ID: 2, Kind: "resource", Name: "isolated"},
		},
		Edges: []IdentityEdge{
			{From: 0, To: 1, Action: "access"},
		},
	}
	levels := g.BFS(0, 10)
	var got []int
	for _, lv := range levels {
		got = append(got, lv...)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 reachable nodes, got %v", got)
	}
	for _, id := range got {
		if id == 2 {
			t.Fatal("did not expect isolated node 2 in BFS from 0")
		}
	}
}

func TestIdentityGraphBFSUnknownStart(t *testing.T) {
	g := IdentityGraph{
		Nodes: []IdentityNode{{ID: 0, Kind: "principal", Name: "a"}},
		Edges: []IdentityEdge{},
	}
	if lv := g.BFS(99, 3); lv != nil {
		t.Fatalf("expected nil for unknown start, got %v", lv)
	}
	if n := g.BlastRadius(99, 3); n != nil {
		t.Fatalf("expected nil blast radius for unknown start, got %v", n)
	}
}

func TestExtractK8sRBACEntitiesClusterRoleAndBinding(t *testing.T) {
	yaml := `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: admin-ish
rules:
  - verbs: ["*"]
    resources: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bind-admin
roleRef:
  kind: ClusterRole
  name: admin-ish
subjects:
  - kind: ServiceAccount
    name: sa1
    namespace: team-a
`
	ents := extractK8sRBACEntities(yaml)
	if len(ents) != 2 {
		t.Fatalf("expected 2 documents, got %d", len(ents))
	}
	if ents[0].DocKind != "ClusterRole" || ents[0].MetaName != "admin-ish" {
		t.Fatalf("clusterrole entity: %+v", ents[0])
	}
	if len(ents[0].Rules) == 0 {
		t.Fatal("expected rules on ClusterRole")
	}
	if ents[1].DocKind != "ClusterRoleBinding" || ents[1].RoleRefName != "admin-ish" {
		t.Fatalf("binding entity: %+v", ents[1])
	}
	if len(ents[1].Subjects) != 1 || ents[1].Subjects[0].Name != "sa1" {
		t.Fatalf("subjects: %+v", ents[1].Subjects)
	}
}

func TestBuildIdentityGraphFromRBACBFSReachability(t *testing.T) {
	yaml := `kind: Role
metadata:
  name: r1
  namespace: ns1
rules:
  - verbs: ["*"]
    resources: ["*"]
---
kind: RoleBinding
metadata:
  name: b1
  namespace: ns1
roleRef:
  kind: Role
  name: r1
subjects:
  - kind: ServiceAccount
    name: bot
`
	ents := extractK8sRBACEntities(yaml)
	g := buildIdentityGraphFromRBACEntities(ents)
	paths := k8sRBACWildcardPaths(g, 4)
	if len(paths) != 1 {
		t.Fatalf("expected 1 wildcard path, got %d: %#v", len(paths), paths)
	}
	// principal -> role -> wildcard = 3 nodes, 2 edges
	if len(paths[0]) != 3 {
		t.Fatalf("expected path length 3, got %d %v", len(paths[0]), paths[0])
	}
	blast := g.BlastRadius(paths[0][0], 4)
	if len(blast) < 3 {
		t.Fatalf("BFS blast from principal should reach wildcard, got %d nodes", len(blast))
	}
}

func TestK8sRBACGraphRespectsHopBudget(t *testing.T) {
	yaml := `kind: ClusterRole
metadata:
  name: wild
rules:
  - verbs: ["*"]
    resources: ["*"]
---
kind: ClusterRoleBinding
metadata:
  name: x
roleRef:
  kind: ClusterRole
  name: wild
subjects:
  - kind: ServiceAccount
    name: z
    namespace: z
`
	ents := extractK8sRBACEntities(yaml)
	g := buildIdentityGraphFromRBACEntities(ents)
	if p := k8sRBACWildcardPaths(g, 1); len(p) != 0 {
		t.Fatalf("maxHops=1 should not reach wildcard (needs 2 edges), got paths %#v", p)
	}
	if p := k8sRBACWildcardPaths(g, 2); len(p) != 1 {
		t.Fatalf("maxHops=2 should reach wildcard, got %#v", p)
	}
}

// An ignored directory must produce no findings. This walker is independent of
// the one in internal/scan, so it needs its own coverage: without the
// ignorePaths argument it walked and reported everything (#88).
func TestRunIdentityGraphChecksHonorsIgnorePaths(t *testing.T) {
	dir := t.TempDir()
	fixtures := filepath.Join(dir, "testdata", "proof")
	if err := os.MkdirAll(fixtures, 0o755); err != nil {
		t.Fatal(err)
	}
	policy := `{"Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}]}`
	if err := os.WriteFile(filepath.Join(fixtures, "iam-policy.json"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := RunIdentityGraphChecks([]string{dir}, 3, false, nil); len(got) == 0 {
		t.Fatal("expected findings without an ignore list; fixture is not triggering the check")
	}

	for _, pattern := range []string{"testdata/proof/**", "**/testdata/proof/**", "testdata/**"} {
		if got := RunIdentityGraphChecks([]string{dir}, 3, false, []string{pattern}); len(got) != 0 {
			t.Errorf("pattern %q: expected no findings, got %d (first: %s %s)",
				pattern, len(got), got[0].RuleID, got[0].File)
		}
	}
}

// Findings carry a path relative to the scan root, the same basis internal/scan
// uses. An absolute path cannot match a repo-relative ignore pattern and leaks
// the scanning host's layout.
func TestRunIdentityGraphChecksReportsRelativePaths(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "infra")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	policy := `{"Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}]}`
	if err := os.WriteFile(filepath.Join(sub, "iam-policy.json"), []byte(policy), 0o644); err != nil {
		t.Fatal(err)
	}

	findings := RunIdentityGraphChecks([]string{dir}, 3, false, nil)
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	for _, f := range findings {
		if filepath.IsAbs(f.File) {
			t.Errorf("%s reported an absolute path: %s", f.RuleID, f.File)
		}
	}
}
