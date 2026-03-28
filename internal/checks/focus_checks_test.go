package checks

import (
	"strings"
	"testing"

	"github.com/TGPSKI/skeptic/internal/model"
)

func TestRunFocusChecksMachineIdentity(t *testing.T) {
	content := `
role: Owner
client_secret: super-secret-value
url: https://login.microsoftonline.com/tenant/oauth2/v2.0/token
grant_type=client_credentials
Authorization: Bearer abcdef
`
	findings := RunFocusChecks(
		"/repo/identity/config.yaml",
		"identity/config.yaml",
		strings.Split(strings.TrimSpace(content), "\n"),
		content,
		true,
		model.ThreatModeMachineIdentity,
	)
	assertHasFinding(t, findings, "MID-001")
	assertHasFinding(t, findings, "MID-002")
	assertHasFinding(t, findings, "MID-003")
}

func TestRunFocusChecksAIWorkload(t *testing.T) {
	content := `
vector_db: qdrant
authentication: disabled
log_prompts: true
retention_days: 30
tool_approval_mode: auto
serve --bind 0.0.0.0:6333
`
	findings := RunFocusChecks(
		"/repo/agent/config.yaml",
		"agent/config.yaml",
		strings.Split(strings.TrimSpace(content), "\n"),
		content,
		true,
		model.ThreatModeAIWorkload,
	)
	assertHasFinding(t, findings, "AIW-001")
	assertHasFinding(t, findings, "AIW-002")
	assertHasFinding(t, findings, "AIW-003")
	assertHasFinding(t, findings, "AIW-004")
}

func TestRunFocusChecksMID101to104(t *testing.T) {
	oidc := `
openid:
  issuer: https://example.com
`
	findings := RunFocusChecks(
		"/repo/k8s/oidc.yaml",
		"k8s/oidc.yaml",
		strings.Split(strings.TrimSpace(oidc), "\n"),
		oidc,
		true,
		model.ThreatModeMachineIdentity,
	)
	assertHasFinding(t, findings, "MID-101")

	spiffe := `trust_domain: "spiffe://cluster*"`
	findings = RunFocusChecks("/repo/a.txt", "a.txt", strings.Split(spiffe, "\n"), spiffe, true, model.ThreatModeMachineIdentity)
	assertHasFinding(t, findings, "MID-102")

	sa := `kind: ServiceAccount
metadata:
  name: bot
`
	findings = RunFocusChecks(
		"/repo/k8s/sa.yaml",
		"k8s/sa.yaml",
		strings.Split(strings.TrimSpace(sa), "\n"),
		sa,
		true,
		model.ThreatModeMachineIdentity,
	)
	assertHasFinding(t, findings, "MID-103")

	env := `API_KEY=123456789012345678901234567890`
	findings = RunFocusChecks(
		"/repo/.env",
		".env",
		strings.Split(strings.TrimSpace(env), "\n"),
		env,
		true,
		model.ThreatModeMachineIdentity,
	)
	assertHasFinding(t, findings, "MID-104")
}

func TestRunFocusChecksAIW101to104(t *testing.T) {
	compose := `
services:
  qdrant:
    ports:
      - 0.0.0.0:6333:6333
`
	findings := RunFocusChecks(
		"/repo/docker-compose.yml",
		"docker-compose.yml",
		strings.Split(strings.TrimSpace(compose), "\n"),
		compose,
		true,
		model.ThreatModeAIWorkload,
	)
	assertHasFinding(t, findings, "AIW-101")

	infer := `
model_server:
  port: 8080
  host: 0.0.0.0
`
	findings = RunFocusChecks(
		"/repo/cfg.yaml",
		"cfg.yaml",
		strings.Split(strings.TrimSpace(infer), "\n"),
		infer,
		true,
		model.ThreatModeAIWorkload,
	)
	assertHasFinding(t, findings, "AIW-102")

	promptLog := `prompt_logging: yes`
	findings = RunFocusChecks(
		"/repo/agent.yaml",
		"agent.yaml",
		strings.Split(strings.TrimSpace(promptLog), "\n"),
		promptLog,
		true,
		model.ThreatModeAIWorkload,
	)
	assertHasFinding(t, findings, "AIW-103")

	emb := `embeddings_path: /data/vec mode 0o777`
	findings = RunFocusChecks(
		"/repo/paths.conf",
		"paths.conf",
		strings.Split(strings.TrimSpace(emb), "\n"),
		emb,
		true,
		model.ThreatModeAIWorkload,
	)
	assertHasFinding(t, findings, "AIW-104")
}

func TestHasOIDCAudienceBinding(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"audience keyword", "issuer: x\naudience: api://default", true},
		{"json aud quoted double", `{"aud":"api"}`, true},
		{"json aud quoted single", "{'aud':'api'}", true},
		{"yaml aud field", "oidc:\n  aud: https://rp", true},
		{"no audience binding", "openid:\n  issuer: https://idp.example.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasOIDCAudienceBinding(tt.content); got != tt.want {
				t.Errorf("HasOIDCAudienceBinding() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsYAMLPath(t *testing.T) {
	tests := []struct {
		lower string
		want  bool
	}{
		{"/repo/app/config.yaml", true},
		{"/repo/manifests/deploy.yml", true},
		{"/repo/readme.md", false},
		{"/repo/script.sh", false},
	}
	for _, tt := range tests {
		t.Run(tt.lower, func(t *testing.T) {
			if got := IsYAMLPath(tt.lower); got != tt.want {
				t.Errorf("IsYAMLPath(%q) = %v, want %v", tt.lower, got, tt.want)
			}
		})
	}
}

func TestIsShellLikeOrEnvPath(t *testing.T) {
	tests := []struct {
		lower string
		want  bool
	}{
		{"/repo/scripts/setup.sh", true},
		{"/repo/.bashrc", true},
		{"/home/u/.profile", true},
		{"/app/.env", true},
		{"/app/.env.local", true},
		{"/svc/dockerfile", true},
		{"/ctx/container/dockerfile.prod", true},
		{"/repo/go.mod", false},
		{"/repo/config.yaml", false},
	}
	for _, tt := range tests {
		t.Run(tt.lower, func(t *testing.T) {
			if got := IsShellLikeOrEnvPath(tt.lower); got != tt.want {
				t.Errorf("IsShellLikeOrEnvPath(%q) = %v, want %v", tt.lower, got, tt.want)
			}
		})
	}
}

func TestIsDockerComposeOrAIConfigPath(t *testing.T) {
	tests := []struct {
		lower string
		want  bool
	}{
		{"/app/docker-compose.yml", true},
		{"/stack/compose.yaml", true},
		{"/proj/docker-compose.override.yml", true},
		{"/ai/config.toml", true},
		{"/ai/settings.json", true},
		{"/repo/binary.exe", false},
		{"/repo/readme.txt", false},
	}
	for _, tt := range tests {
		t.Run(tt.lower, func(t *testing.T) {
			if got := IsDockerComposeOrAIConfigPath(tt.lower); got != tt.want {
				t.Errorf("IsDockerComposeOrAIConfigPath(%q) = %v, want %v", tt.lower, got, tt.want)
			}
		})
	}
}

func TestAiw102ModelServingWithoutAuth(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			"model_server without auth",
			"model_server:\n  port: 8080\n  host: 0.0.0.0",
			true,
		},
		{
			"serving with port no auth",
			"serving:\n  port: 8000",
			true,
		},
		{
			"inference with port no auth",
			"inference:\n  port: 11434",
			true,
		},
		{
			"model_server with token",
			"model_server:\n  port: 8080\n  token: secret",
			false,
		},
		{
			"inference only no port",
			"inference:\n  enabled: true",
			false,
		},
		{
			"unrelated config",
			"foo: bar\nbaz: qux",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AIW102ModelServingWithoutAuth(tt.content); got != tt.want {
				t.Errorf("AIW102ModelServingWithoutAuth() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAiw103PromptLogNoRetention(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			"log_prompts true no ttl",
			"log_prompts: true",
			true,
		},
		{
			"prompt_logging yes with retention",
			"prompt_logging: yes\nretention_days: 7",
			false,
		},
		{
			"store_prompts 1 with ttl",
			"store_prompts: 1\nttl_hours: 24",
			false,
		},
		{
			"logging disabled",
			"log_prompts: false",
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AIW103PromptLogNoRetention(tt.content); got != tt.want {
				t.Errorf("AIW103PromptLogNoRetention() = %v, want %v", got, tt.want)
			}
		})
	}
}
