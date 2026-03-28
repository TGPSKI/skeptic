package rules

import "regexp"

// infrastructureCredentialExposureRules covers high-risk identity and secret
// exposure patterns in IaC artifacts across Terraform, Ansible, and Helm.
func infrastructureCredentialExposureRules() []Rule {
	return []Rule{
		{
			ID:          "IAC-TF-001",
			Title:       "Terraform state file with potential credentials",
			Description: "A .tfstate file is present in the repository. Terraform state files frequently contain plaintext credentials, API keys, and connection strings for provisioned infrastructure.",
			Category:    "credential-access",
			Mitre:       "T1552.001",
			Severity:    SeverityHigh,
			Pattern:     `(?i)\.(tfstate|tfstate\.backup)$`,
			Target:      TargetPath,
		},
		{
			ID:          "IAC-ANS-001",
			Title:       "Ansible vault with weak or no encryption",
			Description: "Detected an Ansible vault reference using plaintext variables or vault files without proper encryption markers. Unencrypted vault files and inline vault passwords expose credentials.",
			Category:    "credential-access",
			Mitre:       "T1552.001",
			Severity:    SeverityHigh,
			Pattern:     `(?i)(ansible_vault_password|vault_password_file|--vault-password-file|--ask-vault-pass|ansible_become_pass|ansible_ssh_pass)\s*[:=]`,
			Target:      TargetContent,
		},
		{
			ID:          "IAC-HELM-002",
			Title:       "Helm secrets plugin reference",
			Description: "Detected helm-secrets or SOPS reference indicating encrypted secret management. Verify decrypted secrets are not committed.",
			Category:    "credential-access",
			Mitre:       "T1552.001",
			Severity:    SeverityInfo,
			Pattern:     `(?i)(helm[-\s]secrets|sops[-_]encrypted|ENC\[AES256_GCM)`,
			Target:      TargetContent,
		},
	}
}

// machineIdentityPolicyRules detects over-permissive and high-risk machine
// identity patterns in IAM and workload identity policy artifacts.
func machineIdentityPolicyRules() []Rule {
	return []Rule{
		{
			ID:             "CLOUD-ID-001",
			Title:          "Over-privileged identity permission marker",
			Description:    "Detected broad machine identity permissions (write-all/admin/*) in IAM/RBAC policy context.",
			Category:       "machine-identity",
			Mitre:          "T1528",
			Severity:       SeverityHigh,
			Pattern:        `(?i)\b(write-all|AdministratorAccess|Owner|cluster-admin|iam:\*|actions:\*)\b`,
			Target:         TargetContent,
			ContextPattern: regexp.MustCompile(`(?i)(Effect|Action|Resource|Principal|Statement|Policy|Role|ClusterRole|RoleBinding|ServiceAccount|permissions|apiVersion|kind|rules)`),
			ContextWindow:  5,
			ExcludePattern: regexp.MustCompile(`(?i)owner/\w+|--repo\s+\w+/\w+|"owner"\s*:|owner@\$|owner@\{|creationPolicy:\s*Owner|requires\s+cluster-admin|CODEOWNERS`),
		},
		{
			ID:          "CLOUD-ID-002",
			Title:       "Wildcard federated trust subject marker",
			Description: "Detected wildcard subject/scope in OIDC or federated trust context.",
			Category:    "machine-identity",
			Mitre:       "T1528",
			Severity:    SeverityHigh,
			Pattern:     `(?i)(token\.actions\.githubusercontent\.com|oidc|federated).{0,200}(repo:\*|subject:\s*\*|sub:\s*\*|system:serviceaccount:\*)`,
			Target:      TargetContent,
		},
		{
			ID:          "CLOUD-ID-003",
			Title:       "Static OAuth client secret material marker",
			Description: "Detected static OAuth or service principal secret in configuration/script content.",
			Category:    "machine-identity",
			Mitre:       "T1552.001",
			Severity:    SeverityHigh,
			Pattern:     `(?i)\b(client_secret|service_principal_secret|app_role_secret)\b`,
			Target:      TargetContent,
		},
		{
			ID:          "CLOUD-ID-004",
			Title:       "Machine token exchange to Graph/OAuth endpoint marker",
			Description: "Detected machine token exchange flow that should be reviewed for scope minimization and audience control.",
			Category:    "machine-identity",
			Mitre:       "T1528",
			Severity:    SeverityMedium,
			Pattern:     `(?i)(oauth2/v2\.0/token|grant_type=client_credentials|graph\.microsoft\.com).{0,160}(access_token|Authorization:\s*Bearer)`,
			Target:      TargetContent,
		},
	}
}
