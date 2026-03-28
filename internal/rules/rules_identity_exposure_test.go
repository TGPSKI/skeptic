package rules

import "testing"

func TestInfrastructureCredentialExposureRules(t *testing.T) {
	rules := infrastructureCredentialExposureRules()
	assertRuleCount(t, "infrastructureCredentialExposureRules", rules, 3)
	validateRuleSlice(t, "infrastructureCredentialExposureRules", rules,
		"IAC-TF-001", "IAC-ANS-001")
}

func TestMachineIdentityPolicyRules(t *testing.T) {
	rules := machineIdentityPolicyRules()
	assertRuleCount(t, "machineIdentityPolicyRules", rules, 4)
	validateRuleSlice(t, "machineIdentityPolicyRules", rules,
		"CLOUD-ID-001", "CLOUD-ID-002")
}
