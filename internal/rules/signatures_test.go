package rules

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunGenRulepackKeypair(t *testing.T) {
	root := t.TempDir()
	priv := filepath.Join(root, "keys", "priv.pem")
	pub := filepath.Join(root, "keys", "pub.pem")
	var stdout, stderr bytes.Buffer

	exit := RunGenRulepackKeypair([]string{"--private-out", priv, "--public-out", pub}, &stdout, &stderr)
	if exit != 0 {
		t.Fatalf("RunGenRulepackKeypair exit=%d stderr=%s", exit, stderr.String())
	}
	if _, err := os.Stat(priv); err != nil {
		t.Fatalf("expected private key output: %v", err)
	}
	if _, err := os.Stat(pub); err != nil {
		t.Fatalf("expected public key output: %v", err)
	}
}

func TestRunSignRulepack(t *testing.T) {
	root := t.TempDir()
	rulesPath := filepath.Join(root, "rules.json")
	if err := os.WriteFile(rulesPath, []byte(`[]`), 0o644); err != nil {
		t.Fatalf("write rules file: %v", err)
	}
	privateDER, publicDER, err := GenerateRulepackKeypair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	privPath := filepath.Join(root, "signing.key.pem")
	pubPath := filepath.Join(root, "signing.pub.pem")
	if err := WritePEMFile(privPath, "PRIVATE KEY", privateDER, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := WritePEMFile(pubPath, "PUBLIC KEY", publicDER, 0o644); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	var stdout, stderr bytes.Buffer
	exit := RunSignRulepack([]string{"--rules-file", rulesPath, "--private-key", privPath}, &stdout, &stderr)
	if exit != 0 {
		t.Fatalf("RunSignRulepack exit=%d stderr=%s", exit, stderr.String())
	}
	sigPath := DefaultRulepackSignaturePath(rulesPath)
	if _, err := os.Stat(sigPath); err != nil {
		t.Fatalf("expected signature output: %v", err)
	}

	sig, err := LoadRulepackSignature(sigPath)
	if err != nil {
		t.Fatalf("LoadRulepackSignature failed: %v", err)
	}
	keys, err := LoadPublicKeys([]string{pubPath})
	if err != nil {
		t.Fatalf("LoadPublicKeys failed: %v", err)
	}
	if err := VerifyRulepackFileSignature(rulesPath, sig, keys); err != nil {
		t.Fatalf("verify signature failed: %v", err)
	}
}

func TestLoadKeyPEMFailures(t *testing.T) {
	root := t.TempDir()
	bad := filepath.Join(root, "bad.pem")
	if err := os.WriteFile(bad, []byte("not-a-pem"), 0o644); err != nil {
		t.Fatalf("write bad pem: %v", err)
	}

	if _, err := LoadEd25519PrivateKeyFromPEM(bad); err == nil {
		t.Fatalf("expected private key decode failure")
	}
	if _, err := LoadEd25519PublicKeyFromPEM(bad); err == nil {
		t.Fatalf("expected public key decode failure")
	}
}

func TestLoadPublicKeysBadPath(t *testing.T) {
	if _, err := LoadPublicKeys([]string{"/definitely/missing/key.pem"}); err == nil {
		t.Fatalf("expected LoadPublicKeys to fail on missing file")
	}
}

func TestRulepackSignatureMessage(t *testing.T) {
	msg := string(RulepackSignatureMessage(" ABCDEF "))
	if !strings.Contains(msg, "skeptic-rulepack-v1") || !strings.Contains(msg, "abcdef") {
		t.Fatalf("unexpected signature message: %q", msg)
	}
}

func TestSignAndKeypairSubcommandValidation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := RunSignRulepack(nil, &stdout, &stderr); code != 2 {
		t.Fatalf("expected missing args exit=2, got %d", code)
	}

	stdout.Reset()
	stderr.Reset()
	if code := RunGenRulepackKeypair([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("expected help exit=0, got %d", code)
	}
}

func TestVerifyMultiSigSingleKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("rulepack-bytes")
	sig := ed25519.Sign(priv, content)
	err = VerifyMultiSig(content, []RulePackSignature{{Signature: sig}}, MultiKeyPolicy{
		RequiredSignatures: 1,
		TrustedKeys:        [][]byte{pub},
	})
	if err != nil {
		t.Fatalf("VerifyMultiSig: %v", err)
	}
	// RequiredSignatures <= 0 is treated as 1.
	if err := VerifyMultiSig(content, []RulePackSignature{{Signature: sig}}, MultiKeyPolicy{
		RequiredSignatures: 0,
		TrustedKeys:        [][]byte{pub},
	}); err != nil {
		t.Fatalf("VerifyMultiSig with RequiredSignatures=0: %v", err)
	}
}

func TestVerifyMultiSigMultiKey(t *testing.T) {
	content := []byte("multi-sign-content")
	var pubs [][]byte
	var sigs []RulePackSignature
	for range 3 {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pubs = append(pubs, pub)
		sigs = append(sigs, RulePackSignature{Signature: ed25519.Sign(priv, content)})
	}
	err := VerifyMultiSig(content, sigs[:2], MultiKeyPolicy{
		RequiredSignatures: 2,
		TrustedKeys:        pubs,
	})
	if err != nil {
		t.Fatalf("VerifyMultiSig: %v", err)
	}
}

func TestVerifyMultiSigInsufficient(t *testing.T) {
	content := []byte("only-one-signer")
	pub0, priv0, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv0, content)
	err = VerifyMultiSig(content, []RulePackSignature{{Signature: sig}}, MultiKeyPolicy{
		RequiredSignatures: 2,
		TrustedKeys:        [][]byte{pub0, pub1},
	})
	if err == nil {
		t.Fatal("expected error when only one distinct key signed")
	}
}

func TestVerifyMultiSigBadSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("original")
	sig := ed25519.Sign(priv, content)
	sig[0] ^= 0xff
	err = VerifyMultiSig(content, []RulePackSignature{{Signature: sig}}, MultiKeyPolicy{
		RequiredSignatures: 1,
		TrustedKeys:        [][]byte{pub},
	})
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
}

func TestVerifyMultiSigEmptyInputs(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("x")
	sig := ed25519.Sign(priv, content)

	if err := VerifyMultiSig(content, nil, MultiKeyPolicy{
		RequiredSignatures: 1,
		TrustedKeys:        [][]byte{pub},
	}); err == nil {
		t.Fatal("expected error for empty sigs")
	}

	if err := VerifyMultiSig(content, []RulePackSignature{{Signature: sig}}, MultiKeyPolicy{
		RequiredSignatures: 1,
		TrustedKeys:        nil,
	}); err == nil {
		t.Fatal("expected error for empty trusted keys")
	}
}
