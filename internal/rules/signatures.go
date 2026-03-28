package rules

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TGPSKI/skeptic/internal/model"
	"github.com/TGPSKI/skeptic/internal/security"
)

// RulePackSignatureAlgorithm is the canonical detached signature algorithm identifier.
const RulePackSignatureAlgorithm = "ed25519-sha256"

// RulePackSignatureMetadata holds detached Ed25519 rulepack JSON on disk (algorithm, hash, base64 sig, etc.).
type RulePackSignatureMetadata struct {
	Version     int    `json:"version"`
	Algorithm   string `json:"algorithm"`
	KeyID       string `json:"key_id,omitempty"`
	CreatedAt   string `json:"created_at"`
	FileSHA256  string `json:"file_sha256"`
	Signature   string `json:"signature"`
	Rulepack    string `json:"rulepack,omitempty"`
	Description string `json:"description,omitempty"`
}

// RulePackSignature represents a single Ed25519 detached signature.
type RulePackSignature struct {
	KeyID     string // optional identifier for which key signed
	Signature []byte
}

// MultiKeyPolicy configures multi-signature verification for rule packs.
type MultiKeyPolicy struct {
	RequiredSignatures int      // minimum number of valid signatures needed
	TrustedKeys        [][]byte // Ed25519 public keys
}

// VerifyMultiSig verifies that content has at least RequiredSignatures valid signatures
// from distinct keys in the TrustedKeys set.
func VerifyMultiSig(content []byte, sigs []RulePackSignature, policy MultiKeyPolicy) error {
	if len(policy.TrustedKeys) == 0 {
		return errors.New("multi-sig: trusted keys required")
	}
	if len(sigs) == 0 {
		return errors.New("multi-sig: signatures required")
	}
	required := policy.RequiredSignatures
	if required <= 0 {
		required = 1
	}

	seen := make(map[int]struct{})
	for _, sig := range sigs {
		for i, rawPub := range policy.TrustedKeys {
			if _, ok := seen[i]; ok {
				continue
			}
			pub := ed25519.PublicKey(rawPub)
			if len(pub) != ed25519.PublicKeySize {
				continue
			}
			if ed25519.Verify(pub, content, sig.Signature) {
				seen[i] = struct{}{}
				break
			}
		}
	}

	got := len(seen)
	if got >= required {
		return nil
	}
	return fmt.Errorf("multi-sig: got %d valid signatures from distinct keys, need %d", got, required)
}

// RunSignRulepack signs a rulepack with detached Ed25519 metadata.
func RunSignRulepack(args []string, stdout io.Writer, stderr io.Writer) int {
	var (
		rulesFile    string
		privateKey   string
		signatureOut string
		keyID        string
	)

	fs := flag.NewFlagSet("skeptic sign-rulepack", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&rulesFile, "rules-file", "", "rulepack JSON to sign")
	fs.StringVar(&privateKey, "private-key", "", "Ed25519 private key PEM (PKCS8)")
	fs.StringVar(&signatureOut, "signature-out", "", "detached signature output (default: <rules-file>.sig)")
	fs.StringVar(&keyID, "key-id", "", "signer key ID")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	rulesFile = strings.TrimSpace(rulesFile)
	privateKey = strings.TrimSpace(privateKey)
	if rulesFile == "" || privateKey == "" {
		fmt.Fprintln(stderr, "--rules-file and --private-key are required")
		return 2
	}

	absRules, err := filepath.Abs(model.ExpandHomePath(rulesFile))
	if err != nil {
		fmt.Fprintf(stderr, "resolve rules file failed: %v\n", err)
		return 1
	}
	absPriv, err := filepath.Abs(model.ExpandHomePath(privateKey))
	if err != nil {
		fmt.Fprintf(stderr, "resolve private key failed: %v\n", err)
		return 1
	}
	if signatureOut == "" {
		signatureOut = DefaultRulepackSignaturePath(absRules)
	}
	absSig, err := filepath.Abs(model.ExpandHomePath(signatureOut))
	if err != nil {
		fmt.Fprintf(stderr, "resolve signature output failed: %v\n", err)
		return 1
	}

	signature, err := SignRulepackFile(absRules, absPriv, keyID)
	if err != nil {
		fmt.Fprintf(stderr, "signing failed: %v\n", err)
		return 1
	}
	if err := WriteRulepackSignature(absSig, signature); err != nil {
		fmt.Fprintf(stderr, "failed to write signature file: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "signed rulepack: %s\n", absRules)
	fmt.Fprintf(stdout, "signature file: %s\n", absSig)
	fmt.Fprintf(stdout, "sha256: %s\n", signature.FileSHA256)
	fmt.Fprintf(stdout, "algorithm: %s\n", signature.Algorithm)
	return 0
}

// RunGenRulepackKeypair generates Ed25519 signer key material in PEM form.
func RunGenRulepackKeypair(args []string, stdout io.Writer, stderr io.Writer) int {
	var (
		privateOut string
		publicOut  string
	)
	fs := flag.NewFlagSet("skeptic gen-rule-keypair", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&privateOut, "private-out", "rulepack-signing.key.pem", "private key output path")
	fs.StringVar(&publicOut, "public-out", "rulepack-signing.pub.pem", "public key output path")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	priv, pub, err := GenerateRulepackKeypair()
	if err != nil {
		fmt.Fprintf(stderr, "key generation failed: %v\n", err)
		return 1
	}

	privatePath, err := filepath.Abs(model.ExpandHomePath(privateOut))
	if err != nil {
		fmt.Fprintf(stderr, "resolve private output path failed: %v\n", err)
		return 1
	}
	publicPath, err := filepath.Abs(model.ExpandHomePath(publicOut))
	if err != nil {
		fmt.Fprintf(stderr, "resolve public output path failed: %v\n", err)
		return 1
	}

	if err := WritePEMFile(privatePath, "PRIVATE KEY", priv, 0o600); err != nil {
		fmt.Fprintf(stderr, "write private key failed: %v\n", err)
		return 1
	}
	if err := WritePEMFile(publicPath, "PUBLIC KEY", pub, 0o644); err != nil {
		fmt.Fprintf(stderr, "write public key failed: %v\n", err)
		return 1
	}

	fmt.Fprintf(stdout, "private key: %s\n", privatePath)
	fmt.Fprintf(stdout, "public key: %s\n", publicPath)
	return 0
}

// DefaultRulepackSignaturePath returns deterministic detached signature path.
func DefaultRulepackSignaturePath(rulepackPath string) string {
	return rulepackPath + ".sig"
}

// SignRulepackFile signs file hash context instead of raw content for deterministic verification.
func SignRulepackFile(rulepackPath string, privateKeyPath string, keyID string) (RulePackSignatureMetadata, error) {
	fileData, err := os.ReadFile(rulepackPath)
	if err != nil {
		return RulePackSignatureMetadata{}, err
	}
	sha := sha256.Sum256(fileData)
	shaHex := hex.EncodeToString(sha[:])

	priv, err := LoadEd25519PrivateKeyFromPEM(privateKeyPath)
	if err != nil {
		return RulePackSignatureMetadata{}, err
	}

	signatureRaw := ed25519.Sign(priv, RulepackSignatureMessage(shaHex))
	return RulePackSignatureMetadata{
		Version:    1,
		Algorithm:  RulePackSignatureAlgorithm,
		KeyID:      strings.TrimSpace(keyID),
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		FileSHA256: shaHex,
		Signature:  base64.StdEncoding.EncodeToString(signatureRaw),
		Rulepack:   filepath.Base(rulepackPath),
	}, nil
}

// VerifyRulepackFileSignature validates algorithm/version/hash and signature against trusted keys.
func VerifyRulepackFileSignature(rulepackPath string, signature RulePackSignatureMetadata, pubKeys []ed25519.PublicKey) error {
	if signature.Version != 1 {
		return fmt.Errorf("unsupported signature version: %d", signature.Version)
	}
	if strings.TrimSpace(signature.Algorithm) != RulePackSignatureAlgorithm {
		return fmt.Errorf("unsupported signature algorithm: %s", signature.Algorithm)
	}
	expectedSHA, err := security.NormalizeSHA256(signature.FileSHA256)
	if err != nil {
		return fmt.Errorf("invalid signature file sha256: %w", err)
	}
	actualSHA, err := security.SHA256FileHex(rulepackPath)
	if err != nil {
		return err
	}
	if actualSHA != expectedSHA {
		return fmt.Errorf("rulepack signature hash mismatch: expected %s got %s", expectedSHA, actualSHA)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(signature.Signature))
	if err != nil {
		return fmt.Errorf("invalid signature encoding: %w", err)
	}
	message := RulepackSignatureMessage(expectedSHA)
	for _, key := range pubKeys {
		if ed25519.Verify(key, message, sigBytes) {
			return nil
		}
	}
	return errors.New("signature verification failed with provided public key(s)")
}

// LoadRulepackSignature parses detached signature JSON metadata.
func LoadRulepackSignature(path string) (RulePackSignatureMetadata, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return RulePackSignatureMetadata{}, err
	}
	var signature RulePackSignatureMetadata
	if err := json.Unmarshal(data, &signature); err != nil {
		return RulePackSignatureMetadata{}, err
	}
	return signature, nil
}

// WriteRulepackSignature writes detached signature metadata to disk.
func WriteRulepackSignature(path string, signature RulePackSignatureMetadata) error {
	abs, err := filepath.Abs(model.ExpandHomePath(path))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(signature, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(abs, data, 0o644)
}

// LoadPublicKeys loads one or more Ed25519 public keys from PEM files.
func LoadPublicKeys(paths []string) ([]ed25519.PublicKey, error) {
	keys := make([]ed25519.PublicKey, 0, len(paths))
	for _, raw := range paths {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		abs, err := filepath.Abs(model.ExpandHomePath(raw))
		if err != nil {
			return nil, err
		}
		key, err := LoadEd25519PublicKeyFromPEM(abs)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", abs, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// LoadEd25519PrivateKeyFromPEM reads a PEM file and delegates to ParseEd25519PrivateKeyPEM.
func LoadEd25519PrivateKeyFromPEM(path string) (ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseEd25519PrivateKeyPEM(data)
}

// LoadEd25519PublicKeyFromPEM reads a PEM file and delegates to ParseEd25519PublicKeyPEM.
func LoadEd25519PublicKeyFromPEM(path string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseEd25519PublicKeyPEM(data)
}

// ParseEd25519PrivateKeyPEM delegates to security.ParseEd25519PrivateKeyPEM.
func ParseEd25519PrivateKeyPEM(data []byte) (ed25519.PrivateKey, error) {
	return security.ParseEd25519PrivateKeyPEM(data)
}

// ParseEd25519PublicKeyPEM delegates to security.ParseEd25519PublicKeyPEM.
func ParseEd25519PublicKeyPEM(data []byte) (ed25519.PublicKey, error) {
	return security.ParseEd25519PublicKeyPEM(data)
}

// GenerateRulepackKeypair generates PKCS8/PKIX DER key material for PEM writing.
func GenerateRulepackKeypair() (privateDER []byte, publicDER []byte, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	privateDER, err = x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	publicDER, err = x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, err
	}
	return privateDER, publicDER, nil
}

// WritePEMFile writes one PEM block with caller-controlled file mode.
func WritePEMFile(path string, blockType string, der []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	block := &pem.Block{Type: blockType, Bytes: der}
	return os.WriteFile(path, pem.EncodeToMemory(block), mode)
}

// RunVerifyRulepack verifies a single rulepack's detached signature from CLI flags.
func RunVerifyRulepack(args []string, stdout io.Writer, stderr io.Writer) int {
	var (
		rulesFile string
		publicKey string
	)
	fs := flag.NewFlagSet("skeptic verify-rulepack", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&rulesFile, "rules-file", "", "rulepack JSON to verify")
	fs.StringVar(&publicKey, "public-key", "", "Ed25519 public key PEM")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	rulesFile = strings.TrimSpace(rulesFile)
	publicKey = strings.TrimSpace(publicKey)
	if rulesFile == "" || publicKey == "" {
		fmt.Fprintln(stderr, "--rules-file and --public-key are required")
		return 2
	}
	absRules, err := filepath.Abs(model.ExpandHomePath(rulesFile))
	if err != nil {
		fmt.Fprintf(stderr, "resolve rules file: %v\n", err)
		return 1
	}
	absPub, err := filepath.Abs(model.ExpandHomePath(publicKey))
	if err != nil {
		fmt.Fprintf(stderr, "resolve public key: %v\n", err)
		return 1
	}
	sigPath := DefaultRulepackSignaturePath(absRules)
	sig, err := LoadRulepackSignature(sigPath)
	if err != nil {
		fmt.Fprintf(stderr, "load signature: %v\n", err)
		return 1
	}
	pubKey, err := LoadEd25519PublicKeyFromPEM(absPub)
	if err != nil {
		fmt.Fprintf(stderr, "load public key: %v\n", err)
		return 1
	}
	if err := VerifyRulepackFileSignature(absRules, sig, []ed25519.PublicKey{pubKey}); err != nil {
		fmt.Fprintf(stderr, "FAIL: %s — %v\n", rulesFile, err)
		return 1
	}
	fmt.Fprintf(stdout, "OK: %s\n", rulesFile)
	return 0
}

// RulepackSignatureMessage creates domain-separated bytes for signing/verification.
func RulepackSignatureMessage(fileSHA256 string) []byte {
	return []byte("skeptic-rulepack-v1\n" + strings.TrimSpace(strings.ToLower(fileSHA256)))
}
