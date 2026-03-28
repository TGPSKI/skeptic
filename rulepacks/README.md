# External Rule Packs

This directory contains external rule packs, campaign IOCs, and signing keys.

## Layout

```
rulepacks/
  signing/
    rulepack-signing.pub.pem    # Ed25519 public key (committed)
    rulepack-signing.key.pem    # Ed25519 private key (gitignored via *.key.pem)
  campaigns/
    <campaign-name>.json        # Campaign-specific rule pack
    <campaign-name>.json.sig    # Detached Ed25519 signature
```

## Generate a rule pack

```bash
go run ./cmd/skeptic ingest \
  --source "./intel.md" \
  --out "rulepacks/campaigns/ingested-rules.json"
```

## Sign a rule pack

```bash
go run ./cmd/skeptic sign-rulepack \
  --rules-file "rulepacks/campaigns/ingested-rules.json" \
  --private-key "rulepacks/signing/rulepack-signing.key.pem"
```

## Enforce signature verification

```bash
./bin/skeptic \
  --rules-file "rulepacks/campaigns/ingested-rules.json" \
  --rules-pubkey "rulepacks/signing/rulepack-signing.pub.pem" \
  --require-signed-rules
```

## Scan with a campaign pack

```bash
./bin/skeptic \
  --rules-dir "rulepacks/campaigns" \
  --path /target/repo
```
