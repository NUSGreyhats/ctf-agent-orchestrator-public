#!/bin/bash
set -euo pipefail

# Enable root login via SSH
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
systemctl restart sshd
