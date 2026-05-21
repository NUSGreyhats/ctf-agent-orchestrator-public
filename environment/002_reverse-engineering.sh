#!/bin/bash

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=environment/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

#
# JADX 1.5.5
#

if [ ! -x /opt/jadx-1.5.5/bin/jadx ]; then
  log "Installing JADX 1.5.5"
  download_file \
    https://github.com/skylot/jadx/releases/download/v1.5.5/jadx-1.5.5.zip \
    /tmp/jadx-1.5.5.zip
  rm -rf /opt/jadx-1.5.5
  unzip -oq /tmp/jadx-1.5.5.zip -d /opt/jadx-1.5.5/
  rm -f /tmp/jadx-1.5.5.zip
  chmod +x /opt/jadx-1.5.5/bin/jadx
fi
append_bashrc_line "export PATH=\$PATH:/opt/jadx-1.5.5/bin"

#
# APKTool 3.0.1
#

if [ ! -f /opt/apktool_3.0.1.jar ]; then
  download_file \
    https://github.com/iBotPeaches/Apktool/releases/download/v3.0.1/apktool_3.0.1.jar \
    /opt/apktool_3.0.1.jar
fi
cat > /usr/bin/apktool << 'EOF'
#!/usr/bin/bash
exec java -jar /opt/apktool_3.0.1.jar "$@"
EOF
chmod +x /usr/bin/apktool

#
# bata24/gef (GDB Enhanced Features)
#

mkdir -p /opt/gef
if [ ! -f /opt/gef/gef.py ]; then
  download_file https://raw.githubusercontent.com/bata24/gef/master/gef.py /opt/gef/gef.py
fi
uv_pip_install keystone-engine ropper

#
# Python packages for skills: ida-domain, libdebug
#

uv_pip_install --reinstall typing-extensions
uv_pip_install ida-domain libdebug
