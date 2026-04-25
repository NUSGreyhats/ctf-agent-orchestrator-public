#!/bin/bash

set -x
set -e

#
# install JADX 1.5.5
#

wget "https://github.com/skylot/jadx/releases/download/v1.5.5/jadx-1.5.5.zip"
rm -rf /opt/jadx-1.5.5
unzip -oq jadx-1.5.5.zip -d /opt/jadx-1.5.5/
rm -f jadx-1.5.5.zip
chmod +x /opt/jadx-1.5.5/bin/jadx
printf '%s\n' "export PATH=\$PATH:/opt/jadx-1.5.5/bin" >> ~/.bashrc

#
# install APKtool 3.0.1
#

wget "https://github.com/iBotPeaches/Apktool/releases/download/v3.0.1/apktool_3.0.1.jar" -O /opt/apktool_3.0.1.jar
cat > /usr/bin/apktool << 'EOF'
#!/usr/bin/bash
exec java -jar /opt/apktool_3.0.1.jar "$@"
EOF
chmod +x /usr/bin/apktool

#
# install bata24/gef (GDB Enhanced Features)
#

mkdir -p /opt/gef
wget -O /opt/gef/gef.py https://raw.githubusercontent.com/bata24/gef/master/gef.py
python3 -m pip install keystone-engine ropper

#
# install ida-mcp-rs (IDA Pro MCP server)
#

IDA_MCP_TAG=$(curl -sI https://github.com/blacktop/ida-mcp-rs/releases/latest | grep -i '^location:' | grep -oP 'v[\d.]+')
curl -sL "https://github.com/blacktop/ida-mcp-rs/releases/download/${IDA_MCP_TAG}/ida-mcp_${IDA_MCP_TAG#v}_Linux_x86_64.tar.gz" \
  | tar xz -C /usr/local/bin ida-mcp ida-mcp-bin
chmod +x /usr/local/bin/ida-mcp /usr/local/bin/ida-mcp-bin

#
# Python packages for skills: libdebug
#

python3 -m pip install --ignore-installed typing-extensions
python3 -m pip install libdebug
