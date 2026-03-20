#!/bin/bash

set -x
set -e

#
# install JADX 1.5.5
#

wget "https://github.com/skylot/jadx/releases/download/v1.5.5/jadx-1.5.5.zip"
unzip jadx-1.5.5.zip -d /opt/jadx-1.5.5/
rm -f jadx-1.5.5.zip
chmod +x /opt/jadx-1.5.5/bin/jadx
echo 'export PATH=$PATH:/opt/jadx-1.5.5/bin' >> ~/.bashrc

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
wget -O /opt/gef/gef.py https://raw.githubusercontent.com/bata24/gef/main/gef.py
python3 -m pip install keystone-engine ropper

#
# Python packages for skills: ida-domain, libdebug
#

python3 -m pip install --ignore-installed typing-extensions
python3 -m pip install ida-domain libdebug
