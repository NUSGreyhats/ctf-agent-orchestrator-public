#!/bin/bash

set -x
set -e

#
# File forensics tools: steganography, PDF/OLE analysis, media tools
#

# Metadata and image analysis
apt install -y \
    libimage-exiftool-perl \
    pngcheck \
    imagemagick

# Steganography
apt install -y \
    steghide \
    stegseek \
    zbar-tools

# Ruby + zsteg (LSB steganography for PNG/BMP)
apt install -y ruby-dev
gem install zsteg

# Audio/video analysis
apt install -y \
    sox \
    ffmpeg

# DidierStevens tools (pdf-parser, pdfid, oledump)
wget -qO /usr/local/bin/pdf-parser.py \
    https://github.com/DidierStevens/DidierStevensSuite/raw/master/pdf-parser.py
wget -qO /usr/local/bin/pdfid.py \
    https://github.com/DidierStevens/DidierStevensSuite/raw/master/pdfid.py
wget -qO /usr/local/bin/oledump.py \
    https://github.com/DidierStevens/DidierStevensSuite/raw/master/oledump.py
chmod +x /usr/local/bin/pdf-parser.py /usr/local/bin/pdfid.py /usr/local/bin/oledump.py

# OLE/Office document analysis
python3 -m pip install 'oletools[full]' pcode2code

# cpdf (Coherent PDF command-line tools)
CPDF_VERSION="2.7.1"
wget -qO /tmp/cpdf.tar.gz \
    "https://github.com/coherentgraphics/cpdf-binaries/archive/refs/tags/v${CPDF_VERSION}.tar.gz"
tar -xzf /tmp/cpdf.tar.gz -C /tmp
cp "/tmp/cpdf-binaries-${CPDF_VERSION}/Linux-Intel-64bit/cpdf" /usr/local/bin/cpdf
chmod +x /usr/local/bin/cpdf
rm -rf /tmp/cpdf.tar.gz /tmp/cpdf-binaries-*
