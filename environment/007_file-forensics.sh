#!/bin/bash

set -euo pipefail
set -x

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=environment/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"

#
# File forensics tools: steganography, PDF/OLE analysis, media tools
#

apt_install \
  libimage-exiftool-perl \
  pngcheck \
  imagemagick \
  steghide \
  stegseek \
  zbar-tools \
  ruby-dev \
  sox \
  ffmpeg

if ! have_cmd zsteg; then
  gem_install zsteg
fi

download_file \
  https://github.com/DidierStevens/DidierStevensSuite/raw/master/pdf-parser.py \
  /usr/local/bin/pdf-parser.py
download_file \
  https://github.com/DidierStevens/DidierStevensSuite/raw/master/pdfid.py \
  /usr/local/bin/pdfid.py
download_file \
  https://github.com/DidierStevens/DidierStevensSuite/raw/master/oledump.py \
  /usr/local/bin/oledump.py
chmod +x /usr/local/bin/pdf-parser.py /usr/local/bin/pdfid.py /usr/local/bin/oledump.py

uv_pip_install 'oletools[full]' pcode2code

if ! have_cmd cpdf; then
  CPDF_VERSION="2.7.1"
  download_file \
    "https://github.com/coherentgraphics/cpdf-binaries/archive/refs/tags/v${CPDF_VERSION}.tar.gz" \
    /tmp/cpdf.tar.gz
  tar -xzf /tmp/cpdf.tar.gz -C /tmp
  cp "/tmp/cpdf-binaries-${CPDF_VERSION}/Linux-Intel-64bit/cpdf" /usr/local/bin/cpdf
  chmod +x /usr/local/bin/cpdf
  rm -rf /tmp/cpdf.tar.gz /tmp/cpdf-binaries-*
fi
