#!/usr/bin/env bash
# Chrome for Testing (puppeteer's download) is a desktop build; this
# container's base image lacks several runtime shared libs it dlopens
# (GTK/ATK/cairo/pango/alsa/dbus stack). apt-get download + dpkg -x pulls
# just those .debs and extracts them user-locally -- no root, no system
# package-manager mutation. Run once via `just e2e-setup`.
set -euo pipefail
cd "$(dirname "$0")"

# Package names shifted with the time64 ABI transition (Ubuntu 24.04+ uses
# the t64 suffix for a handful of these); try the modern name, fall back to
# the pre-t64 one so this also works on older bases.
PKG_ALTERNATIVE_PAIRS=(
  "libasound2t64:libasound2"
  "libatk1.0-0t64:libatk1.0-0"
  "libatk-bridge2.0-0t64:libatk-bridge2.0-0"
  "libatspi2.0-0t64:libatspi2.0-0"
  "libcups2t64:libcups2"
)
PKGS_FIXED=(
  libxdamage1 libcairo2 libpango-1.0-0 libavahi-common3 libavahi-client3
  libxcb-render0 libxcb-shm0 libpixman-1-0 libxrender1 libpangocairo-1.0-0
  libpangoft2-1.0-0 libthai0 libdatrie1 libfribidi0 libharfbuzz0b
  libgraphite2-3
)

mkdir -p .chrome-libs/debs .chrome-libs/root
cd .chrome-libs/debs
for pair in "${PKG_ALTERNATIVE_PAIRS[@]}"; do
  apt-get download "${pair%%:*}" 2>/dev/null || apt-get download "${pair##*:}"
done
apt-get download "${PKGS_FIXED[@]}"
for deb in *.deb; do dpkg -x "$deb" ../root; done
cd ..
find "$PWD/root" -name '*.so*' -printf '%h\n' | sort -u | paste -sd: - > ../.chrome-libs-profile
