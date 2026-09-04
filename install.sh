#!/usr/bin/env bash
set -u
PROJECT="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT" || exit 1
sudo dnf install -y gcc-c++ cmake qt6-qtbase-devel polkit flatpak || exit 1
rm -rf build
mkdir -p build
cd build || exit 1
cmake -DCMAKE_INSTALL_PREFIX=/usr/local .. || exit 1
cmake --build . --parallel || exit 1
sudo cmake --install . || exit 1
sudo update-desktop-database /usr/local/share/applications >/dev/null 2>&1 || true
kbuildsycoca6 >/dev/null 2>&1 || true
echo
echo "TotalSweep Uninstaller was installed successfully."
echo "Run: totalsweep"
