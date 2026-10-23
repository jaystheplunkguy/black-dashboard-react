#!/usr/bin/env bash
# Package the Splunk app: vendors splunklib into bin/lib and writes dist/changeguard-<version>.tgz
set -euo pipefail
cd "$(dirname "$0")"
APP=splunk_app/changeguard
VERSION=$(sed -n 's/^version = //p' "$APP/default/app.conf")
rm -rf "$APP/bin/lib"
python3 -m pip install --quiet --no-compile --target "$APP/bin/lib" "splunk-sdk>=2.0"
find "$APP" -name "__pycache__" -type d -prune -exec rm -rf {} +
mkdir -p dist
tar -C splunk_app --exclude="local" --exclude="*.pyc" -czf "dist/changeguard-$VERSION.tgz" changeguard
echo "built dist/changeguard-$VERSION.tgz"
