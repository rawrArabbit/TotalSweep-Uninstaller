#!/usr/bin/env bash
set -u

PROJECT="$(cd "$(dirname "$0")" && pwd)"
exec "$PROJECT/totalsweep-uninstall" "$@"
