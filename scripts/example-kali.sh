#!/usr/bin/env bash
set -euo pipefail

source .venv/bin/activate
mkdir -p reports

reconforge scan example.com \
  --modules dns \
  --scope example.com \
  --format json \
  --output reports/example-dns.json

