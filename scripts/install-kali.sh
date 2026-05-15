#!/usr/bin/env bash
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 tidak ditemukan. Install dulu: sudo apt install -y python3 python3-venv python3-pip" >&2
  exit 1
fi

if ! python3 -m venv --help >/dev/null 2>&1; then
  echo "python3-venv belum tersedia, mencoba install via apt..."
  sudo apt update
  sudo apt install -y python3-venv python3-pip
fi

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e .

mkdir -p reports
reconforge list-modules

cat <<'EOF'

ReconForge siap dipakai.

Aktifkan environment:
  source .venv/bin/activate

Contoh scan aman:
  reconforge scan example.com --modules dns --scope example.com --format json --output reports/example-dns.json

Untuk modul aktif HTTP/TLS, gunakan hanya pada aset yang punya izin:
  reconforge scan example.com --modules all --authorized --scope example.com --output reports/example.json
EOF

