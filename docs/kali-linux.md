# Kali Linux Usage

Panduan ini memakai terminal Kali/Linux.

## Install

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e .
```

Atau:

```bash
chmod +x scripts/install-kali.sh
./scripts/install-kali.sh
```

## Commands

```bash
source .venv/bin/activate
reconforge list-modules
reconforge scan example.com --modules dns --scope example.com --format json --output reports/example-dns.json
reconforge scan example.com --modules all --authorized --scope example.com --format md --output reports/example-full.md
reconforge scan-file examples/targets.txt --scope-file examples/scope.txt --output-dir reports
```

## Reverse WHOIS Provider Key

```bash
export REVERSE_WHOIS_API_KEY="token-kamu"
```
