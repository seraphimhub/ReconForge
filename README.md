# ReconForge

ReconForge adalah framework CLI recon modular untuk assessment keamanan yang legal dan terotorisasi. Fokusnya adalah discovery dan metadata: HTTP, DNS, TLS, WHOIS, domain lookup, reverse lookup, ASN, IP lookup, dan geolocation. Tool ini tidak berisi exploit, bypass, brute force, credential capture, atau payload agresif.

## Fitur

- Struktur proyek lengkap, bukan single file.
- Modul: `domain`, `dns`, `whois`, `http`, `tls`, `ip`, `asn`, `geo`, `reverse`.
- Output JSON dan Markdown.
- Scope guard untuk domain/CIDR.
- Flag authorization untuk modul aktif.
- Rate limit dan concurrency limit.
- Provider hook untuk reverse IP dan reverse WHOIS berbayar/eksternal.
- Passive certificate transparency discovery via `crt.sh`.
- RDAP domain/IP lookup via `rdap.org`.
- ASN lookup via Team Cymru whois.

## Instalasi Kali Linux

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip setuptools wheel
python -m pip install -e .
```

Atau pakai installer:

```bash
chmod +x scripts/install-kali.sh
./scripts/install-kali.sh
```

Untuk menjalankan test:

```bash
source .venv/bin/activate
python -m pip install -e ".[dev]"
pytest
```

## Penggunaan Cepat

Lihat modul:

```bash
source .venv/bin/activate
reconforge list-modules
```

Recon pasif/default:

```bash
reconforge scan example.com --scope example.com --format md --output reports/example.md
```

Recon lengkap termasuk HTTP dan TLS, hanya untuk aset yang kamu punya izin:

```bash
reconforge scan example.com --modules all --authorized --scope example.com --format json --output reports/example.json
```

Gunakan scope file:

```bash
reconforge scan example.com --modules all --authorized --scope-file examples/scope.txt
```

Recon batch dari file target:

```bash
reconforge scan-file examples/targets.txt --scope-file examples/scope.txt --output-dir reports
```

IP/ASN/geolocation:

```bash
reconforge scan 8.8.8.8 --modules ip,asn,geo,reverse --format md
```

## Bukti Tools Bekerja

Contoh hasil run penuh pada target demo `example.com`:

```bash
cat reports/example.json
```

```json
{
  "completed_at": "2026-05-15T01:09:57+00:00",
  "findings": [
    {
      "data": {
        "certificate_transparency": {
          "count": 10,
          "names": [
            "as207960 test intermediate - example.com",
            "dev.example.com",
            "example.com",
            "m.example.com",
            "m.testexample.com",
            "products.example.com",
            "subjectname@example.com",
            "support.example.com",
            "user@example.com",
            "www.example.com"
          ],
          "ok": true,
          "url": "https://crt.sh/?q=%25.example.com&output=json"
        },
        "rdap": {
          "error": "Expecting value: line 1 column 1 (char 0)",
          "ok": false,
          "url": "https://rdap.org/domain/example.com"
        }
      },
      "error": null,
      "module": "domain",
      "status": "ok",
      "target": "example.com",
      "timestamp": "2026-05-15T01:09:48+00:00"
    },
    {
      "data": {
        "records": {
          "A": [
            "104.20.23.154",
            "172.66.147.243"
          ],
          "AAAA": [
            "2606:4700:10::6814:179a",
            "2606:4700:10::ac42:93f3"
          ],
          "CAA": [],
          "MX": [
            "0 ."
          ],
          "NS": [
            "elliott.ns.cloudflare.com.",
            "hera.ns.cloudflare.com."
          ],
          "SOA": [
            "elliott.ns.cloudflare.com. dns.cloudflare.com. 2403488901 10000 2400 604800 1800"
          ],
          "TXT": [
            "_k2n1y4vw3qtb4skdx9e7dxt97qrmmq9",
            "v=spf1 -all"
          ]
        }
      },
      "error": null,
      "module": "dns",
      "status": "ok",
      "target": "example.com",
      "timestamp": "2026-05-15T01:09:54+00:00"
    },
    {
      "data": {
        "raw_excerpt": "% IANA WHOIS server\n% for more information on IANA, visit http://www.iana.org\n% This query returned 1 object\n\ndomain:       EXAMPLE.COM\n\norganisation: Internet Assigned Numbers Authority\n\ncreated:      1992-01-01\nsource:       IANA\n\n",
        "referral": null,
        "server": "whois.iana.org",
        "summary": {}
      },
      "error": null,
      "module": "whois",
      "status": "ok",
      "target": "example.com",
      "timestamp": "2026-05-15T01:09:44+00:00"
    },
    {
      "data": {
        "cookies": [],
        "headers": {
          "cf-ray": "9fbe4295a97c87f6-SIN",
          "content-type": "text/html",
          "server": "cloudflare"
        },
        "http_version": "HTTP/1.1",
        "ok": true,
        "reason_phrase": "OK",
        "redirect_chain": [],
        "robots": {
          "found": false,
          "status_code": 404,
          "url": "https://example.com/robots.txt"
        },
        "security_headers": {
          "missing": [
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy"
          ],
          "present": {}
        },
        "status_code": 200,
        "technologies": [
          "cloudflare"
        ],
        "title": "Example Domain",
        "url": "https://example.com"
      },
      "error": null,
      "module": "http",
      "status": "ok",
      "target": "example.com",
      "timestamp": "2026-05-15T01:09:47+00:00"
    },
    {
      "data": {
        "cipher": [
          "TLS_AES_256_GCM_SHA384",
          "TLSv1.3",
          256
        ],
        "expired": false,
        "expires_at_utc": "2026-07-01T21:24:46+00:00",
        "host": "example.com",
        "issuer": {
          "commonName": "Cloudflare TLS Issuing ECC CA 1",
          "countryName": "US",
          "organizationName": "CLOUDFLARE, INC."
        },
        "not_after": "Jul  1 21:24:46 2026 GMT",
        "not_before": "Apr  2 21:18:57 2026 GMT",
        "port": 443,
        "protocol": "TLSv1.3",
        "serial_number": "6520589EF17EB55C664433F29F2E684A",
        "subject": {
          "commonName": "example.com"
        },
        "subject_alt_names": [
          "example.com",
          "*.example.com"
        ]
      },
      "error": null,
      "module": "tls",
      "status": "ok",
      "target": "example.com",
      "timestamp": "2026-05-15T01:09:45+00:00"
    },
    {
      "data": {
        "addresses": [
          {
            "classification": {
              "is_global": true,
              "is_link_local": false,
              "is_loopback": false,
              "is_multicast": false,
              "is_private": false,
              "is_reserved": false,
              "version": "4"
            },
            "ip": "104.20.23.154",
            "ptr": [],
            "rdap": {
              "error": "Expecting value: line 1 column 1 (char 0)",
              "ok": false,
              "url": "https://rdap.org/ip/104.20.23.154"
            }
          },
          {
            "classification": {
              "is_global": true,
              "is_link_local": false,
              "is_loopback": false,
              "is_multicast": false,
              "is_private": false,
              "is_reserved": false,
              "version": "4"
            },
            "ip": "172.66.147.243",
            "ptr": [],
            "rdap": {
              "error": "Expecting value: line 1 column 1 (char 0)",
              "ok": false,
              "url": "https://rdap.org/ip/172.66.147.243"
            }
          },
          {
            "classification": {
              "is_global": true,
              "is_link_local": false,
              "is_loopback": false,
              "is_multicast": false,
              "is_private": false,
              "is_reserved": false,
              "version": "6"
            },
            "ip": "2606:4700:10::6814:179a",
            "ptr": [],
            "rdap": {
              "error": "Expecting value: line 1 column 1 (char 0)",
              "ok": false,
              "url": "https://rdap.org/ip/2606:4700:10::6814:179a"
            }
          },
          {
            "classification": {
              "is_global": true,
              "is_link_local": false,
              "is_loopback": false,
              "is_multicast": false,
              "is_private": false,
              "is_reserved": false,
              "version": "6"
            },
            "ip": "2606:4700:10::ac42:93f3",
            "ptr": [],
            "rdap": {
              "error": "Expecting value: line 1 column 1 (char 0)",
              "ok": false,
              "url": "https://rdap.org/ip/2606:4700:10::ac42:93f3"
            }
          }
        ]
      },
      "error": null,
      "module": "ip",
      "status": "ok",
      "target": "example.com",
      "timestamp": "2026-05-15T01:09:57+00:00"
    },
    {
      "data": {
        "query": "104.20.23.154",
        "raw": "Bulk mode; whois.cymru.com [2026-05-15 01:10:02 +0000]\n13335   | 104.20.23.154    | 104.20.16.0/20      | US | arin     | 2014-03-28 | CLOUDFLARENET - Cloudflare, Inc., US\n",
        "records": [
          {
            "bulk_mode;_whois.cymru.com_[2026-05-15_01:10:02_+0000]": "13335"
          }
        ]
      },
      "error": null,
      "module": "asn",
      "status": "ok",
      "target": "example.com",
      "timestamp": "2026-05-15T01:09:50+00:00"
    },
    {
      "data": {
        "addresses": [
          {
            "classification": {
              "is_global": true,
              "is_private": false,
              "is_reserved": false,
              "version": "4"
            },
            "geolocation": {
              "city": "San Francisco",
              "connection": {
                "asn": 13335,
                "domain": "cloudflare.com",
                "isp": "Cloudflare, Inc.",
                "org": "Cloudflare, Inc."
              },
              "country": "United States",
              "country_code": "US",
              "latitude": 37.718128,
              "longitude": -122.4343849,
              "ok": true,
              "region": "California",
              "timezone": {
                "abbr": "PDT",
                "id": "America/Los_Angeles",
                "is_dst": true,
                "offset": -25200,
                "utc": "-07:00"
              },
              "url": "https://ipwho.is/104.20.23.154"
            },
            "ip": "104.20.23.154"
          },
          {
            "classification": {
              "is_global": true,
              "is_private": false,
              "is_reserved": false,
              "version": "4"
            },
            "geolocation": {
              "city": "San Francisco",
              "connection": {
                "asn": 13335,
                "domain": "cloudflare.com",
                "isp": "Cloudflare, Inc.",
                "org": "Cloudflare, Inc."
              },
              "country": "United States",
              "country_code": "US",
              "latitude": 37.718128,
              "longitude": -122.4343849,
              "ok": true,
              "region": "California",
              "timezone": {
                "abbr": "PDT",
                "id": "America/Los_Angeles",
                "is_dst": true,
                "offset": -25200,
                "utc": "-07:00"
              },
              "url": "https://ipwho.is/172.66.147.243"
            },
            "ip": "172.66.147.243"
          }
        ]
      },
      "error": null,
      "module": "geo",
      "status": "ok",
      "target": "example.com",
      "timestamp": "2026-05-15T01:09:53+00:00"
    },
    {
      "data": {
        "certificate_transparency_names": {
          "count": 10,
          "names": [
            "as207960 test intermediate - example.com",
            "dev.example.com",
            "example.com",
            "m.example.com",
            "m.testexample.com",
            "products.example.com",
            "subjectname@example.com",
            "support.example.com",
            "user@example.com",
            "www.example.com"
          ],
          "ok": true,
          "url": "https://crt.sh/?q=%25.example.com&output=json"
        },
        "reverse_whois": {
          "enabled": false,
          "reason": "reverse_whois requires a configured external provider. Set endpoint, query_param, and optional API key env in configs/default.yaml."
        }
      },
      "error": null,
      "module": "reverse",
      "status": "ok",
      "target": "example.com",
      "timestamp": "2026-05-15T01:09:50+00:00"
    }
  ],
  "metadata": {
    "authorized": true,
    "passive_only": false
  },
  "modules": [
    "domain",
    "dns",
    "whois",
    "http",
    "tls",
    "ip",
    "asn",
    "geo",
    "reverse"
  ],
  "started_at": "2026-05-15T01:09:42+00:00",
  "target": "example.com"
}
```

## Modul

| Modul | Fungsi | Active |
| --- | --- | --- |
| `domain` | RDAP domain dan certificate transparency | no |
| `dns` | A, AAAA, MX, NS, TXT, CAA, SOA, PTR | no |
| `whois` | WHOIS lookup dengan referral IANA | no |
| `http` | Header, redirect, cookie, title, security headers, robots.txt, tech hints | yes |
| `tls` | Sertifikat, SAN, issuer, cipher, protocol, expiry | yes |
| `ip` | IP classification, PTR, RDAP IP | no |
| `asn` | Origin ASN/routing metadata via Team Cymru | no |
| `geo` | Geolocation IP via ipwho.is | no |
| `reverse` | Reverse lookup via CT dan provider hook reverse IP/WHOIS | no |

## Reverse WHOIS dan Reverse IP

Reverse WHOIS biasanya tidak tersedia secara bebas dan umumnya membutuhkan provider komersial. ReconForge menyediakan hook generik di `configs/default.yaml`:

```yaml
passive_sources:
  reverse_whois:
    enabled: true
    endpoint: "https://provider.example/api/reverse-whois"
    query_param: q
    api_key_env: REVERSE_WHOIS_API_KEY
    api_key_header: Authorization
```

Set environment variable sesuai provider:

```bash
export REVERSE_WHOIS_API_KEY="token-kamu"
```

## Standar Keamanan

- Jalankan hanya terhadap aset milik sendiri atau yang punya izin tertulis.
- Gunakan `--scope` atau `--scope-file` agar target tetap dalam batas.
- Modul aktif seperti `http` dan `tls` membutuhkan `--authorized`.
- Domain yang resolve ke IP private/special diblokir untuk modul aktif kecuali `--allow-private` diberikan.
- Default rate limit dibuat konservatif.
- Private/reserved IP diblokir secara default; gunakan `--allow-private` hanya untuk jaringan internal yang kamu boleh uji.
- Detail desain guardrail ada di `docs/security-model.md`.

## Struktur

```text
reconforge/
  cli.py
  core/
    config.py
    context.py
    models.py
    rate_limiter.py
    runner.py
    scope.py
  modules/
    asn.py
    dns.py
    domain.py
    geo.py
    http.py
    ip.py
    reverse.py
    tls.py
    whois.py
  reporting/
    json_report.py
    markdown_report.py
configs/
docs/
examples/
scripts/
tests/
```

## Catatan Legal

ReconForge dibuat untuk defensive security, audit internal, bug bounty yang sesuai rules of engagement, dan asset inventory. Jangan gunakan untuk target tanpa izin.
