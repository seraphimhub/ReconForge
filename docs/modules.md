# Modules

## domain

Performs RDAP domain lookup and certificate transparency name discovery.

## dns

Queries DNS records: A, AAAA, MX, NS, TXT, CAA, SOA, and PTR for IP targets.

## whois

Uses IANA referral WHOIS to locate the registry WHOIS server and stores a short parsed summary plus a raw excerpt.

## http

Fetches HTTP/HTTPS metadata: status, redirects, title, security headers, cookies, interesting headers, robots.txt, and lightweight technology hints. This is an active module.

## tls

Connects to TLS and records certificate subject, issuer, SANs, cipher, protocol, and expiration. This is an active module.

## ip

Resolves IP addresses, classifies them, checks PTR, and fetches RDAP IP metadata.

## asn

Uses Team Cymru WHOIS to map IPs to origin ASN and routing metadata.

## geo

Uses local IP classification plus optional ipwho.is enrichment for global IP addresses.

## reverse

For domains, uses certificate transparency as a passive reverse-name source and exposes a configurable reverse WHOIS provider hook. For IPs, exposes a configurable reverse IP provider hook.

