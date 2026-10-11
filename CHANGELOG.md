# Changelog

All notable changes to `@mlabsh/n8n-nodes-mlab`. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## 1.2.0 - 2026-10-11

Domain scan v2.

### Added

- **Domain → Get Report**: the full v2 scan report (`schema: "domain-report/2"`) with score, findings, registration, DNS, mail, AI, web, certificates and attack surface.
- **Domain → Scan → Output**: pick the v2 report or the legacy v1 results once the scan finishes.

### Changed

- Node version 1.1: **Scan** returns the v2 report by default. Version 1 nodes keep the v1 results.
- **Get Results** is renamed **Get Results (Legacy)**; the v1 payload is frozen upstream.

- Dev dependencies updated: `npm audit` reports 0 vulnerabilities (down from 15). `gulp` is dropped; the icon copy is a `fs.cpSync` in the build script. `axios` is overridden to `^1.20.0`, because `n8n-workflow` pins a vulnerable version.

### Fixed

- A scan that ends `failed` now raises an error instead of returning a payload, when waiting on the v2 report.

## 1.1.2 - 2026-09-24

Brings the node in line with the full public mlab.sh API.

### Added

- **Hash** resource: look up an MD5, SHA-1 or SHA-256 against known-good and known-malicious reference sets, single or bulk.
- **URL** resource: analyse a URL for phishing shapes, with an optional *Follow Redirects* switch to resolve its final destination.
- **Email Address** resource: mailbox type, domain spoofability and risk score.
- **Phone Number** resource: validity, line type, allocated operator and scam shapes.
- **MAC Address** resource: vendor, randomization, virtualization and every notation.
- **IOC** resource: extract every indicator from raw text, with optional SMS threat scoring (*Fast* offline or *Deep* with network checks) and a country pack.
- **Crypto Address → Bulk Lookup**: many addresses in one call, with an optional chain applied to the batch.
- **Domain → Get SSL Certificates**: certificate history from certificate transparency logs.
- **Domain → Capture Network Requests**: load a page in a headless browser and list every request it makes (counts as one domain scan).
- **File → Get Tool Output**: raw output of a single analysis tool.

### Changed

- Bulk lookups pool the values of every input item and send them in as few requests as the API allows (500 hashes or 100 addresses per call), instead of one request per item. Crypto items are grouped by chain. Duplicates are dropped before sending.
- The credential base URL is read once per execution instead of on every request.

### Fixed

- **File → Upload** now posts to `https://mlab.sh/upload/file`. It previously called `/api/v1/upload/file`, which does not exist, so every upload failed with a 404.

## 0.1.3 - 2026-06-10

### Fixed

- Package metadata adjusted for n8n verified community node requirements.

## 0.1.1 - 2026-06-09

### Added

- First public release: Domain (scan, status, results), IP lookup, Crypto lookup, File (upload, results), Quota, CVE (search, get, latest) and Threat Actor (list, get, by CVE).

