# @mlabsh/n8n-nodes-mlab

n8n community node for [**mlab.sh**](https://mlab.sh) — bring core scanning, CVE
vulnerability intelligence and threat-actor data into your n8n workflows.

The package ships a single **mlab.sh** node whose surfaces are exposed as resources:

| Resource | Service | Auth |
|----------|---------|------|
| **Domain / IP Address / Crypto Address / File / Quota** (Core) | `mlab.sh/api/v1` — domain / IP / crypto / file scans | API key |
| **CVE** | `vuln.mlab.sh/api/v1` — CVE search & details | none (public) |
| **Threat Actor** | `actors.mlab.sh/api/v1` — threat-actor intel | none (public) |

[Installation](#installation) · [Credentials](#credentials) · [Resources & operations](#resources--operations) · [Examples](#examples)

---

## Installation

### From the n8n UI

1. In n8n, go to **Settings → Community Nodes → Install**.
2. Enter the npm package name: `@mlabsh/n8n-nodes-mlab`.
3. Agree to the risk prompt and install.

> Community nodes require `N8N_COMMUNITY_PACKAGES_ENABLED=true` (the default on self-hosted instances).

### Manually (self-hosted)

```bash
cd ~/.n8n/nodes      # or your N8N_CUSTOM_EXTENSIONS path
npm install @mlabsh/n8n-nodes-mlab
```

Restart n8n afterwards. The **mlab.sh** node then appears in the nodes panel.

---

## Credentials

Only the **Core** resources (Domain / IP Address / Crypto Address / File / Quota) need credentials. The credential field is hidden when a public resource (CVE / Threat Actor) is selected.

1. Create an API key at **mlab.sh → Account → Settings → API Keys** (it starts with `mlab_`).
2. In n8n, add a new **mlab.sh API** credential and paste the key.
3. The node sends it as `Authorization: token mlab_...`. The credential's *Test* button hits `GET /limit/ip` to validate the key.

The **CVE** and **Threat Actor** resources call public, unauthenticated APIs — no credential required.

---

## Resources & operations

Pick a **Resource**, then an **Operation**. The node processes every input item and outputs the raw JSON returned by mlab.sh.

### Core — Domain

| Operation | Endpoint | Notes |
|-----------|----------|-------|
| **Scan** | `POST /scan/domain` | Launches a scan. With **Wait for Completion** on (default) it polls `/scan/domain/status` and returns the full `/scan/domain/results` payload (subdomains, DNS, SSL, security.txt…). Disable it to return only the job acknowledgement. **Timeout (Seconds)** controls how long polling waits. |
| **Get Status** | `GET /scan/domain/status` | Check an async scan you launched yourself. |
| **Get Results** | `GET /scan/domain/results` | Fetch results once a scan has finished. |

### Core — IP Address

| Operation | Endpoint | Notes |
|-----------|----------|-------|
| **Lookup** | `GET /scan/ip` | Geolocation, ASN and ownership for an IPv4/IPv6 address. |

### Core — Crypto Address

| Operation | Endpoint | Notes |
|-----------|----------|-------|
| **Lookup** | `GET /scan/crypto` | Sanctions, labels and risk score. **Chain** can be auto-detected (leave blank) or forced (BTC, ETH, SOL, TRON, …). |

### Core — File

| Operation | Endpoint | Notes |
|-----------|----------|-------|
| **Upload** | `POST /upload/file` | Uploads the file from the **Input Binary Field** (max 10 MB) and returns its `sha256`. |
| **Get Results** | `GET /scan/file/results` | Fetch analysis results by **SHA-256** hash. |

### Core — Quota

| Operation | Endpoint | Notes |
|-----------|----------|-------|
| **Get** | `GET /limit/{type}` | Remaining daily quota for a **Scan Type** (domain / IP / file / crypto). |

### CVE

| Operation | Endpoint | Notes |
|-----------|----------|-------|
| **Search** | `GET /cve?q=…` | Search by keyword, vendor or product. Optional **Filters**: severity, published-after date, exact match, KEV-only. |
| **Get** | `GET /cve/{id}` | Full detail for a CVE, including EPSS and KEV data. |
| **Get Latest** | `GET /cve/latest` | Vulnerabilities from the last 7 days. |

### Threat Actor

| Operation | Endpoint | Notes |
|-----------|----------|-------|
| **List / Search** | `GET /actors` | Optional **Filters**: origin, motivation, sector. Paginate with **Limit** / **Offset**. |
| **Get** | `GET /actors/{slug}` | A single actor by slug, including aliases, tools, CVEs and techniques. |
| **Get by CVE** | `GET /cves/{id}/actors` | Reverse lookup — which actors are known to exploit a given CVE. |

---

## Examples

**Enrich a domain on demand.** Webhook → **mlab.sh** (Resource: *Domain*, Operation: *Scan*, Wait for Completion: on) → use the returned subdomains / SSL / DNS data downstream.

**Vulnerability watch.** Schedule Trigger (daily) → **mlab.sh** (Resource: *CVE*, Operation: *Get Latest*) → Filter on `severity = CRITICAL` → notify Slack / email.

**Threat-actor context for an alert.** **mlab.sh** (Resource: *Threat Actor*, Operation: *Get by CVE*, CVE ID: `CVE-2021-44228`) → attach the matching actors to your incident record.

**Crypto / IP triage.** Feed a list of addresses or IPs into **mlab.sh** (Resource: *Crypto Address* or *IP Address*, Operation: *Lookup*); the node runs once per input item and returns risk/ownership data per row.

> Each Core operation consumes daily quota. Use the **Quota → Get** operation to check remaining budget before large batch runs.

---

## License

[MIT](LICENSE) · Threat-actor data is sourced from ETDA under CC BY-NC-SA 4.0.
