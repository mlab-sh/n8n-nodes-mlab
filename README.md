# @mlabsh/n8n-nodes-mlab

n8n community node for [**mlab.sh**](https://mlab.sh) — bring core scanning, CVE
vulnerability intelligence and threat-actor data into your n8n workflows.

The package ships two nodes: **mlab.sh**, whose surfaces are exposed as resources, and **mlab.sh Trigger**, which starts a workflow on a signed mlab.sh webhook.

| Resource | Service | Auth |
|----------|---------|------|
| **Domain / IP / Crypto / File / Hash / URL / Email / Phone / MAC / IOC / Quota** (Core) | `mlab.sh/api/v1` — scans and lookups | API key |
| **Batch Triage / RedKit Audit / Watchdog Schedule / Case / Finding Tag / Monitoring Finding** | `mlab.sh/api/v1` — automation and collaboration | API key |
| **CVE** | `vuln.mlab.sh/api/v1` — CVE search & details | none (public) |
| **Threat Actor** | `actors.mlab.sh/api/v1` — threat-actor intel | none (public) |

[Installation](#installation) · [Credentials](#credentials) · [Resources & operations](#resources--operations) · [Trigger](#mlabsh-trigger) · [Examples](#examples)

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

Every resource but CVE and Threat Actor needs credentials. The credential field is hidden when a public resource is selected.

1. An owner or admin creates an API key in **mlab.sh → Organization settings → API keys** (it starts with `mlab_`). Give it the permissions the workflow uses: `scan.lookup`, `scan.domain`, `scan.file`, `scan.batch`, `redkit`, `watchdog.read` / `watchdog.write`, `cases.read` / `cases.write`, `tags.read` / `tags.write`. A call outside them answers 403 and names the missing permission.
2. In n8n, add a new **mlab.sh API** credential and paste the key.
3. The node sends it as `Authorization: token mlab_...`. The credential's *Test* button hits `GET /limit/ip` to validate the key.

Keys **expire after 90 days** by default. An expired, revoked or unknown key answers 401, and the node says so: create a new key and update the credential.

**Quota in the output.** Scans made with a key carry `X-RateLimit-Limit`, `-Remaining`, `-Resource` and `-Window` headers; the node adds them to the item as `rateLimit: {limit, remaining, resource, windowSeconds}`, so a workflow can slow down before it hits the 429.

The **CVE** and **Threat Actor** resources call public, unauthenticated APIs — no credential required.

---

## Resources & operations

Pick a **Resource**, then an **Operation**. The node processes every input item and outputs the raw JSON returned by mlab.sh.

### Core — Domain

| Operation | Endpoint | Notes |
|-----------|----------|-------|
| **Scan** | `POST /scan/domain` | Launches a scan. With **Wait for Completion** on (default) it polls `/scan/domain/status` and returns the scan **Output**: the v2 report (default) or the legacy v1 results. A scan that ends `failed` raises an error. Disable it to return only the job acknowledgement. **Timeout (Seconds)** controls how long polling waits. |
| **Get Status** | `GET /scan/domain/status` | `pending`, `scanning` (with `done` / `total` job progress) or `success`. |
| **Get Report** | `GET /scan/domain/report` | The whole scan, `schema: "domain-report/2"`: `score` (value + grade), `findings` (severity / title / section / block), `registration`, `dns`, `mail`, `ai`, `web`, `certificates`, `surface`. `status` is `completed`, `partial`, `failed` or `in_progress` (ungraded). |
| **Get Results (Legacy)** | `GET /scan/domain/results` | Frozen v1 payload: subdomains, DNS resolve / TXT, SSL, security.txt and robots.txt. |
| **Get SSL Certificates** | `GET /domain/ssl` | Certificates seen in certificate transparency logs. |
| **Capture Network Requests** | `GET /scan/domain/loadnetworkrequest` | Loads a page in a headless browser and lists every request it makes. |

Node version 1.1 defaults **Output** to the v2 report. Workflows built on version 1 keep the legacy results until you switch Output.

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
| **Upload** | `POST /upload/file` | Uploads the file from the **Input Binary Field** (10 MB, 100 MB on paid plans) and returns its `sha256`. |
| **Get Results** | `GET /scan/file/results` | Fetch analysis results by **SHA-256** hash. |

### Core — Quota

| Operation | Endpoint | Notes |
|-----------|----------|-------|
| **Get** | `GET /limit/{type}` | Remaining daily quota for a **Scan Type** (domain / IP / file / crypto). |

### Batch Triage

| Operation | Endpoint | Notes |
|-----------|----------|-------|
| **Triage** | `POST /scan/batch` | Types, de-duplicates and enriches up to 200 pasted indicators from what mlab already holds. **Spends no lookup**: an indicator mlab has not seen comes back as `needs_lookup`. |

### RedKit Audit

| Operation | Endpoint | Notes |
|-----------|----------|-------|
| **Launch** | `POST /scan/redkit` | Audits a domain your organization has verified, with the chosen **Plugins**. Returns `scan_uuid`. |
| **Get Status** | `GET /scan/redkit/status` | `status`, and `raw_json` once `completed`. |
| **Get Quota** | `GET /scan/redkit/quota` | Plan, used, limit, remaining (`-1` = unlimited). |

### Watchdog Schedule

| Operation | Endpoint | Notes |
|-----------|----------|-------|
| **List** | `GET /scan/watchdog/list` | One item per schedule. |
| **Create** | `POST /scan/watchdog/create` | A recurring **Domain Scan** (any domain, daily/weekly/monthly) or **RedKit Audit** (verified domain, weekly/monthly). Hours are UTC. |
| **Update** | `POST /scan/watchdog/update` | Enable or disable a schedule. |
| **Delete** | `POST /scan/watchdog/delete` | |

### Case

| Operation | Endpoint | Notes |
|-----------|----------|-------|
| **List** | `GET /cases` | One item per case. |
| **Get** | `POST /cases/detail` | A case with its indicators and comments. |
| **Create / Update / Delete** | `POST /cases/create`, `/update`, `/delete` | Update takes title, summary and status (`open` / `closed`). A key deletes only what it created. |
| **Add Indicators / Delete Indicator** | `POST /cases/indicator/add`, `/delete` | Indicators are pasted text, typed and de-duplicated by mlab. |
| **Add Comment / Delete Comment** | `POST /cases/comment/add`, `/delete` | A comment can be attached to one indicator. |

### Finding Tag and Monitoring Finding

| Operation | Endpoint | Notes |
|-----------|----------|-------|
| **Finding Tag → List / Add / Remove** | `GET /scan/finding-tags`, `/add`, `/remove` | Triage a RedKit finding: `false-positive`, `accepted-risk`, `fixed`, `review-later`. Dismissed findings stay dismissed on the next scans, and the linked issue tracker follows. |
| **Monitoring Finding → Set Status** | `POST /scan/monitoring/finding-status` | `false_positive`, `accepted_risk` or `open` on a security monitoring finding (Team and Enterprise). |

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

## mlab.sh Trigger

Starts the workflow when mlab.sh delivers a webhook: RedKit results and new findings, domain scans finished or changed, watchdog runs, monitoring findings, agents, quota and audit events.

1. Add the **mlab.sh Trigger** node and copy its production URL.
2. In mlab.sh, **Organization → Alerting → Channels**, add a webhook endpoint with that URL and the **Generic** format (the chat formats are not signed), and pick its events.
3. Paste the secret shown at creation in an **mlab.sh Webhook API** credential.

Each delivery is checked before the workflow runs: `X-Mlab-Signature` must be the HMAC-SHA256 of `<X-Mlab-Timestamp>.<body>` under the secret, and the timestamp within **Timestamp Tolerance** (300 s by default) of now; anything else answers 401. mlab retries a delivery for about seven hours with the same `X-Mlab-Delivery`, so a retry of a delivery already received is acknowledged and not run twice. **Events** narrows which events start the workflow; the output is the delivery's JSON (`event`, `delivery_id`, `timestamp`, `org_uuid`, `data`, with `data.alert` as the common summary).

---

## Examples

**Enrich a domain on demand.** Webhook → **mlab.sh** (Resource: *Domain*, Operation: *Scan*, Wait for Completion: on) → route on `score.grade` or the `findings` array of the returned v2 report.

**Vulnerability watch.** Schedule Trigger (daily) → **mlab.sh** (Resource: *CVE*, Operation: *Get Latest*) → Filter on `severity = CRITICAL` → notify Slack / email.

**Threat-actor context for an alert.** **mlab.sh** (Resource: *Threat Actor*, Operation: *Get by CVE*, CVE ID: `CVE-2021-44228`) → attach the matching actors to your incident record.

**Crypto / IP triage.** Feed a list of addresses or IPs into **mlab.sh** (Resource: *Crypto Address* or *IP Address*, Operation: *Lookup*); the node runs once per input item and returns risk/ownership data per row.

**Close the loop on RedKit.** **mlab.sh Trigger** (Events: `scan.redkit.findings.new`) → open a case (**Case → Create**), add the hosts (**Add Indicators**) → once fixed, **Finding Tag → Add** `fixed`.

**Paste triage.** Email Trigger → **Batch Triage** on the body → route the rows that are `needs_lookup` to the per-type lookups.

> Each Core operation consumes daily quota. Use the **Quota → Get** operation to check remaining budget before large batch runs.

---

## License

[MIT](LICENSE) · Threat-actor data is sourced from ETDA under CC BY-NC-SA 4.0.
