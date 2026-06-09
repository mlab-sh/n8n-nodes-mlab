# @mlabsh/n8n-nodes-mlab

n8n community nodes for [**mlab.sh**](https://mlab.sh) — bring core scanning, CVE
vulnerability intelligence and threat-actor data into your n8n workflows.

This package ships three nodes:

| Node | Service | Auth |
|------|---------|------|
| **mlab.sh Core** | `mlab.sh/api/v1` — domain / IP / crypto / file scans | API key |
| **mlab.sh CVE** | `vuln.mlab.sh/api/v1` — CVE search & details | none (public) |
| **mlab.sh Threat Actors** | `actors.mlab.sh/api/v1` — threat-actor intel | none (public) |

[Installation](#installation) · [Credentials](#credentials) · [Operations](#operations) · [Local development](#local-development) · [Publishing to npm](#publishing-to-npm) · [Becoming a verified / official node](#becoming-a-verified--official-node)

---

## Installation

### From the n8n UI (recommended)

1. In n8n, go to **Settings → Community Nodes → Install**.
2. Enter the npm package name: `@mlabsh/n8n-nodes-mlab`.
3. Agree to the risk prompt and install.

> Community nodes require `N8N_COMMUNITY_PACKAGES_ENABLED=true` (the default on self-hosted instances). On **n8n Cloud**, only *verified* community nodes can be installed (see below).

### Manually (self-hosted)

```bash
cd ~/.n8n/nodes      # or your N8N_CUSTOM_EXTENSIONS path
npm install @mlabsh/n8n-nodes-mlab
```

Restart n8n afterwards.

---

## Credentials

Only the **Core** node needs credentials.

1. Create an API key at **mlab.sh → Account → Settings → API Keys** (it starts with `mlab_`).
2. In n8n, add a new **mlab.sh API** credential and paste the key.
3. The node sends it as `Authorization: token mlab_...`. The credential's *Test* button hits `GET /limit/ip` to validate the key.

The **CVE** and **Threat Actors** nodes call public, unauthenticated APIs — no credential required.

---

## Operations

### mlab.sh Core

- **Domain → Scan** — launches `POST /scan/domain`. With *Wait for Completion* on (default) it polls `/scan/domain/status` and returns the full `/scan/domain/results` payload (subdomains, DNS, SSL, security.txt…).
- **Domain → Get Status** / **Get Results** — for managing an async scan yourself.
- **IP → Lookup** — `GET /scan/ip` (geolocation, ASN, ownership).
- **Crypto → Lookup** — `GET /scan/crypto` (sanctions, labels, risk score). Chain auto-detected or forced.
- **File → Upload** — `POST /upload/file` from an input binary field (max 10MB) and returns the `sha256`.
- **File → Get Results** — `GET /scan/file/results?sha256=…`.
- **Quota → Get** — remaining daily quota for a scan type (`GET /limit/{type}`).

### mlab.sh CVE

- **Search** — `GET /cve?q=…` with optional `severity`, `dateStart`, `exact`, `kev` filters.
- **Get** — `GET /cve/CVE-XXXX-XXXX` (full detail incl. EPSS & KEV).
- **Get Latest** — `GET /cve/latest` (last 7 days).

### mlab.sh Threat Actors

- **List / Search** — `GET /actors` with `origin`, `motivation`, `sector`, `limit`, `offset`.
- **Get** — `GET /actors/:slug` (aliases, tools, CVEs, techniques).
- **Get by CVE** — `GET /cves/CVE-XXXX-XXXX/actors` (reverse lookup).

---

## Local development

```bash
npm install
npm run build         # compiles TS → dist/ and copies icons
npm run lint          # n8n-nodes-base lint rules

# Link into a local n8n for testing:
npm link
cd ~/.n8n/nodes && npm link @mlabsh/n8n-nodes-mlab
n8n start
```

Requires Node ≥ 20.15 (same as n8n).

---

## Publishing to npm

```bash
npm login                       # scope @mlabsh must exist / you must own it
npm run build
npm publish --access public     # scoped packages are private by default
```

`prepublishOnly` re-runs the build + lint, and `.npmignore` ships only `dist/`, `package.json`, `README.md` and `LICENSE`.

---

## Becoming a verified / official node

n8n has three tiers. This package starts at tier 1.

1. **Community node (now).** Any package named `n8n-nodes-*` (or scoped `@scope/n8n-nodes-*`) published to npm with the `n8n-community-node-package` keyword. Installable on self-hosted n8n immediately after `npm publish`.

2. **Verified community node** (installable on n8n Cloud). Submit the package for n8n's review. Requirements:
   - Package name matches `n8n-nodes-*` / `@scope/n8n-nodes-*` ✅
   - `package.json` declares `n8n.n8nNodesApiVersion`, `nodes`, `credentials` ✅
   - Passes `eslint-plugin-n8n-nodes-base` with **zero errors** on the `community`, `nodes` and `credentials` rulesets — run `npm run lint` ✅ (a few opinionated rules are relaxed in `.eslintrc.js`; tighten them before submitting)
   - No runtime dependencies beyond `n8n-workflow` (this package has none) ✅
   - Icons, `description`, `documentationUrl`, codex/category metadata present
   - Submit via the form linked from n8n's docs: **Creating nodes → Submit community nodes for verification** (<https://docs.n8n.io/integrations/creating-nodes/deploy/submit-community-nodes/>). n8n reviews the source and, once approved, the node appears in the in-app nodes panel and is installable on Cloud.

3. **Official / built-in node** (ships inside n8n core). This is owned by n8n, not by package authors. The realistic path:
   - Get adoption + verification first (tier 2).
   - Open a discussion/issue on <https://github.com/n8n-io/n8n> proposing the integration, or contact n8n's partnerships team (integrations are often prioritised via the partner program).
   - If accepted, the node source is contributed into the `n8n-nodes-base` package via PR following n8n's contribution guide. From then on n8n maintains it and the community package can be deprecated.

**Recommended sequence:** publish this package → gather usage → submit for verification (tier 2) → propose upstreaming to n8n core (tier 3).

---

## License

[MIT](LICENSE) · Threat-actor data is sourced from ETDA under CC BY-NC-SA 4.0.
