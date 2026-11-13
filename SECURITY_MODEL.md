# Threat model: rayaun01/govtechsg-oobee (Oobee accessibility scanner)

## System overview
Oobee is a Node.js/TypeScript tool (published as `@govtechsg/oobee`). It crawls websites, sitemaps and local HTML/PDF files with Playwright/Crawlee, injects axe-core and custom checks into each page, and writes HTML/PDF/CSV/JSON reports. It can also upload results to S3, send telemetry to Sentry, and tunnel traffic through a Cloudflare Worker SOCKS proxy.

**Deployment (user-provided):** developers and auditors run the CLI or desktop app on their own machines. CI, hosted-service and npm-library use were not selected as current deployments. Hosted-service attackers were still named as relevant, though (see Open questions), so code paths used by the hosted mode (S3 upload via `OOBEE_SCAN_ID`/`OOBEE_USER_*` env, Docker image) stay in scope.

**Infrastructure:** no separate infrastructure repository (user-confirmed). The only deployment artifacts are the `Dockerfile` (base `mcr.microsoft.com/playwright`, non-root user `purple`), `.github/workflows/*` (npm publish with `NPM_TOKEN`, GHCR push, macOS signing certs in `image.yml`) and `gitlab-pipeline-template.yml`.

## Components
| Component | Code | Notes |
|---|---|---|
| **CLI & API** | `src/cli.ts`, `src/index.ts`, `src/npmIndex.ts`, `src/combine.ts`, `src/constants/cliFunctions.ts`, `src/constants/questions.ts` | Operator input (trusted). Orchestrates scans. |
| **Crawlers** | `src/crawlers/crawl*.ts`, `commonCrawlerFunc.ts`, `crawlRateController.ts`, `pageCapture.ts`, `pdfScanFunc.ts`, `src/constants/common.ts`, `src/safeBrowsingProfile.ts`, `src/utils.ts`, `src/shutdownController.ts` | Loads untrusted site content in Chromium and handles redirects, robots.txt, sitemaps and PDF downloads. veraPDF runs via `spawnSync(..., {shell:true})`. Chrome profiles and cookies are cloned. |
| **Custom Flow** | `src/crawlers/runCustom.ts`, `src/crawlers/custom/*`, `src/crawlers/guards/urlGuard.ts`, `src/crawlers/scanCustomFlow.ts` | Headed browser with an overlay menu. `page.exposeFunction('handleOnScanClick'/'handleOnStopClick'/'updateMenuPos')` is callable by any page script. |
| **Reports** | `src/mergeAxeResults.ts`, `src/mergeAxeResults/*`, `src/static/ejs/**`, `src/generateHtmlReport.ts`, `src/screenshotFunc/*`, `src/generateOobeeClientScanner.ts`, `oobee-client-scanner.js` | Renders untrusted page data (HTML snippets, URLs, titles, alt text) into the reports. About 81 unescaped `<%-` EJS outputs. |
| **Network Proxy** | `src/proxyService.ts`, `src/cfProxyWorker.ts` | Local SOCKS5 on 127.0.0.1 tunnelled over WebSocket to a CF Worker using `CF_WORKER_PROXY_AUTH_TOKEN`. Family DoH filtering. |
| **Upload & Telemetry** | `src/services/s3Uploader.ts`, Sentry setup in `src/constants/constants.ts` / `src/utils.ts` | Uploads the results folder to `S3_BUCKET_NAME` with user metadata (email, userId). Sentry events carry scan metadata. |
| **Build & Release** | `Dockerfile`, `.github/workflows/*`, `scripts/*`, `gitlab-pipeline-template.yml`, `package.json`/`package-lock.json` | Supply chain: npm deps, base image, Chrome .deb, unpinned GitHub Actions tags. |

## Trust boundaries and entry points
1. **Scanned content → scanner (primary).** Untrusted HTML/JS, redirects, robots.txt, sitemap XML and PDFs from target sites enter Crawlers and Custom Flow. That data then reaches Node (page.evaluate results, exposed functions), the filesystem (dataset JSON, downloaded PDFs, screenshots) and Reports.
2. **Report → report viewer.** Generated HTML reports are opened in a browser by the operator or by whoever receives them.
3. **Scanner → external services.** S3 (AWS creds from the environment), Sentry, the CF Worker proxy and Google Safe Browsing.
4. **Hosted submitter → scanner.** If a hosted service passes user-submitted URLs/options into Oobee (see Open questions).
5. **Supply chain → build/release.** npm deps, Docker base image, GitHub Actions, and the publish secrets (`NPM_TOKEN`, signing certs).

## Assets (user-provided: all marked critical)
- **Host/container integrity.** Scanned content must never lead to code execution on the scanning host.
- **AWS S3 credentials and the results bucket** (integrity and confidentiality of uploaded results; key/prefix control).
- **CF Worker proxy token and proxy.** No leakage, and no open-relay abuse of the local SOCKS listener or the worker.
- **Confidentiality of scan results.** Authenticated pages, cookies from cloned Chrome profiles, DOM/screenshot captures.
- **Scanner PII** (name/email) sent to Sentry and S3 metadata.

## Attacker profiles (user-provided)
- **Malicious or compromised scanned website.** Tries to escape into Node/host, inject script into reports (XSS), use redirects or sitemaps to make the scanner reach internal/file:// resources (SSRF/LFI), or exfiltrate cookies and profile data.
- **Untrusted user of a hosted scanning service.** Submits URLs/options to a service built on Oobee.
- **Supply-chain attacker.** Compromised npm dependency, Docker base image or GitHub Action.
- *Not selected:* a recipient of a generated report acting as the attacker. Report XSS still matters because the scanned site is the attacker who plants the payload.

## Existing controls (observed in code)
- `urlGuard.ts` restricts navigation in Custom Flow. robots.txt handling and blacklisted-pattern files.
- The SOCKS listener binds to `127.0.0.1` only. The worker token is sent as an Authorization header.
- S3 metadata values are sanitised to printable ASCII (`sanitizeS3MetadataValue`).
- The Docker image runs as non-root `purple`, with `NODE_ENV=production` and `npm install --omit=dev`.
- Safe Browsing (optional) blocks known-malicious URLs.

## Out of scope / accepted risk (user-provided)
- **Anything that requires control of CLI args, `init()` options or environment variables.** The operator is trusted. This covers command/path injection through `-u`, `-o`, `-x`, `-k`, `OOBEE_*`, `S3_*`, `CF_WORKER_PROXY*` and the veraPDF paths when the value comes from the operator.
- **`NODE_TLS_REJECT_UNAUTHORIZED=0`** (`src/constants/constants.ts`) is intentional, to support self-signed sites, and accepted.

## Open questions
- Hosted service: the user is **not sure** whether a hosted service feeds user-submitted URLs/options into Oobee and asked that findings depending on a hosted submitter **keep the scanner's severity** (not lowered for operator trust). Operator-trust (out-of-scope) applies only when the operator themselves controls the input.
- Dev/demo files (`dev/`, `examples/`, `testStaticJSScanner.html`, `scripts/`) were not ruled out and stay in scope.
