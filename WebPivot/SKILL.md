---
name: WebPivot
description: Website content & DOM analysis for OSINT and cybercrime investigation — extracts pivot artifacts (favicon mmh3 hash, tracking/analytics IDs, crypto wallets, emails, contact phones, Telegram channels/invites, Google Doc/Sheet/Form/Drive IDs, footer postal address, page description, ETag, WHOIS registrant name/org/phone/email/dates, third-party infra, template/DOM fingerprints) from a page's HTML/DOM and produces ready-to-run pivot queries (Shodan, PublicWWW, crt.sh, urlscan, Validin, Chainabuse). USE WHEN analyze website, analyze HTML, analyze DOM, page analysis, find pivot, pivoting point, pivot artifact, favicon hash, tracking ID, analytics ID, GA GTM pixel, reverse analytics, phone number, telegram channel, google sheet, google form, footer address, whois registrant, cluster sites, campaign clustering, phishing kit, scam site, infrastructure link, source code search, who owns this site, related domains, threat infrastructure.
---

> **OPSEC — this skill is portable/shared. Never write case data into it.** No real operator
> names, emails, domains, IPs, wallets, tracking IDs, hashes, or case IDs in this file, its
> workflows, tool code, or test fixtures. Investigation data lives only in the git-ignored
> `cases/` / `knowledge/` / `MEMORY/`. In examples use placeholders (`example.com`,
> `G-XXXXXXXXXX`, `CASE-0001`). See the repo-root `CLAUDE.md` for the full rule.

## Customization

**Before executing, check for user customizations at:**
`~/.claude/PAI/USER/SKILLCUSTOMIZATIONS/WebPivot/`

If this directory exists, load and apply any PREFERENCES.md, API keys, or resources found there. These override default behavior. If the directory does not exist, proceed with skill defaults.

**API keys (optional — enables live pivoting).** `pivot_extract.py` reads keys from the
environment first, then from a `chmod 600` `.env` in the customization dir (env wins).
Recognized: `URLSCAN_API_KEY`, `FOFA_KEY` (or `FOFA_API_KEY`), `FOFA_EMAIL`, `WHOISXML_API_KEY`,
`PDNS_USERNAME` + `PDNS_PASSWORD` (passive DNS, optional `PDNS_URL`).
With keys set, the tool runs the HIGH-confidence pivots live — FOFA reverses the favicon
`icon_hash` and tracker/verification bodies, authenticated urlscan content-searches the same
values, and WhoisXML adds current + historical registrant data plus reverse-WHOIS pivots — all
attached to each pivot as `live_results` (shown inline in `--leads`). Use `--no-enrich` /
`--no-whois` to skip; `--whois-reverse` runs reverse-WHOIS live (costs credits).

**urlscan reverses match how urlscan INDEXES each artifact** (not one-size-fits-all) — this is
often the better index than FOFA for freshly-stood-up domains FOFA hasn't crawled:
- **tracker / verification IDs** → page-**content** search (`"<id>"`).
- **favicon** → resource-**hash** search (`hash:<sha256>`) — urlscan stores the favicon's SHA-256,
  not the mmh3 pivot value, so the reverse keys off `artifacts.favicon.sha256`.
- **saas token / third-party host** → resource-**filename** search (`filename:<basename>`). SaaS
  tokens and 3rd-party infra live inside a loaded resource URL, not page text, so urlscan indexes
  them by filename. The tool picks the **distinctive** external script tied to that host/token
  (a build-hash/long-token basename like `project_767893_793428_1783053448.js` — never a generic
  `gtm.js`/`jquery.min.js` or the seed's own asset) and records it as `live_results.urlscan.reversed_resource`.
  *(Inline-script SHA-256s are intentionally NOT reversed — inline scripts aren't fetched resources,
  so urlscan doesn't index them.)* This is what clusters siblings sharing one chat/SaaS account.
By default FOFA reverses search only the most recent ~1-year window; add `--fofa-full` to
run every FOFA reverse (favicon `icon_hash`, tracker/verification bodies, live-IP reverse)
over **all historical data** (`full=true`) — this catches assets that were live in the past
and later scrubbed. Requires a FOFA tier that permits full/historical search; lower tiers
ignore or reject `full=true`.
**Passive DNS (CIRCL-style COF) — `PDNS_USERNAME` + `PDNS_PASSWORD`.** When set, live
enrichment adds a passive-DNS lookup on the base host: historical IPs the domain has used
(folded into the stale-vs-live-IP check) and other domains seen co-hosted on the same IPs —
attached to the domain pivot as `live_results.pdns` and counted toward corroboration. Uses HTTP
Basic auth against `PDNS_URL` (default CIRCL `https://www.circl.lu/pdns/query`); point `PDNS_URL`
at any COF-compatible instance. No creds → the lookup is simply skipped (keyless mode unchanged).

**No keys → keyless mode, unchanged.** Prefer macOS Keychain over a plaintext `.env`;
see `SKILLCUSTOMIZATIONS/WebPivot/PREFERENCES.md` for setup.

**WHOIS tool — `tools/whois_enrich.py`.** Standalone WhoisXML client: current WHOIS,
WHOIS history (every registrant email/name ever seen), and reverse WHOIS by
registrant email/name. `pivot_extract.py` calls it automatically when `WHOISXML_API_KEY`
is set; `graph_build.py` models registrant email/name, registrar, and name servers as
graph hubs so shared registration data clusters domains.
```bash
python3 tools/whois_enrich.py suspect.example                     # current + history
python3 tools/whois_enrich.py --reverse-email owner@x.com         # owner's other domains
```

## 🚨 MANDATORY: Voice Notification (REQUIRED BEFORE ANY ACTION)

Send this BEFORE anything else when this skill is invoked:

```bash
curl -s -X POST http://localhost:8888/notify \
  -H "Content-Type: application/json" \
  -d '{"message": "Running the WORKFLOWNAME workflow in the WebPivot skill to ACTION"}' \
  > /dev/null 2>&1 &
```

Then output: `Running the **WorkflowName** workflow in the **WebPivot** skill to ACTION...`

---

# WebPivot Skill

## Running the tools — paths & working directory (read first)

Two roots; keep them straight or commands fail:

- **Skill scripts** live in this skill folder. Call them by **absolute path** so the current
  directory never matters: `~/.claude/skills/WebPivot/tools/pivot_extract.py`. Inside the
  `intelligence_assist` repo, the repo-relative form `WebPivot/tools/pivot_extract.py` also works.
  *(Bare `tools/pivot_extract.py` only works if you already `cd`'d into `WebPivot/` — don't rely on it.)*
- **Case data + KB tools** live at the `intelligence_assist` **project root** — `cases/`,
  `knowledge/`, and `tools/kb/`. Run those commands from the project root.

Set this up once per case, then every example below resolves:

```bash
cd ~/.claude/skills/WebPivot/../..     # or: cd <intelligence_assist repo root>
ROOT="$PWD"; WP="$ROOT/WebPivot"       # WP = skill scripts, ROOT = case data + KB
CASE="$ROOT/cases/<case-name>"; mkdir -p "$CASE/raw" "$CASE/whois"
set -a; [ -f "$ROOT/.env" ] && source "$ROOT/.env"; set +a   # FOFA / URLSCAN / WHOISXML keys
```

## One-command case pipeline (the stable path)

For a whole domain list, prefer the orchestrator over running each tool by hand — it always
persists to the case and the KB the same way, so a case is reproducible:

```bash
python3 tools/intel.py open <case> domains.txt        # extract → ingest → --shared
python3 tools/intel.py open <case> domains.txt --render --operator "name"   # + case_graph.json + network.html
python3 tools/intel.py status <case>                  # audit what a case has persisted
```

It writes `cases/<case>/raw/<host>.json` (one per host, overwrites on re-run), ingests into
`knowledge/`, and saves the cluster seeds to `cases/<case>/shared.txt`. The per-tool commands
below are for single pages or when you need a step in isolation.

Turn a single web page into a set of **pivot points** — the artifacts in its HTML/DOM that link it to other sites, infrastructure, and actors — and the exact queries to run them. Built for authorized OSINT and cybercrime (scam/phishing/fraud-infra) investigation.

> ⚠️ **Authorization first.** Read `EthicalFramework.md` before targeting live infrastructure. Fetching a hostile site touches it directly — use non-attributable egress (research VPS / VPN) and prefer passive sources (urlscan, Wayback, crt.sh) over direct fetches when the target is adversarial.

## The harness

`tools/pivot_extract.py` is the AI-controllable engine. **Zero required dependencies** — the core runs on the Python 3 stdlib, and the Shodan-style favicon `mmh3` hash is computed with a bundled pure-Python MurmurHash3. Optional accelerators: `requests` (fetch), `playwright` (rendered post-JS DOM via `--render`).

```bash
# Analyze a live page → full artifact + pivot JSON, SAVED to the case (the deliverable, not stdout)
python3 "$WP/tools/pivot_extract.py" https://suspicious-site.example --pretty -o "$CASE/raw/suspicious-site.example.json"

# Just the ranked pivot leads (markdown, high→low confidence) — a quick view
python3 "$WP/tools/pivot_extract.py" https://suspicious-site.example --leads

# Render JS-heavy SPA before extraction (needs: pip install playwright && playwright install chromium)
python3 "$WP/tools/pivot_extract.py" https://spa.example --render --leads

# Offline: analyze saved HTML, or pipe from stdin / another scraper
python3 "$WP/tools/pivot_extract.py" saved_page.html --pretty
curl -s https://x.example | python3 "$WP/tools/pivot_extract.py" -
```

**Crawl the site, not just the landing page — `--crawl`.** By default the tool analyzes a
single page. Add `--crawl [MAXPAGES]` to also follow the site's **navigation / tabs / panels**
(links inside `<nav>`/`<header>`/`<aside>` and menu/tab/panel/sidebar elements), staying on the
seed's **registrable domain**, and merge every page's artifacts into one result. `--crawl-depth`
sets how many link-hops deep to walk. The pages actually fetched are listed in `meta.crawled`.
```bash
# walk up to 15 pages, 2 hops deep, and fold all their pivot artifacts together
python3 "$WP/tools/pivot_extract.py" https://target.example --crawl 15 --crawl-depth 2 --leads
```
Crawl is same-site only (never leaves the registrable domain), bounded by the page cap, and a
per-page fetch error is skipped, not fatal. It works with `--render` too (post-JS DOM per page).

**Change the User-Agent + route through a proxy — stay low-profile while crawling.**
- `--rotate-ua` rotates the User-Agent per request from a built-in browser pool (auto-enabled
  during `--crawl` so a multi-page walk isn't one identical fingerprint). `--ua "<string>"` pins
  one fixed UA and disables rotation.
- `--proxy URL` routes requests through a single proxy (`http://user:pass@host:port`,
  `socks5://host:port`). `--proxy-range SPEC` gives an **optional** pool that rotates per request —
  SPEC is a comma list, a file (one proxy per line), and/or a final-octet IP range like
  `10.0.0.1-10.0.0.9:8080`. Bare `host:port` tokens get an `http://` scheme. **No proxy flag →
  direct connection, unchanged.** Proxy/UA rotation apply to the target-site fetches (seed, crawl,
  favicon); third-party enrichment APIs (crt.sh/urlscan/FOFA/WhoisXML) stay on a direct path.
```bash
python3 "$WP/tools/pivot_extract.py" https://target.example --crawl --rotate-ua \
    --proxy-range 10.0.0.1-10.0.0.9:8080          # rotating UA + rotating proxy pool
python3 "$WP/tools/pivot_extract.py" https://target.example --proxy http://user:pass@host:3128
```

**Redirect & affiliate-link analysis (tracker/shortlinks).** The tool follows redirects, records
the full **redirect chain** (`meta.redirect_chain`) and final destination host, and extracts any
**affiliate / referral / campaign codes** from the URL query strings (`affid`, `ref`, `partner`,
`8c`, `utm_*`, …) — base64 values are auto-decoded (e.g. `affid=MTA2MDEzMQ==` → `1060131`). Each
code becomes a MEDIUM pivot with source-search queries: run the code in PublicWWW / urlscan /
Google to find **where the promoter advertises the link** (social, Telegram, other sites) — usually
the more interesting entity than the broker. Shown inline in `--leads`.

**Registrant-name reverse WHOIS (run historic!).** With `--whois-reverse`, the tool now runs
reverse-WHOIS by registrant **name** (not just email), in **both current and historic** modes, and
attaches the sibling domains to the `whois:registrant_name` pivot's `live_results`. A shared
registrant name can cluster sites that share *no* technical artifact — historic mode has linked
sibling brands that a current-only lookup returned as a single unrelated domain.

**Low-profile fetch + boilerplate filtering.** Requests carry a full browser header profile (not
just User-Agent), so basic Cloudflare/LiteSpeed bot filters don't reset the fetch. Platform-default
artifacts from hosted builders (Wix/Squarespace/Shopify favicon hashes, `facebook.com/wix`-style
handles, `*.wixpress.com` emails and Sentry DSNs) are filtered out so they never create false
same-operator clusters.

**Dead / blocked targets recover passively (not a silent miss).** If the live fetch fails
(NXDOMAIN, firewalled, Cloudflare block), the tool falls back to the most recent **urlscan stored
DOM** then a **Wayback** snapshot, and — even when nothing is recoverable — still records the
intended host with its passive intel (urlscan related domains/IPs) so the target is a persisted
fact, not dropped. `recovered_via` in `meta` records the source. `--no-fallback` disables this.

**Cloudflare-walled targets — detect + escalate (`--solve-cf`).** Many scam/leak sites sit
behind Cloudflare's **managed challenge / Turnstile** (HTTP 403/503 JS interstitial). The tool
now *detects* this (`meta.cloudflare`) instead of reporting a generic error, because the fix is
different from a normal block: **a User-Agent swap does NOT beat a managed challenge** — it needs
a browser that runs the challenge JS. Escalation ladder, weakest→strongest (all already in the
tool): full browser headers (always on) → `--rotate-ua` → **residential/rotating `--proxy` /
`--proxy-range`** (CF blocks datacenter IPs hardest — this is usually the deciding factor) →
`--render` (Playwright executes the JS) → **`--solve-cf`**, which on a detected challenge tries a
**FlareSolverr** instance (`--flaresolverr URL` or `$FLARESOLVERR_URL`; run
`docker run ghcr.io/flaresolverr/flaresolverr`) and then a Playwright render. FlareSolverr drives
a real headless browser and returns the solved HTML + cookies — the proper way to *collect* a
CF-walled page; we never forge a `cf_clearance` token. ⚠️ **Authorized OSINT only**
(`EthicalFramework.md`) — use non-attributable egress. Note the `--solve-cf` render path needs
Playwright in the running interpreter (use the WebPivot `.venv`).

**Not archived yet? Create a snapshot to pivot on (`--archive-missing`).** If the target has no
Wayback snapshot, this submits it to **Save-Page-Now** so a permanent third-party capture exists
for this and future runs, then analyzes the fresh snapshot if nothing else was recoverable
(`archives.wayback.submitted` records the URL). Caveat: SPN's crawler is itself blocked by a hard
CF wall (you'll see a 520), so pair it with `--solve-cf` or a proxy on CF-hardened targets.

**Collect + archive in one pass — `--save-dom` and `--submit`.** Store the raw DOM you
collected, and actively push the URL to the Wayback Machine *and* urlscan.io so there's a
permanent third-party capture and a fresh scan to mine later:
```bash
python3 "$WP/tools/pivot_extract.py" https://target.example --render \
    -o "$CASE/raw/target.example.json" \
    --save-dom "$CASE/dom/target.example.html" \    # store the collected DOM (add --render for post-JS)
    --submit                                         # Wayback Save-Page-Now + urlscan scan (needs URLSCAN_API_KEY)
```
`--save-dom` writes whatever was fetched (use `--render` to store the post-JS DOM — client-side
content like inline form scripts only appears there). `--submit` attaches `archives.wayback.snapshot`
and `archives.urlscan.result` to the JSON. A Wayback read-timeout does **not** mean the capture
failed — Save-Page-Now usually completes server-side.

**Historical analytics (Bellingcat method) — `tools/wayback_ga.py`.** Walks a domain's
*entire Wayback history* and extracts every GA/GTM/AdSense/verification ID ever present —
catching shared IDs that a network later scrubbed. Passive (only touches web.archive.org).
```bash
python3 "$WP/tools/wayback_ga.py" suspect.example --max 15 --timeline
python3 "$WP/tools/wayback_ga.py" -f domains.txt --pretty > "$CASE/history.json"
```

**Live TLS certificate — SANs, co-SAN cross-apex link, cert fingerprint.** When the
seed is fetched live over https (never for archived/offline input), the tool reads the
**served certificate** directly (443 handshake, stdlib `ssl` — no new dependency) and
records its **SAN list, issuer, serial, validity, and SHA-256 fingerprint** as
`artifacts.tls_cert`. A hostname-mismatched / expired / self-signed cert doesn't abort —
it falls back to an unverified read and still yields the fingerprint + DER-scanned SANs
(those failures are themselves signals). Two HIGH-confidence pivots come out of it:
- **`tls_cert:co_san`** — SANs whose **registrable domain differs from the seed's** (one
  cert covering `brand-a.com` *and* `brand-b.net`). This is often a cleaner same-operator
  link than the hosting IP. Same-site subdomains are excluded (they're just this domain's
  own hosts). Emits crt.sh / Censys / urlscan queries per co-apex.
- **`tls_cert:fingerprint_sha256`** — the cert fingerprint → Censys
  (`services.tls.certificates.leaf_data.fingerprint_sha256`), Validin, and crt.sh to find
  **every host serving the exact same certificate**.

**CT / SSL search — two indexes merged, resilient, wildcard-aware.** Live enrichment runs a
certificate-transparency search on the base domain via `ct_search()`, which queries **both crt.sh
and Shodan's keyless CTL mirror** (`ctl.shodan.io/api/v1/domain/<d>` + `/hostnames`) concurrently
and unions the results. crt.sh queries **both** `%.<domain>` (subdomains) **and** the apex
`identity`, and — because crt.sh's `?q=` endpoint frequently returns nginx **502s** — falls back to
the more stable `?identity=` form (`_crtsh_fetch`); when crt.sh is down entirely, Shodan CTL still
returns the subdomains + certs, so a CT lookup no longer silently fails. Shodan's `/hostnames`
endpoint enumerates every logged hostname directly and each cert's `san_dns_names` exposes
**SAN-sibling domains** (a different registrable domain on the same cert = strong same-owner link). The result carries, per logged
certificate, the **issuer + validity window + serial**, and flags any **wildcard cert**
(`*.<domain>`) separately (`wildcards` field) — one wildcard cert can cover many sibling hosts,
so it's a broad-scope-reuse signal worth pivoting. Shown inline in `--leads` (cert timeline +
wildcard note). A per-domain Let's Encrypt cert with only `apex`+`www` SANs (common on
Hostinger/shared auto-SSL) is **not** a shared-operator pivot — read the issuer + SAN scope
before treating a cert as a link.

**Hosting IP is noise, not a pivot — `cdn_ranges` is now wired in.** During live enrichment
each resolved IP is classified against `tools/cdn_ranges.py` (Cloudflare/Fastly/CloudFront/
Google/Bunny ranges). A shared **CDN/cloud edge** IP is flagged as noise and the FOFA
IP-reverse is **skipped** for it (reversing a Cloudflare IP returns thousands of unrelated
tenants); only an **origin-candidate** IP gets reversed. Classification is attached to the
domain pivot's `live_results.dns.ip_classification`. If the range cache is missing the step
degrades gracefully (old behaviour). Refresh ranges with `python3 tools/cdn_ranges.py --update`.

**What it extracts** (see `references/PivotArtifacts.md`): favicon mmh3/md5/sha256, analytics & ad IDs (GA4 `G-`, `GTM-`, AdSense `pub-`, FB Pixel, Yandex, Hotjar, Matomo, Sentry DSN, …), crypto wallets (BTC/ETH/XMR/TRON/LTC), **app-download artifacts** (direct `.apk`/`.aab`/`.ipa`
URLs + the backend host serving them, **desktop "trading terminal" installers** — `.exe`/`.msi`/`.dmg`/`.pkg`/`.appimage`/`.deb` — Android package ids, iOS app ids, smart-app-banner meta,
`intent://` deep links, and the APK **signing-cert SHA-256** + package from `/.well-known/assetlinks.json`). Each detected file emits an `app:apk` / `app:desktop_installer` pivot whose first query is the exact **BinaryPivot** command to statically extract the file's own IOCs (signing cert, embedded C2/backend hosts, wallets) — those become shared indicators that cluster the app with the web infra,
emails, social handles, third-party hosts, inline-script SHA-256, form actions + input names (phishing-kit tell), HTML comments, DOM-skeleton hash (template reuse), tech fingerprints, cookie names, server headers, **SaaS / no-code operator tokens** (GoHighLevel `msgsndr` location ID, backend Google Sheet ID, Make/Zapier/Apps-Script automation webhooks, TrustedForm lead-cert) — attribution-grade for hosted-builder funnels, and only fully present in the `--render` DOM.

**QR codes — the money is often hidden in the QR (`qr:*` pivots).** Scam funnels put the
deposit wallet, a Telegram invite, or a WhatsApp/affiliate link inside a QR image instead of
in text, so it dodges keyword extraction. `pivot_extract.py` handles this two ways:
- **Zero-dep, always on:** when the page renders the QR through a generator *service*
  (`api.qrserver.com/...?data=`, Google Charts `chart.googleapis.com/...&chl=`, QuickChart,
  tec-it, …) the payload sits in the image URL query string — the tool URL-decodes it directly,
  no image processing needed.
- **`--decode-qr` (optional):** fetches candidate `<img>`/inline `data:` images and decodes them
  from pixels via `pyzbar`+Pillow or OpenCV if installed. Without a decoder lib, a detected QR is
  **still surfaced** as a `qr:undecoded_image` lead (never silently dropped). A canvas-drawn QR has
  no `<img>` to read statically — capture it with `--render --screenshot` and decode the screenshot.

Decoded payloads are classified into pivots — `qr:crypto:<coin>` (HIGH, the payout wallet, also
fed to the KB as `qr_wallet_*` so a reused deposit address clusters operators), `qr:telegram`
(HIGH), `qr:whatsapp`, and `qr:url` (a URL in a QR is usually a redirector/affiliate link — the
`qr:url` pivot's first query resolves the redirect to the real destination). **URL redirects are
first-class**: the tool already records the seed's full `meta.redirect_chain` + affiliate/referral
codes, and every URL-bearing pivot keeps the **full, unshortened URL** so you can resolve it.

**What it emits:** a `pivots` array, ranked high→low confidence, each with copy-paste queries for the right engine (with the correct hash algorithm per engine — Shodan/FOFA=mmh3, Censys=MD5, Netlas=SHA-256), plus redirect-chain / affiliate-code pivots for tracker links, live-TLS-cert pivots (`tls_cert:co_san` cross-apex + `tls_cert:fingerprint_sha256`), and reverse-WHOIS (email + name, current + historic) under `--whois-reverse`.

**Case graph — `tools/graph_build.py`.** Merges many `pivot_extract` JSONs into one
normalized, **clustered** graph model: typed nodes (domains + shared artifacts as hub
nodes), evidence-graded edges, plus connected components, **Louvain communities**, and
**betweenness centrality** — all zero-dependency. Feeds the interactive renderer.
```bash
python3 "$WP/tools/graph_build.py" "$CASE"/raw/*.json --operator "name" --operator-links a.com,b.com -o "$CASE/case_graph.json"
# then render (IntelGraph skill): python3 ~/.claude/skills/IntelGraph/scripts/render_network.py "$CASE/case_graph.json" "$CASE/network.html" --title "..."
```
See `Workflows/NetworkGraph.md` for the full extract → build → render pipeline and how to read it.

**Reporting is the deliverable — `Workflows/Reporting.md`.** Every run ends with a readable
**ICD-203 assessment** (`--report` per host; `evidence_report.py` for a whole-campaign rollup),
not raw JSON — plus evidence ledger (`--master`), IOC bundle (`--misp`), evidence screenshot
(`--screenshot`), and CT brand monitoring (`tools/ct_monitor.py`). Flags + examples there.

## Workflow Routing

| Request | Workflow |
|---|---|
| Analyze one page, get all pivots | `Workflows/AnalyzePage.md` |
| I have an artifact (favicon/tracker/wallet), where does it pivot? | `Workflows/PivotFromArtifact.md` |
| Cluster many pages into campaigns / find sibling sites | `Workflows/CampaignClustering.md` |
| Find sites via shared/scrubbed analytics IDs over time (Bellingcat) | `Workflows/HistoricalAnalytics.md` |
| Build a clustered, interactive link graph to tell the story | `Workflows/NetworkGraph.md` |
| **"Output full report for that cluster"** (whole-case ICD-203 rollup, not one host) | `Workflows/Reporting.md` |
| Write per-host report / evidence ledger / IOC bundle, or monitor a brand's new certs | `Workflows/Reporting.md` |
| Analyze a **list/batch** of domains, or fan out agents for scale/verification | `Workflows/ParallelBatch.md` |
| The site pushes an APK / .exe installer — analyze the file for IOCs | **BinaryPivot skill** (`analyze_artifact.py`) |

## Trigger Patterns

- "analyze this site / page / HTML / DOM", "what can I pivot on here"
- "find related / sibling domains", "who else runs this", "same operator?"
- "is this a phishing kit / scam cluster", "cluster these URLs"
- "reverse this GA / GTM / AdSense / pixel ID", "favicon hash for pivoting"
- "trace this scam site's infrastructure / wallet"
- **"output full report for that cluster"** / "cluster report" / "campaign report" → whole-case ICD-203 rollup (`Workflows/Reporting.md`), not a single-domain report
- "this site pushes an APK / .exe download" → detect it here, then hand the file to the **BinaryPivot** skill

## Method (default flow)

1. **Acquire** — fetch (or `--render` for SPAs; or feed saved HTML / a urlscan DOM). Prefer passive capture for hostile targets.
1b. **Always check the web archive** — on *every* target, even one that loads live. Pull the Wayback CDX timeline (`http://web.archive.org/cdx/search/cdx?url=<host>*&output=json&collapse=digest`) and read the status codes: a parked/dead site today may have hosted a live scam funnel in an earlier snapshot (mine that archived DOM for real artifacts), and a `created` WHOIS date inside the capture history means a prior owner. Never conclude "parked / nothing to pivot on" from the live page alone. Then run `wayback_ga.py` for the full analytics history. See `Workflows/AnalyzePage.md` step 2c.
2. **Extract** — run `pivot_extract.py`; get structured artifacts + ranked pivots.
3. **Pivot** — run the emitted queries against the services in `references/PivotServices.md`. Start with HIGH-confidence artifacts (favicon hash, shared tracker IDs) — they most reliably reveal same-operator infrastructure.
4. **Corroborate** — a single shared artifact is a lead, not proof. Confirm a cluster with ≥2 independent artifacts (e.g. same favicon **and** same GA4 ID) before asserting common ownership.
5. **Record** — capture artifact values + the confirming pivots for the graph (**invoke the `IntelGraph` skill** for a relationship diagram).
6. **Correlate (hand off)** — for anything past a single host — a cluster, a "same operator?" question, an attribution call — **invoke the `IntelAnalysis` skill**. It reads the KB you just ingested and runs the judgment layer (triage → cluster → attribute → calibrate confidence → next pivot). A WebPivot run that stops at raw pivots is collection without judgment; the analysis is a separate skill and does not start unless you invoke it.

## Output contract — every run lands in the case (do not skip)

A WebPivot run is only "done" when its result is **persisted into the case**, not when it
prints to the terminal. Stdout is a preview; the case files are the deliverable. For every
page analyzed, produce all three, in order:

1. **Raw pivot JSON** → `cases/<case>/raw/<host>.json` — always use `-o "$CASE/raw/<host>.json"`.
   Never let the JSON exist only in stdout.
2. **Ingested into the knowledge base** → run once the raw files exist, from the project root:
   ```bash
   python3 tools/kb/ingest_webpivot.py --kb knowledge "$CASE"/raw/*.json
   ```
   This is what makes IntelAnalysis able to reason over the run. A run that isn't ingested
   is invisible to correlation — **so once the seeds are ingested, invoke the `IntelAnalysis`
   skill to correlate and attribute** (step 6 of the flow above). Don't end at raw pivots.
3. **Confirmed** with `query.py --shared` so the cluster seeds are recorded, not just implied:
   ```bash
   python3 tools/kb/query.py --kb knowledge --shared --min 2
   ```
4. **Reported** as a human-readable **ICD-203 assessment** — the analyst deliverable, not raw JSON.
   `intel.py open` writes `cases/<case>/assessment.md` for you; otherwise render it explicitly:
   ```bash
   python3 tools/evidence_report.py cases/<case>/raw/*.json --case <case> \
       --analyst <you> -o cases/<case>/assessment.md
   ```
   Present the BLUF + Key Judgments to the user (table / verdict / estimative wording) — do NOT
   end a run by pasting raw pivot JSON. For a single page, `pivot_extract.py … --report`.
   Ledger / IOC-bundle / monitoring options: `Workflows/Reporting.md`.

   Every assessment now **auto-opens with a standardized Domain Summary table** rendered by
   `tools/domain_table.py` (called from `evidence_report.py`): one fixed grid of
   **Domain | Status | Registered | Expires | Registrar | Nameservers | Registrant | IP · ASN |
   Attribution | Analyst context** — so WHOIS + registration dates + attribution are in *every*
   output for the analyst to judge, not buried in JSON. Status/IP come from the pivot capture,
   WHOIS from WhoisXML (cached under `cases/<case>/whois/`), ASN keyless from ip-api, attribution
   from `knowledge/operators.jsonl`. The **Analyst context** column is populated from an optional
   `cases/<case>/notes.json` sidecar (`{"domain": "your judgement note", …}`) — use it to record
   the reasoning the automated columns can't. Render it standalone for an ad-hoc set:
   ```bash
   python3 tools/domain_table.py cases/<case>/raw/*.json --case <case> --kb knowledge
   python3 tools/domain_table.py --domains a.com,b.com --kb knowledge   # live-probe domains w/o raw JSON
   ```

Fixed filename rule: **one file per host**, named exactly `<host>.json` (the bare hostname,
no scheme, no trailing slash) so re-runs overwrite instead of duplicating. Same host analyzed
twice = same file. This is what keeps a case reproducible: re-running the whole `domains.txt`
yields the identical set of `raw/*.json`, and ingest is idempotent, so the KB converges to the
same state every time.

## Notes on artifact reliability (2025-2026)

- **GA `UA-` IDs are historical** (Universal Analytics shut down Jul 2023). Live analytics artifacts are GA4 `G-` and `GTM-`.
- **crt.sh is frequently overloaded** — `ct_search` auto-covers it with the keyless **Shodan CTL** mirror (`ctl.shodan.io`); Certspotter / Censys remain further CT fallbacks.
- **Validin** is the current standout free/low-cost infra-pivot engine (DNS + certs + favicon + response-body hashes in one graph).
- **Chainabuse** (absorbed Bitcoinabuse) is the primary free crypto-scam reporting DB with a real public API.
