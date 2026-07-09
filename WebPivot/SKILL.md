---
name: WebPivot
description: Website content & DOM analysis for OSINT and cybercrime investigation — extracts pivot artifacts (favicon mmh3 hash, tracking/analytics IDs, crypto wallets, emails, third-party infra, template/DOM fingerprints) from a page's HTML/DOM and produces ready-to-run pivot queries (Shodan, PublicWWW, crt.sh, urlscan, Validin, Chainabuse). USE WHEN analyze website, analyze HTML, analyze DOM, page analysis, find pivot, pivoting point, pivot artifact, favicon hash, tracking ID, analytics ID, GA GTM pixel, reverse analytics, cluster sites, campaign clustering, phishing kit, scam site, infrastructure link, source code search, who owns this site, related domains, threat infrastructure.
---

## Customization

**Before executing, check for user customizations at:**
`~/.claude/PAI/USER/SKILLCUSTOMIZATIONS/WebPivot/`

If this directory exists, load and apply any PREFERENCES.md, API keys, or resources found there. These override default behavior. If the directory does not exist, proceed with skill defaults.

**API keys (optional — enables live pivoting).** `pivot_extract.py` reads keys from the
environment first, then from a `chmod 600` `.env` in the customization dir (env wins).
Recognized: `URLSCAN_API_KEY`, `FOFA_KEY` (or `FOFA_API_KEY`), `FOFA_EMAIL`, `WHOISXML_API_KEY`.
With keys set, the tool runs the HIGH-confidence pivots live — FOFA reverses the favicon
`icon_hash` and tracker/verification bodies, authenticated urlscan content-searches the same
values, and WhoisXML adds current + historical registrant data plus reverse-WHOIS pivots — all
attached to each pivot as `live_results` (shown inline in `--leads`). Use `--no-enrich` /
`--no-whois` to skip; `--whois-reverse` runs reverse-WHOIS live (costs credits).
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

**What it extracts** (see `references/PivotArtifacts.md`): favicon mmh3/md5/sha256, analytics & ad IDs (GA4 `G-`, `GTM-`, AdSense `pub-`, FB Pixel, Yandex, Hotjar, Matomo, Sentry DSN, …), crypto wallets (BTC/ETH/XMR/TRON/LTC), emails, social handles, third-party hosts, inline-script SHA-256, form actions + input names (phishing-kit tell), HTML comments, DOM-skeleton hash (template reuse), tech fingerprints, cookie names, server headers, **SaaS / no-code operator tokens** (GoHighLevel `msgsndr` location ID, backend Google Sheet ID, Make/Zapier/Apps-Script automation webhooks, TrustedForm lead-cert) — attribution-grade for hosted-builder funnels, and only fully present in the `--render` DOM.

**What it emits:** a `pivots` array, ranked high→low confidence, each with copy-paste queries for the right engine (with the correct hash algorithm per engine — Shodan/FOFA=mmh3, Censys=MD5, Netlas=SHA-256).

**Case graph — `tools/graph_build.py`.** Merges many `pivot_extract` JSONs into one
normalized, **clustered** graph model: typed nodes (domains + shared artifacts as hub
nodes), evidence-graded edges, plus connected components, **Louvain communities**, and
**betweenness centrality** — all zero-dependency. Feeds the interactive renderer.
```bash
python3 "$WP/tools/graph_build.py" "$CASE"/raw/*.json --operator "name" --operator-links a.com,b.com -o "$CASE/case_graph.json"
# then render (IntelGraph skill): python3 ~/.claude/skills/IntelGraph/scripts/render_network.py "$CASE/case_graph.json" "$CASE/network.html" --title "..."
```
See `Workflows/NetworkGraph.md` for the full extract → build → render pipeline and how to read it.

## Workflow Routing

| Request | Workflow |
|---|---|
| Analyze one page, get all pivots | `Workflows/AnalyzePage.md` |
| I have an artifact (favicon/tracker/wallet), where does it pivot? | `Workflows/PivotFromArtifact.md` |
| Cluster many pages into campaigns / find sibling sites | `Workflows/CampaignClustering.md` |
| Find sites via shared/scrubbed analytics IDs over time (Bellingcat) | `Workflows/HistoricalAnalytics.md` |
| Build a clustered, interactive link graph to tell the story | `Workflows/NetworkGraph.md` |

## Trigger Patterns

- "analyze this site / page / HTML / DOM", "what can I pivot on here"
- "find related / sibling domains", "who else runs this", "same operator?"
- "is this a phishing kit / scam cluster", "cluster these URLs"
- "reverse this GA / GTM / AdSense / pixel ID", "favicon hash for pivoting"
- "trace this scam site's infrastructure / wallet"

## Method (default flow)

1. **Acquire** — fetch (or `--render` for SPAs; or feed saved HTML / a urlscan DOM). Prefer passive capture for hostile targets.
2. **Extract** — run `pivot_extract.py`; get structured artifacts + ranked pivots.
3. **Pivot** — run the emitted queries against the services in `references/PivotServices.md`. Start with HIGH-confidence artifacts (favicon hash, shared tracker IDs) — they most reliably reveal same-operator infrastructure.
4. **Corroborate** — a single shared artifact is a lead, not proof. Confirm a cluster with ≥2 independent artifacts (e.g. same favicon **and** same GA4 ID) before asserting common ownership.
5. **Record** — capture artifact values + the confirming pivots for the graph (hand off to the `IntelGraph` skill for a relationship diagram).

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
   is invisible to correlation.
3. **Confirmed** with `query.py --shared` so the cluster seeds are recorded, not just implied:
   ```bash
   python3 tools/kb/query.py --kb knowledge --shared --min 2
   ```

Fixed filename rule: **one file per host**, named exactly `<host>.json` (the bare hostname,
no scheme, no trailing slash) so re-runs overwrite instead of duplicating. Same host analyzed
twice = same file. This is what keeps a case reproducible: re-running the whole `domains.txt`
yields the identical set of `raw/*.json`, and ingest is idempotent, so the KB converges to the
same state every time.

## Notes on artifact reliability (2025-2026)

- **GA `UA-` IDs are historical** (Universal Analytics shut down Jul 2023). Live analytics artifacts are GA4 `G-` and `GTM-`.
- **crt.sh is frequently overloaded** — keep Certspotter / Censys as CT fallbacks.
- **Validin** is the current standout free/low-cost infra-pivot engine (DNS + certs + favicon + response-body hashes in one graph).
- **Chainabuse** (absorbed Bitcoinabuse) is the primary free crypto-scam reporting DB with a real public API.
