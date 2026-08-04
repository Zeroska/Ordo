---
name: WebPivot
description: Website content & DOM analysis for OSINT and cybercrime investigation — extracts pivot artifacts (favicon mmh3 hash, tracking/analytics IDs, crypto wallets, emails, contact phones, Telegram channels/invites, Google Doc/Sheet/Form/Drive IDs, footer postal address, page description, ETag, WHOIS registrant name/org/phone/email/dates, third-party infra, template/DOM fingerprints) from a page's HTML/DOM and produces ready-to-run pivot queries (Shodan, PublicWWW, crt.sh, urlscan, Validin, Chainabuse). USE WHEN analyze website, analyze HTML, analyze DOM, page analysis, find pivot, pivoting point, pivot artifact, favicon hash, tracking ID, analytics ID, GA GTM pixel, reverse analytics, phone number, telegram channel, google sheet, google form, footer address, whois registrant, cluster sites, campaign clustering, phishing kit, scam site, infrastructure link, source code search, who owns this site, related domains, threat infrastructure, impersonation domain, typosquat, typo domain, lookalike domain, spoofed domain, brand impersonation, TLD sweep, keyword hunt, domain permutation, homoglyph, combosquat, hunt lookalikes.
---

> **OPSEC — this skill is portable/shared. Never write case data into it.** No real operator
> names, emails, domains, IPs, wallets, tracking IDs, hashes, or case IDs in this file, its
> workflows, tool code, or test fixtures. Investigation data lives only in the git-ignored
> `cases/` / `knowledge/` / `MEMORY/`. In examples use placeholders (`example.com`,
> `G-XXXXXXXXXX`, `CASE-0001`). See the repo-root `CLAUDE.md` for the full rule.

## API keys — and the keyless disclosure rule (read before reporting any "nothing found")

**Optional API keys enable live pivoting** (`URLSCAN_API_KEY`, `FOFA_KEY`/`FOFA_EMAIL`,
`WHOISXML_API_KEY`, `PDNS_USERNAME`/`PDNS_PASSWORD`, `CENSYS_PAT`, and for IPPivot `IPINFO_TOKEN` / `SHODAN_KEY`) —
read from the environment first, then from the first `chmod 600` `.env` found: the invocation
directory, the repo root, then a skill-local `.env`. **No keys → keyless mode: every tool still
runs, nothing errors.** Full setup, what each key + urlscan-Pro unlocks, passive-DNS, and the
standalone `whois_enrich.py` tool are in **`references/Setup.md`**.

> 🔑 **RULE — say so when the run was keyless or partial.** Keyless is supported, but it is not the
> same investigation. A keyless run **extracts** every artifact and **cannot reverse** most of them:
> with no FOFA/urlscan credential the favicon-hash and tracker reverses never execute, so *"no
> sibling domains"* is a fact about the credentials, **not** about the operator. Before you present
> any negative or thin result:
>
> ```bash
> python3 "$WP/tools/wp_capabilities.py"          # which keys exist · what each absence costs
> ```
>
> 1. **Tell the user** the run's mode (`keyless` / `partial` / `free-only`), **which indexes went
>    unqueried**, and that absence of siblings is therefore not evidence of absence.
> 2. **Carry it into the deliverable** — every run already writes `meta.capability` into its JSON
>    (mode, missing keys, the lost evidence classes, and a ready-to-paste limitation statement);
>    put that statement in the assessment's collection-limitations note and cap confidence
>    accordingly. `--leads` prints it at the top; `pivot_extract` prints the banner on stderr.
> 3. **Say what would fix it** — name the one key that would most change the answer (the tool ranks
>    the absences by impact) rather than reporting a dead end.
>
> The MCP tool is `capability_check`. This applies to `--free-only` runs too: keys may exist but be
> forbidden to spend, which is analytically keyless for the metered indexes.

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

## Capabilities — flags & when (full detail: `references/Capabilities.md`)

`pivot_extract.py` auto-detects its input and already does everything below — this index is the
routing map, so **open `references/Capabilities.md` for the depth on any row** (the tool's behaviour
is unchanged whether or not you read it). **Exhaust both pivot modes.**

| Capability | Flag / trigger | What it gives you |
|---|---|---|
| **Capability check (run it first)** | `tools/wp_capabilities.py` · `capability_check` MCP tool · auto-banner on every run | which keys are configured and, for each absent one, **the evidence class that is unavailable** + the free path that substitutes. Recorded in `meta.capability` and printed at the top of `--leads`. **Read it before reporting any "nothing found"** — see the keyless disclosure rule above |
| **domainPivot** | URL / host / HTML (default) | favicon mmh3, trackers, wallets, emails, WHOIS, TLS, CT, 3rd-party, SaaS tokens |
| **IPPivot** | a **bare IP** as input | passive IP recon: IPinfo ASN, FOFA `ip=`, Shodan, `dig` PTR/MX/NS/TXT; a shared CDN IP → `ip:information`, not a pivot |
| **ImpersonationHunt** | `<domain> --hunt-impersonation` | hunt lookalikes of a seed: typosquat perms + TLD sweep + crt.sh keyword hunt, existence-checked by live DNS → `impersonation:candidate` pivots + a monitoring watchlist. FREE (crt.sh+DNS); `--hunt-fofa`/`--hunt-urlscan` opt-in. Never live-fetches the lookalike infra |
| **SearchPivot** (multi-engine) | `tools/search_pivot.py "<indicator>" [--engines google,yandex,duckduckgo]` · `search_pivot` MCP tool | general-web complement to FOFA/PublicWWW for ANY indicator (domain, slogan, tracking ID, wallet, handle): emits ready-to-open, URL-encoded dork queries across Google/Yandex/DuckDuckGo/Bing/Brave. Does NOT scrape — **fire the queries with Claude Code's WebSearch + WebFetch (the readable duckduckgo html URL)**, extract candidate hosts, feed the NEW ones back into `pivot_extract`. FREE, no keys |
| **Asset layer — JS bundles + source maps** | (auto) · off with `--no-assets` · `--assets-max N` | **the fix for SPA/white-label kits, where the shell HTML is empty and every extractor above finds nothing.** Fetches the page's OWN JS (config/env names + hashed builds first, libraries skipped) and re-runs all extractors over the bundle source → off-apex `api_endpoint` / `websocket_endpoint` (the backend the front was compiled against — every front rotates, the backend doesn't), `build_env:<KEY>` tenant/brand tokens inlined by the bundler, `js_bundle_sha256` (survives a favicon/DOM re-skin). Follows `sourceMappingURL` → `.js.map` for `dev_username` / `dev_project` / `dev_path` — the operator's own build machine. FREE |
| **SPA route table** | (auto, from the bundles already fetched) | the app's OWN router declares every path it serves — Vue/React/Angular route literals + Next.js `sortedPages`/`__NEXT_DATA__`. **Zero extra requests, no path brute-forcing.** → `spa_route_signature` (sha256 over the sorted route set = same compiled app, survives a re-skin), `spa_route:admin` (the operator panel the public funnel never links to) and `spa_route:funnel` (deposit/withdraw/KYC/referral — the scam's mechanics, read without walking the funnel). Routes are **leads only; the tool never fetches them** |
| **Well-known / policy files** | (auto) · off with `--no-well-known` | fixed list of published standards: `robots.txt`, `sitemap.xml`, `ads.txt`, `app-ads.txt`, `security.txt`, `humans.txt`, `apple-app-site-association` → `adstxt_publisher` (an owner-registered AdSense `pub-` account — **Tier A**, same class as a GSC/GA4 token), `apple_team_id` + `ios_bundle_id`, `security_contact`, `robots_disallow` leads. FREE. **A fixed standards list, never a wordlist — this does not brute-force paths** |
| Multi-page crawl | `--crawl [N] --crawl-depth D` | follow same-site nav/tabs, fold every page's artifacts into one result |
| Rotate UA / proxy | `--rotate-ua` · `--ua` · `--proxy` · `--proxy-range` | low-profile fetch; per-request UA + proxy pool (auto during crawl) |
| Redirect & affiliate codes | (auto) | records `meta.redirect_chain` + affid/ref/utm codes (base64-decoded) as pivots |
| Reverse WHOIS (name+email) | `--whois-reverse` | current + historic reverse-WHOIS siblings (name links sites sharing no tech artifact) |
| Passive recovery | (auto) · `--no-fallback` | dead/blocked target → urlscan DOM → Wayback → still records the host + passive intel |
| Cloudflare solve | `--solve-cf` (+ `--flaresolverr`) | detects managed challenge; FlareSolverr/Playwright *collect* it (a UA swap won't) |
| Create archive | `--archive-missing` | Save-Page-Now snapshot when none exists yet |
| Save DOM + archive | `--save-dom` · `--submit` | store raw/post-JS DOM; push to Wayback + urlscan for a permanent capture |
| Historical analytics | `tools/wayback_ga.py` | every GA/GTM/verification ID across full Wayback history (Bellingcat) |
| Live TLS cert | (auto, https) | SANs, `tls_cert:co_san` cross-apex link, `tls_cert:fingerprint_sha256` |
| **Censys Platform** ⚠️ **100 credits/MONTH** | (auto with `CENSYS_PAT`) · off with `--no-censys` · `tools/wp_censys.py` · `censys` MCP tool | the **server-side** view FOFA/urlscan don't give. Every pivot gets a **CenQL query + a click-to-run `platform.censys.io` URL** built **offline, keyless, free**. With a key it also runs the three **lookup** endpoints — the only ones a **FREE Censys plan** can call: `cert <sha256>` → the certificate's own `names` (every hostname on that exact leaf cert — the cert stating its own coverage, not crt.sh's fuzzy overlap), `host <ip>` → ASN/WHOIS org + DNS names + ports + cert fingerprints (folded into IPPivot), `webproperty <host>` → cert/favicon/body-hash/software/threat labels (folded into domain enrichment). **`search` is Starter+** — on Free it degrades to `skipped` **plus the UI link that runs the same query**. **SPEND IT SPARINGLY — see the credit rule below.** Setup: `references/Setup.md` |
| CORS backend probe | (auto, primary page) | foreign-Origin GET+preflight → `cors_allowed_origin` backend/sibling hosts the HTML never names |
| Mail intel | (auto, `dig`) | MX provider / `m365_tenant` / custom `mail_server`, SPF `include`/sender-IP, DMARC contacts |
| CT / SSL search | (auto) | crt.sh + Shodan CTL merged, resilient, wildcard-aware, SAN siblings |
| Hosting-IP classify | (auto) | `cdn_ranges` → CDN edge = noise, only the origin-candidate IP is reversed |
| App-download artifacts | (auto) | APK/`.exe`/installer URLs + signing-cert → first query is the **BinaryPivot** command |
| QR decode | (auto for generator URLs) · `--decode-qr` | wallet / Telegram / WhatsApp / affiliate link hidden in a QR image |
| **Reporting (the deliverable)** | `--report` · `--master` · `--misp` · `--screenshot` | ICD-203 assessment, evidence ledger, IOC bundle → `Workflows/Reporting.md` |
| Case graph | `tools/graph_build.py` | merge JSONs → clustered graph (components / Louvain / centrality) → `Workflows/NetworkGraph.md` |

Chain the modes: a domain's live IP → IPPivot; an IPPivot co-hosted domain → domainPivot. A shared
managed provider / CDN edge / registrar is context, **not** a same-operator pivot. A WebPivot run
ends with a readable ICD-203 assessment — **never** raw JSON.

### ⚠️ Censys credits — 100 a MONTH, no rollover, shared by every case

Censys is the **tightest quota in the toolkit** and the quota is **per account**: overspending in
one case removes Censys from every later case until the 1st. A lookup is **1 credit**, a search is
**5** — and **running the emitted CenQL in the web UI costs the same 5**, so the UI link is not a
free escape hatch. Twenty searches empty the month.

- **Default to the free, keyless path.** Every pivot already carries its CenQL + UI link at zero
  cost. Hand those to the analyst instead of spending a search yourself.
- **Spend on the artifact that decides the question**, not as blanket enrichment. Ranked by value
  per credit: `cert <sha256>` (1 credit → every hostname on that leaf cert) → `host <ip>` →
  `webproperty <host>` → `search` (5 credits, and Starter+ only anyway).
- **Check the balance before a batch:** `python3 "$WP/tools/wp_censys.py" budget` (offline, free) or
  the `censys` MCP tool with `mode='budget'`.
- The guard enforces this: spends are tracked against `MEMORY/api_usage.jsonl`, capped per month
  **and** per run, with a reserve that keeps the cheap 1-credit lookups affordable. Over budget →
  `skipped` with the balance and the UI link, never a mid-case 402. Tune thresholds in
  `references/censys_queries.json` → `credit_budget` (or `CENSYS_MONTHLY_CREDITS` /
  `CENSYS_MAX_CREDITS_PER_RUN` for one run).
- **Report Censys spend** alongside the Anthropic cost — they are separate ledgers.

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
3. **Pivot** — run the emitted queries against the services in `references/PivotServices.md`. Work the **`references/PivotMatrix.md`** checklist: harvest *every* dimension on *every* seed and rank attribution by its same-owner strength tiers (Tier A owner-verified tokens — GSC `verifications`, own GA4/GTM, TLS leaf-fingerprint — before Tier D falsifiable WHOIS). Don't pivot opportunistically off whichever artifact you happened to notice.
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
   python3 WebPivot/tools/evidence_report.py cases/<case>/raw/*.json --case <case> \
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

*(Artifact-reliability notes — UA/GA4, crt.sh overload, Validin, Chainabuse — moved to
`references/Capabilities.md` § Notes on artifact reliability.)*

---

## Tuning the tool without editing code — `references/*.json`

Every denylist, provider registry and permutation table the collector matches against is **data,
not code**. When a run produces a bad link or misses one, the fix is usually a one-line edit to a
JSON file — no Python, no redeploy. Each file opens with a `_comment` explaining what it is for
and which direction is the safe one to be wrong in; every group has its own `_comment`.

| File | Edit it when |
|---|---|
| `references/registrant_noise.json` | a WHOIS privacy proxy / registrar role mailbox got treated as a registrant, or a reverse-WHOIS burned credits on boilerplate |
| `references/third_party_noise.json` | an analytics/CDN endpoint scraped from a JS bundle was reported as the operator's backend, or a managed MX/NS showed up as operator infra |
| `references/generic_labels.json` | a generic subdomain (`api.`, `cdn.`) or a library filename (`jquery.min.js`) created a false same-operator link |
| `references/impersonation.json` | `--hunt-impersonation` is missing the TLDs or affixes a ring actually uses — **this is the per-campaign tuning knob** |
| `references/mail_providers.json` | an MX / SPF include / DMARC `rua` host came back unclassified |
| `references/pivot_tables.json` | a SaaS token's confidence is wrong (a vendor started sharing tenant ids → set it to `null`), or a new affiliate param appeared |
| `references/asn_registry.json` | an ASN's `noise` / `kind` call is wrong. Grows automatically — `wp_ippivot` banks each new ASN it meets |
| `references/censys_queries.json` | Censys renamed a CenQL field, changed a credit price, you upgraded plan, or an artifact kind should (or should not) get a Censys query — `pivot_kind_map` is the single place that decides. **`credit_budget` is the spend guard**: raise `monthly_credits` after buying credits, `max_credits_per_run` for a batch that genuinely needs it |
| `references/api_keys.json` | a new optional key exists, a provider changed what a tier includes, or the keyless banner overstates/understates what an absent key costs — this is what `wp_capabilities.py` prints and what `meta.capability` records |
| `references/cdn_ranges.json` | **never by hand** — generated cache; rerun `python3 tools/cdn_ranges.py --refresh` |

Two rules that keep this safe:

- **Over-filtering is the costlier direction.** A value added to a denylist silently destroys real
  attribution. Adding a *provider* is cheap; adding anything that could be an operator's own asset
  is not. The exact-vs-substring semantics of each group are stated in its `_comment` — read it.
- **A broken file degrades loudly, never silently.** If a JSON is missing or malformed, the module
  falls back to a minimal embedded list and prints a `[refs] WARNING` to stderr. Never ignore that
  warning: a filter running on the stub is a filter that manufactures false clusters.

`python3 tests/test_references.py` (also run by `tools/eval/run_eval.py`) proves every file parses,
is documented, and is actually being loaded rather than silently falling back.
