# Workflow: AnalyzePage

Extract every pivot artifact from one page and produce ranked leads.

## Voice
`curl -s -X POST http://localhost:8888/notify -H "Content-Type: application/json" -d '{"message": "Running the AnalyzePage workflow in the WebPivot skill to extract pivot artifacts"}' >/dev/null 2>&1 &`

## Steps

1. **Authorization check.** Confirm the target is in scope (`../EthicalFramework.md`). For adversarial infra, prefer passive acquisition (step 2b) and non-attributable egress.

   Paths: `WP="$ROOT/WebPivot"` (skill scripts), `CASE="$ROOT/cases/<case>"` — see SKILL.md
   "Running the tools". Bare `tools/pivot_extract.py` fails from the project root.

2. **Acquire the page.** Always write the JSON into the case with `-o` (see Output contract).
   - Live static: `python3 "$WP/tools/pivot_extract.py" <URL> --pretty -o "$CASE/raw/<host>.json"`
   - JS-heavy SPA (renders post-JS DOM): add `--render` (needs `playwright install chromium`).
   - **Whole site, not just the landing page**: add `--crawl [MAXPAGES] [--crawl-depth D]` to also
     follow the site's nav/tabs/panels (same registrable domain) and merge every page's artifacts —
     `meta.crawled` lists the pages fetched. IDs that only appear on an inner page (contact form,
     about, checkout) get caught this way.
   - **Stay low-profile**: `--rotate-ua` rotates the User-Agent per request (auto-on with `--crawl`);
     `--proxy URL` or `--proxy-range SPEC` (comma list / file / `10.0.0.1-10.0.0.9:8080` IP range)
     routes the target-site fetches through a rotating proxy pool. No proxy flag → direct, unchanged.
   - **2b Passive** (hostile target): pull the DOM from urlscan.io or a Wayback snapshot, save to `page.html`, then `python3 "$WP/tools/pivot_extract.py" page.html --pretty -o "$CASE/raw/<host>.json"`.

3. **Read the artifacts.** The JSON `artifacts` block covers favicon hashes, trackers, crypto, emails, socials, third-party hosts, inline-script hashes, forms, comments, DOM-skeleton hash, tech fingerprint, cookies, headers.

4. **Get ranked leads.** `python3 "$WP/tools/pivot_extract.py" <URL> --leads` prints pivot suggestions high→low confidence with copy-paste queries.

5. **Run the top pivots.** Execute HIGH-confidence queries first (favicon hash, shared GA4/GTM/AdSense IDs) against `../references/PivotServices.md`.

5b. **Collect + archive.** Add `--save-dom "$CASE/dom/<host>.html"` to keep the raw DOM
   (use `--render` for the post-JS DOM — inline form scripts, injected IDs, and embedded
   Google-Sheet/webhook config only appear there), and `--submit` to push the URL to Wayback
   Save-Page-Now + a fresh urlscan scan for later mining.

6. **Persist, corroborate & report.** Ingest so the run is in the KB
   (`python3 tools/kb/ingest_webpivot.py --kb knowledge "$CASE"/raw/*.json`, from the project root).
   Require ≥2 overlapping artifacts before claiming a cluster. Summarize: artifacts found →
   pivots run → confirmed related hosts → confidence. Offer to render a relationship graph via
   the `IntelGraph` skill.

## Example
```bash
python3 "$WP/tools/pivot_extract.py" https://login-secure-verify.example --leads
# → [HIGH] favicon_hash = -1256781000
#     Shodan: http.favicon.hash:-1256781000
#     Censys: services.http.response.favicons.md5_hash=...
#   [HIGH] tracker:google_analytics_ga4 = G-ABC123XYZ
#     PublicWWW: "G-ABC123XYZ"
```
