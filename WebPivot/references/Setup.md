# WebPivot — Setup, API keys & the WHOIS tool

Load this when you need to wire up live pivoting (keys), understand what each key unlocks, or run
the standalone WHOIS client. **No keys → keyless mode, everything below is simply skipped.**

## API keys (optional — enables live pivoting)

`pivot_extract.py` reads keys from the environment first, then from the first `chmod 600` `.env` it
finds — the **invocation directory** (normally the repo root you run from), the **repo root**
relative to the script, then a **skill-local** `.env` next to `WebPivot/`. A real environment
variable always wins; among files, the earlier one wins. Recognized: `URLSCAN_API_KEY`, `FOFA_KEY` (or `FOFA_API_KEY`),
`FOFA_EMAIL`, `WHOISXML_API_KEY`, `PDNS_USERNAME` + `PDNS_PASSWORD` (passive DNS, optional
`PDNS_URL`), and — for IPPivot — `IPINFO_TOKEN` (richer IPinfo ASN/abuse) and `SHODAN_KEY` (host
ports/services). Both optional.

`URLSCAN_VISIBILITY` — set to `private` with a **urlscan Pro** key so submitted scans of hostile
infra stay team-only (never in the public feed); defaults to `unlisted`. A Pro key also auto-enables
`search_after` pagination (far more siblings per reverse), the **structure-similarity** pivot
(clusters re-skinned kits), and urlscan **verdict/brand** capture (feeds `risk_signals`).

With keys set, the tool runs the HIGH-confidence pivots live — FOFA reverses the favicon
`icon_hash` and tracker/verification bodies, authenticated urlscan content-searches the same
values, and WhoisXML adds current + historical registrant data plus reverse-WHOIS pivots — all
attached to each pivot as `live_results` (shown inline in `--leads`). Use `--no-enrich` /
`--no-whois` to skip; `--whois-reverse` runs reverse-WHOIS live (costs credits).

**WHOIS runs on every domain, key or not.** Without `WHOISXML_API_KEY` the tool falls back to
**keyless RDAP** (the IETF-standard, free, structured-JSON, ToS-respecting successor to port-43
whois — one polite request per domain via the `rdap.org` bootstrap redirector), with a system
`whois` port-43 fallback for ccTLDs that don't serve RDAP (e.g. `.vn`). RDAP reliably yields
**registrar, registration/expiry/updated dates, name servers, and domain status** even when the
registrant is GDPR-redacted — so the Domain Summary table + report are populated on every host,
not left blank. `meta.enriched_with` records the actual source (`rdap` / `whois43` / `whoisxml`,
or `whoisxml+rdap` when the licensed record was empty and RDAP backfilled it). History + reverse-
WHOIS still require the licensed WhoisXML API (RDAP has no reverse index).

### urlscan reverses match how urlscan INDEXES each artifact

(not one-size-fits-all) — this is often the better index than FOFA for freshly-stood-up domains
FOFA hasn't crawled:
- **tracker / verification IDs** → page-**content** search (`"<id>"`).
- **favicon** → resource-**hash** search (`hash:<sha256>`) — urlscan stores the favicon's SHA-256,
  not the mmh3 pivot value, so the reverse keys off `artifacts.favicon.sha256`.
- **saas token / third-party host** → resource-**filename** search (`filename:<basename>`). SaaS
  tokens and 3rd-party infra live inside a loaded resource URL, not page text, so urlscan indexes
  them by filename. The tool picks the **distinctive** external script tied to that host/token
  (a build-hash/long-token basename like `project_100000000_200000000_300000000.js` — never a generic
  `gtm.js`/`jquery.min.js` or the seed's own asset) and records it as `live_results.urlscan.reversed_resource`.
  *(Inline-script SHA-256s are intentionally NOT reversed — inline scripts aren't fetched resources,
  so urlscan doesn't index them.)* This is what clusters siblings sharing one chat/SaaS account.

By default FOFA reverses search only the most recent ~1-year window; add `--fofa-full` to
run every FOFA reverse (favicon `icon_hash`, tracker/verification bodies, live-IP reverse)
over **all historical data** (`full=true`) — this catches assets that were live in the past
and later scrubbed. Requires a FOFA tier that permits full/historical search; lower tiers
ignore or reject `full=true`.

### Passive DNS (CIRCL-style COF) — `PDNS_USERNAME` + `PDNS_PASSWORD`

When set, live enrichment adds a passive-DNS lookup on the base host: historical IPs the domain has
used (folded into the stale-vs-live-IP check) and other domains seen co-hosted on the same IPs —
attached to the domain pivot as `live_results.pdns` and counted toward corroboration. Uses HTTP
Basic auth against `PDNS_URL` (default CIRCL `https://www.circl.lu/pdns/query`); point `PDNS_URL`
at any COF-compatible instance. No creds → the lookup is simply skipped (keyless mode unchanged).

**No keys → keyless mode, unchanged.** Prefer your OS keychain over a plaintext `.env` —
see `INSTALL.md §5` for the macOS/Linux/Windows recipes.

## WHOIS tool — `tools/whois_enrich.py`

Standalone WHOIS client. **With `WHOISXML_API_KEY`:** current WHOIS, WHOIS history (every
registrant email/name ever seen), and reverse WHOIS by registrant email/name. **Without a key:**
current-registration lookup still works via keyless RDAP (+ port-43 fallback) — history/reverse
need the licensed key. `pivot_extract.py` calls it automatically for **every** domain (keyed or
keyless); `graph_build.py` models registrant email/name, registrar, and name servers as graph
hubs so shared registration data clusters domains.
```bash
python3 WebPivot/tools/whois_enrich.py suspect.example                     # current + history
python3 WebPivot/tools/whois_enrich.py --reverse-email owner@x.com         # owner's other domains
```
