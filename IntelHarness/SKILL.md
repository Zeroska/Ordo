---
name: IntelHarness
description: Run a whole OSINT case end-to-end — the Collect → Correlate → Assess pipeline over one or many seed domains, driven by Claude Code (no Agent SDK) using WebPivot + IntelAnalysis + the KB tools. Handles evidence archiving, versioned assessments, convergence, cluster-level judgment at scale, cross-case provenance, and false-positive control. USE WHEN work a case, run the harness, investigate these domains end to end, build the case from seeds, collect correlate assess, full investigation pipeline, cluster these domains, converge the case, batch of scam domains, attribute this cluster, produce an assessment with evidence, scale to many domains, run a case without the SDK.
---

> **OPSEC — this skill is portable/shared. Never write case data into it.** No real operator
> names, emails, domains, IPs, wallets, tracking IDs, hashes, or case IDs in this file, its
> workflows, tool code, or fixtures. Investigation data lives only in the git-ignored
> `cases/` / `knowledge/` / `MEMORY/`. In examples use placeholders (`example.com`,
> `site-a.example`, `G-XXXXXXXXXX`, `CASE-0001`). See the repo-root `CLAUDE.md` for the full rule.

# IntelHarness — run a case end-to-end, inside Claude Code

This is the **Claude-Code-native front-end** to the OSINT harness: *you* (the agent) are the
orchestrator, following the phases below and calling the repo's CLIs directly. Same tools, same
KB, same evidence discipline as the Agent-SDK driver — but on the subscription, interactive, no
`claude_agent_sdk` and no `ANTHROPIC_API_KEY` needed.

**Two front-ends over one core — pick per situation:**

| | `harness/orchestrator.py` (Agent SDK) | **this skill** (Claude Code) |
|---|---|---|
| Auth | `ANTHROPIC_API_KEY`, pay-per-token | your Claude subscription |
| Run mode | headless / scriptable / cron | interactive, agent-in-the-loop |
| Output | schema-forced `Assessment` JSON | you write the assessment; `case_store.py` versions it |
| Best for | batch, unattended, reproducible pipelines | exploratory work, one case at a time, mid-case judgement |

Both read/write the same git-ignored `cases/` + `knowledge/` and produce the **same** versioned
snapshots + evidence manifest, so a case worked either way is continuous.

The tradecraft for each phase lives in the sibling skills — **read/apply `WebPivot` for collection
and `IntelAnalysis` for judgement.** This skill is the *orchestration*: what to run, in what order,
what to reject, and when to stop.

**Prefer the typed MCP tools when connected.** If the `intel` MCP server (repo-root `.mcp.json`,
`harness/mcp_server.py`) is available, the phase tools are exposed as native, typed tools —
`pivot_extract`, `fallback_probe`, `kb_ingest`, `kb_cluster`, `kb_entity`, `cert_overlap`,
`reference_check`, `which_cases`, `domain_verdict`, … — backed by the *same* CLIs. Use them instead
of shelling out; they're typed and permission-gated, and you skip the bash quoting. The `python3 …`
command forms shown in the phases below are the **fallback** for when the server isn't connected
(check `/mcp`), and remain the reference for exact flags.

---

## Setup (every run)

- **Case id**: `CASE-YYYY-NN` or a short slug (a CLI arg — never hardcode one).
- **KB dir**: defaults to `knowledge/`. For a throwaway/smoke run, `export HARNESS_KB=knowledge_scratch`
  and pass `--kb "$HARNESS_KB"` to the KB tools.
- Run all commands from the **repo root**.
- **Before collecting, check what's already known** (don't re-investigate):
  ```bash
  python3 tools/case_index.py <seed>                 # which case(s) is this domain/indicator already in?
  python3 tools/kb/operator_registry.py find <seed>  # already attributed to a known operator?
  ```
  If a seed is already attributed, show that verdict and skip re-collection unless the user wants a refresh.

---

## Phase 1 — COLLECT  (apply `WebPivot`; cheap, mechanical)

For **each NEW seed**, collect with full enrichment + evidence capture:
```bash
python3 WebPivot/tools/pivot_extract.py <url> --pretty \
    -o cases/<CASE>/raw/<host>.json --save-dom cases/<CASE>/dom/<host>.html \
    --archive-missing --master --case <CASE>
```
- `--archive-missing` submits a Wayback snapshot so the copy survives takedown; `--master` appends
  every pivot to the case evidence ledger. Add `--render --screenshot cases/<CASE>/screenshots/<host>.png`
  for visual evidence (needs the WebPivot `.venv` / Playwright).
- **HOSTILE target** → never a bare live fetch: use `--proxy-range <cidr>` or feed an
  already-saved/archived HTML file. (See `WebPivot/EthicalFramework.md`.)
- **Cloudflare** interstitial → retry with `--render` (browser) or `--solve-cf --flaresolverr <url>`.

**EMPTY-RESULT RULE — never end a seed on silence.** If `pivot_extract` returns zero/near-zero
pivots or a parked / empty-favicon / NXDOMAIN page (WHOIS+FOFA+urlscan all cold), run the keyless
last-resort probe and report its **VERDICT**:
```bash
python3 tools/fallback_probe.py <host> --kb "${HARNESS_KB:-knowledge}"
```
It sweeps crt.sh certs (SAN-sibling domains = strongest same-owner link), the full Wayback timeline
(parked-today was often live last year), archive.today, ready-to-run search dorks, and the local KB
→ `PIVOTABLE` (leads) or `NO-PIVOT-YET` (cold + next steps).

Then **ingest** so collection becomes correlatable, and (re)build the evidence manifest:
```bash
python3 tools/kb/ingest_webpivot.py --kb "${HARNESS_KB:-knowledge}" cases/<CASE>/raw/*.json
python3 tools/case_store.py manifest <CASE>
```

---

## Phase 2 — CORRELATE  (apply `IntelAnalysis`; the judgement)

Reason over the ingested KB. For each seed, its focused subgraph is the primary evidence:
```bash
python3 tools/kb/query.py --kb "${HARNESS_KB:-knowledge}" --cluster <host> --strong   # same-operator peers
python3 tools/kb/query.py --kb "${HARNESS_KB:-knowledge}" --entity  <host>            # facts + edges + provenance
python3 tools/kb/risk_signals.py --case <CASE>                                        # NRD / BPH / money-trail
```
Corroborate and control false positives with:
```bash
python3 tools/cert_overlap.py <domain-a> <domain-b> [...]     # shared TLS cert / SAN cross-cover = near-decisive
python3 tools/case_index.py <domain-or-indicator>            # which prior case(s) — cross-case links
python3 tools/kb/reference.py --kb "${HARNESS_KB:-knowledge}" check <hash-or-keyword>  # benign / signal / unknown
```

### Noise discipline — the golden rules (this is what separates real clusters from false ones)
1. **`--strong` for clustering.** It drops boilerplate edges (shared WP-Rocket CSS / HTML comments /
   DOM skeleton) and indicators shared by > 8 domains (`--max-prevalence`), so only **owner-set**
   indicators cluster (favicon / GA / GTM / verification / wallet / brand-theme / socials).
2. **`reference_check` before trusting a shared hash.** BENIGN = a common logo/CDN/CSS artifact →
   discard it. If you confirm a new benign or a distinctive signal, remember it:
   `reference.py add --value <ind> --verdict benign|signal --label "..." [--case <CASE>]`.
3. **Managed DNS / parking favicons / registrar-privacy emails are NOT operator links** (see
   `tools/kb/noise_filters.py`). A shared Cloudflare nameserver clusters nothing.
4. **A cert whose SAN list covers two otherwise-unrelated domains is near-decisive same-owner.**
5. **State the competing explanation you ruled out** — that's what makes an attribution defensible.

### Chain further: high-value HTML string / unique subdomain → FOFA body & CT
When correlation surfaces a **distinctive HTML string** (a slogan, brand phrase, unique class or
template literal — the kind of thing `IntelAnalysis` calls out as high-value) or a **unique
subdomain label**, feed it straight back into collection as a new search — this is how a case grows
past its seed set:
```bash
# HTML-string pivot — FOFA body-searches the served HTML for every host running the same page
python3 WebPivot/tools/pivot_extract.py <url> --fofa-keyword "<distinctive phrase>" \
    --fofa-keyword "<second phrase>" --pretty -o cases/<CASE>/raw/<host>.json
# unique subdomain label (e.g. svc-a.site-a.example) is auto-emitted as a `subdomain` pivot with
#   FOFA host="<label>." · crt.sh <label>.% · Shodan ssl.cert.subject.CN/hostname · Censys names:<label>.*
```
`pivot_extract` already auto-emits a FOFA `body=` query for every HTML-string artifact and runs the
keyword/subdomain reverse **live** when a `FOFA_KEY` is set. Collect the new hosts (Phase 1),
re-ingest, and re-correlate — repeat until convergence. Prefer FOFA `body=` / CT over PublicWWW on
**freshly-registered** domains PublicWWW hasn't indexed yet.

---

## Phase 3 — ASSESS  (write it, then version it)

Write the assessment as JSON to a temp file, following the `IntelAnalysis` estimative discipline and
this schema:
```json
{
  "bluf": "one sentence with an estimative word (assessed / likely / possible)",
  "cluster": [{"domain": "site-a.example", "shared_artifacts": ["favicon:123456789", "ga:G-XXXXXXXXXX"]}],
  "attribution_level": "same-kit | same-operator | same-actor | inconclusive",
  "confidence": "low | moderate | high",
  "evidence": ["cited artifacts justifying the attribution level"],
  "gaps": ["what could not be verified + the competing explanation ruled out"],
  "next_pivots": ["prioritised open leads, highest yield/cost first"]
}
```
Then snapshot it (immutable history + living `SUMMARY.md` + `CHANGELOG.md`), with the standard table:
```bash
python3 tools/domain_table.py cases/<CASE>/raw/*.json --case <CASE> --kb "${HARNESS_KB:-knowledge}" > /tmp/<CASE>_table.md
python3 tools/case_store.py snapshot <CASE> --assessment /tmp/<CASE>_assessment.json --table /tmp/<CASE>_table.md
```
Every run appends `assessments/<UTC>_r<n>.{md,json}` — **nothing is overwritten**; `SUMMARY.md` is the
current head. Show the BLUF + attribution/confidence + the evidence trail (full, unshortened URLs).

---

## Iterate to convergence (optional, for expanding cases)

Each round is a cheap, LLM-free expansion; only assess once the case stops growing:
```bash
python3 tools/kb/convergence.py snapshot <CASE>                 # record this round's hosts+indicators
python3 tools/kb/convergence.py status  <CASE> --stale 2        # CONVERGED (stop) or EXPANDING (keep going)
```
To find the **next frontier**, take the `--strong` cluster peers of the collected domains that are
**not yet collected**, collect those (Phase 1), re-ingest, snapshot convergence. Repeat until
`status` says **CONVERGED** (last 2 rounds added nothing) or the shared budget is spent. Only then
write the assessment. (This mirrors `orchestrator.py --continue`.)

---

## Scale — many domains (10s–100s)

Don't loop one giant reasoning pass over 100 domains. **Partition first, judge per cluster:**
```bash
DOMS=$(for f in cases/<CASE>/raw/*.json; do basename "$f" .json; done | paste -sd, -)
python3 tools/kb/query.py --kb "${HARNESS_KB:-knowledge}" --components --domains "$DOMS"
```
Each `COMPONENT` line is one same-operator cluster (strong edges only). Then, per cluster:
- if **every** member is already attributed (`operator_registry.py find`) → reuse the prior verdict, **skip judgement**;
- else run Phase 2 + Phase 3 for **just that cluster's domains**, and snapshot it.

Collection scales by fanning `pivot_extract` across seeds (independent processes / background Bash);
each cluster is a small, focused judgement, so cost tracks cluster count, not domain count. (This
mirrors `orchestrator.py --parallel`.)

---

## Close the loop — LEARN (do this when an attribution is confirmed)

```bash
python3 tools/kb/operator_registry.py add "<Operator label>" --domains <d1,d2,...> --case <CASE> \
    --confidence assessed --basis "the artifacts that tied them (cited)"
python3 tools/kb/reference.py --kb "${HARNESS_KB:-knowledge}" ingest-case <CASE>   # bank the case's unique hashes as a watchlist
```
Attributing the cluster + banking its distinctive fingerprints is what makes the NEXT case faster —
future collections that hit a `signal` fingerprint or an attributed domain resolve instantly.

---

## Cost per run

- **Interactive (this skill / Claude Code):** the model can't read its own spend — run **`/cost`**
  to see the Anthropic model cost of the session/run.
- **Headless (`harness/orchestrator.py`, Agent SDK):** each run prints per-phase + total
  `total_cost_usd` and appends a line to **`cases/<CASE>/run_cost.jsonl`** — sum that file for the
  case's model cost over time.
- **API credits (FOFA / urlscan / WhoisXML / IPinfo / Shodan)** are separate from `total_cost_usd`
  and now **logged locally** every collection: each licensed call appends to
  `MEMORY/api_usage.jsonl` (git-ignored, tagged with case + skill), and every `pivot_extract` run
  prints an "API usage this run" summary. See totals with:
  ```bash
  python3 WebPivot/tools/api_usage.py report [--case <CASE>] [--since YYYY-MM-DD] [--last 20]
  ```
  or the `api_usage` MCP tool. Credits are best-effort **unit counts** (1 = one query/request;
  urlscan_search = 1 per page), plus the provider's reported quota-remaining where exposed (urlscan
  headers) — a usage log, not an invoice. `pivot_extract.py` makes **zero** Anthropic calls.

## Phase ↔ tool map (parity with `harness/orchestrator.py`)

| Phase / step | This skill runs | SDK-harness counterpart |
|---|---|---|
| prior-knowledge | `case_index.py`, `operator_registry.py find` | `_prior_knowledge`, `domain_verdict` |
| collect | `pivot_extract.py --archive-missing --master` | `collect_one` / `collect_many` |
| empty-seed | `fallback_probe.py` | `fallback_probe` tool |
| ingest | `ingest_webpivot.py` | `ingest` |
| correlate | `query.py --cluster --strong`/`--entity`, `cert_overlap.py`, `reference.py check`, `risk_signals.py` | Correlate phase tools |
| cross-case | `case_index.py` | `which_cases` |
| assess + version | write JSON → `case_store.py snapshot` | schema-forced `Assessment` + `_persist_assessment` |
| evidence manifest | `case_store.py manifest` | `_append_manifest` |
| converge | `convergence.py snapshot/status` | `--continue` loop |
| scale | `query.py --components` + per-cluster judge | `--parallel` / `run_case_parallel` |
| learn | `operator_registry.py add`, `reference.py ingest-case` | close-out step |
