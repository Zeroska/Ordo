# intelligence_assist — an OSINT investigation kit for Claude Code

A set of Claude Code **skills** plus a shared knowledge base and a case **harness** for authorized
OSINT / cybercrime investigation. The job they do together: trace a **scam / fraud operation from
one website (or the app it pushes) to the operator behind the whole cluster** — because you rarely
care about a single domain, you care about who runs the network and the identifiers that expose them.

```
  scam website ─▶ WebPivot ───┐
  pushed APK / ─▶ BinaryPivot ┤─▶ shared KB (tools/kb) ─▶ IntelAnalysis ─▶ IntelGraph ─▶ cluster
  installer                   │      (attributed facts)      (attribution)   (network graph)   report
                              └──────────────────────────────────────────────────────────────▶
```

You can drive it three ways — a **one-command CLI**, **conversationally inside Claude Code**, or a
**headless batch runner** — all over the same tools and the same case files. Pick per §3.

> 🔒 **Shared tool — keep it clean (OPSEC).** More than one analyst uses this kit. The committed
> skills contain **only synthetic placeholders** (`site-a.example`, `com.example.app`, `CASE-0001`) —
> never real case names, domains, operators, IPs, wallets, or tokens. Your investigation data lives
> in `cases/` and `knowledge/`, which are **git-ignored** and must never be committed. See **§9**.

---

## 1. What's in the box

### The skills (type `/<name>` in Claude Code once registered)

| Skill | Folder | Role | What it does |
|---|---|---|---|
| **WebPivot** | `WebPivot/` | **Web collector** | Pulls pivot artifacts from a page — favicon hash, tracking/analytics IDs, WHOIS, crypto wallets, TLS cert, **CORS-trusted backend/API origins**, full HTTP request/response, SaaS/no-code operator tokens, contact phone, Telegram, footer address — and emits ready-to-run pivot queries (Shodan, PublicWWW, crt.sh, urlscan…). Flags APK / desktop-installer download funnels. |
| **BinaryPivot** | `BinaryPivot/` | **File collector** | Static IOC extraction from the binary a scam site serves (APK / `.exe` / `.dmg` / `.msi`): file hash, APK signing-cert, package, embedded backend/C2 hosts, Firebase tenant, wallets. Emits **WebPivot-shaped JSON** so the app clusters with the web infra. |
| **IntelAnalysis** | `IntelAnalysis/` | **Analyst** | Correlates, attributes (same-kit / same-operator / same-actor), calibrates confidence, and decides the next pivot. Reasons over the KB — it does **not** collect. |
| **IntelGraph** | `IntelGraph/` | **Visualizer** | Charts, timelines, Gantt, and clustered interactive network graphs from the case data. |
| **IntelReport** | `IntelReport/` | **Publisher** | Renders a finished assessment markdown into a polished PDF + editable DOCX (editorial house style, embedded figures, Vietnamese-safe typography). |
| **IntelHarness** | `IntelHarness/` | **Case runner (in Claude Code)** | Drives the whole Collect → Correlate → Assess pipeline over one or many seeds from your subscription — evidence archiving, versioned assessments, convergence, cluster-level judgment. The conversational front-end to the harness. |

### The harness (two front-ends, one core)

Both run the **same** Collect → Correlate → Assess pipeline over the **same** `cases/` + `knowledge/`
and produce the **same** versioned assessments + evidence — pick by how you want to run it:

| | **IntelHarness** skill | `harness/orchestrator.py` (Agent SDK) |
|---|---|---|
| Auth | your Claude **subscription** | **`ANTHROPIC_API_KEY`** (pay-per-token) |
| Mode | interactive, agent-in-the-loop | headless / scriptable / cron |
| Best for | exploring one case, mid-case judgment | batch, unattended, reproducible pipelines |

Both front-ends reach the tools through **one typed surface** — `harness/tools.py` — which the SDK
`orchestrator.py` and the stdio `harness/mcp_server.py` both import. Registering a capability there
once exposes it to the SDK harness **and** to interactive Claude Code (via the repo-root `.mcp.json`
server `intel`). That's why a new tool never has to be a raw `python3 …` line.

### Shared plumbing
`tools/intel.py` (the one-command pipeline) · `tools/kb/` (the attributed knowledge base) ·
`knowledge/` (the store) · `cases/` (per-investigation working dirs). Data stores are git-ignored.

---

## 2. How the skills chain together

The kit is a **pipeline**, not a pile of tools. Each stage hands the next a well-defined artifact,
and the join point is a **shared JSON contract** plus the **knowledge base**. Understand these two
and the whole chain follows.

### The stages and what flows between them

```
 seed (domain / URL / IP / binary)
      │
      ▼
 ┌─ COLLECT ─────────────────────────────────────────────┐
 │  WebPivot  (pivot_extract.py) — a web page → pivot-JSON │
 │  BinaryPivot (analyze_artifact.py) — a file → pivot-JSON│   ← same JSON shape
 └────────────────────────────────────────────────────────┘
      │  cases/<case>/raw/<host>.json     (one file per host or binary)
      ▼
 ┌─ INGEST ──────────────────────────────────────────────┐
 │  tools/kb/ingest_webpivot.py — pivot-JSON → typed facts │
 │  every artifact becomes a NODE; the host it came from   │
 │  becomes an EDGE to it. Shared artifacts = shared nodes.│
 └────────────────────────────────────────────────────────┘
      │  knowledge/ (entities, edges, reports)
      ▼
 ┌─ CORRELATE / ATTRIBUTE ───────────────────────────────┐
 │  IntelAnalysis — reasons over the KB: which hosts share │
 │  which artifacts, is it same-kit / same-operator, how   │
 │  confident, and what to pivot on next.                  │
 └────────────────────────────────────────────────────────┘
      │  a cited, versioned assessment (markdown) + cluster seeds
      ├─────────────▶ IntelGraph  — case_graph.json → interactive network.html / figures
      └─────────────▶ IntelReport — assessment.md → PDF + DOCX deliverable
```

### The contract that makes it chain — one pivot-JSON shape

WebPivot **and** BinaryPivot emit the **same** JSON shape: a `meta` block (host, final URL,
collection time), an `artifacts` block (every identifier found), and a `pivots` array (ranked,
copy-paste queries). Because a downloaded APK's backend host / signing cert land in the *same*
fields a website's TLS cert / third-party host land in, **one ingester, one correlation pass, and
one cluster report cover a website and its app together.** A shared indicator — a favicon hash, a
GA4 ID, a wallet, a signing cert, a CORS-trusted backend — becomes the **same node** in the KB no
matter which collector found it, so the app and the site converge automatically.

### The join point — the KB is a graph of *shared* artifacts

Ingest turns every artifact into a typed node and links the source host to it. The **clustering**
falls out of the graph: two domains that both point at node `favicon:123456789` are a lead; two that
share `favicon:123456789` **and** `ga:G-XXXXXXXXXX` are a cluster. IntelAnalysis reads this graph;
it never re-collects. This is also why **corroboration** is a first-class rule (see §4): a single
shared node is a lead, not proof.

### A collect step can chain into itself

Collection is not one-shot. A WebPivot run emits pivot *queries*; running them surfaces new hosts;
those hosts get collected and ingested — the **analyze → pivot → re-extract** loop. The harness
automates this: `--continue` loops to convergence, and it judges **clusters, not individual
domains**, so the case stops growing when no new shared artifact appears (see §5, convergence).

---

## 3. How it works under the hood

### Why each artifact is a pivot

Collection isn't scraping for its own sake — every extracted artifact is chosen because it **survives
re-skinning**: an operator can change a domain's name, logo, and copy in minutes, but the
infrastructure and account-level identifiers underneath are expensive to rotate. A few of the load-
bearing ones WebPivot pulls:

- **Favicon hash (mmh3/md5/sha256)** — the same icon across unrelated domains = shared kit/operator.
  Emitted per engine with the right algorithm (Shodan/FOFA = mmh3, Censys = md5, Netlas = sha256).
- **Analytics / operator tokens** — GA4 `G-`, `GTM-`, AdSense `pub-`, plus SaaS/no-code account IDs
  (GoHighLevel location, backend Google Sheet, automation webhooks). An account ID ties every
  property the operator ever wired to that account, even scrubbed ones (mine history with
  `wayback_ga.py`).
- **Live TLS certificate** — SANs on a *different registrable domain* than the seed (`tls_cert:co_san`)
  are a cross-brand operator link; the cert fingerprint finds every host serving the exact same cert.
- **CORS policy** *(new)* — an active probe sends a foreign `Origin` and reads the server's
  `Access-Control-Allow-Origin`. A **literal** allowed origin (e.g. `https://api.backend.example`)
  names a **backend/API/staging/sibling host the app trusts that never appears in the page HTML** →
  a `cors_allowed_origin` pivot. A reflect-any + `Allow-Credentials:true` reply is flagged as a
  `cors_misconfig` (a live credential-bearing API to enumerate). The full HTTP request/response is
  kept under `artifacts.http`. The probe routes through the normal fetch path, so `--proxy` is honored.
- **Redirect chain + affiliate codes, crypto wallets (incl. QR-hidden), Telegram, WHOIS registrant** —
  each an independent thread back to the operator.

Every pivot carries a **confidence** (high/medium/low) reflecting how uniquely it identifies an
operator, and the ranked list is what you actually run.

### Live vs passive, and OPSEC-aware collection

WebPivot fetches live by default but **always** also pulls the Wayback CDX timeline — a parked page
today may have been a live scam funnel last year. When a target is hostile or Cloudflare-challenged
it escalates (UA rotation → `--proxy` residential egress → `--render` a real browser → FlareSolverr)
and, failing that, falls back to passive sources (Wayback snapshot, urlscan stored DOM) so a cold
seed never ends on silence. Raw-socket probes (TLS) are suppressed when a proxy is set so they can't
leak your real IP; header-based probes (CORS/HTTP) go through the proxy and are safe.

### Cost accounting — two separate meters

- **Anthropic model cost** (the agent's reasoning) is captured per run by the SDK harness and
  written to `cases/<case>/run_cost.jsonl`. In interactive Claude Code, run `/cost`.
- **Third-party API credits** (FOFA / WhoisXML / urlscan / IPinfo / Shodan) are **not** in the model
  cost. They're logged to `MEMORY/api_usage.jsonl` and summarized per run ("API usage this run").
  When you report what a case cost, state the split — the model bill does not cover the API credits.

---

## 4. Install once

### Prerequisites
- **Claude Code** (`claude --version`) and **Python 3.8+** (`python3 --version`).
- WebPivot's core needs **nothing** beyond the Python stdlib. Everything below is optional, per feature.

### Register the skills
Claude Code discovers skills from `~/.claude/skills/`. Symlink each folder across (edit once, live
everywhere):

```bash
# from the repo root after you clone/copy it
for s in WebPivot BinaryPivot IntelAnalysis IntelGraph IntelReport IntelHarness; do
  ln -s "$PWD/$s" ~/.claude/skills/$s
done
```
(Or copy instead: `cp -R WebPivot ~/.claude/skills/WebPivot`, etc.) Restart Claude Code, then verify
each is registered: `/WebPivot`, `/BinaryPivot`, `/IntelAnalysis`, `/IntelGraph`, `/IntelReport`,
`/IntelHarness`. Confirm the shared tool surface with `/mcp` (server `intel`).

### Optional dependencies (install only what you use)
```bash
# WebPivot — faster fetch + rendered post-JS DOM (needed for hosted-builder funnels / --render)
pip install requests playwright && playwright install chromium

# BinaryPivot — zero required deps (stdlib). Optional accelerators improve results if present:
#   keytool (any JDK) → APK signing-cert SHA-256 (strongest same-operator pivot)
#   openssl → signing-cert fallback ·  file/strings → typing + faster string sweep ·  requests → nicer download

# IntelGraph — charts + entity graphs
pip install matplotlib graphviz          # graphviz also needs the `dot` binary: brew install graphviz
npm i -g @mermaid-js/mermaid-cli         # only for Mermaid flows/kill-chains
# render_network.py (clustered interactive graphs) is ZERO-dependency — JS libs are vendored.

# IntelReport — PDF/DOCX rendering
#   pandoc + a LaTeX engine (xelatex, e.g. via TeX Live / MacTeX) for PDF; pandoc alone for DOCX.

# Agent-SDK harness — only if you use harness/orchestrator.py (§5c)
python3 -m venv harness/.venv && source harness/.venv/bin/activate && pip install -r harness/requirements.txt
```

### API keys (optional — unlocks live pivoting)
Read from the **environment first**, then a `chmod 600 ./.env` at the repo root. Recognized:
`URLSCAN_API_KEY`, `FOFA_KEY` (or `FOFA_API_KEY`), `FOFA_EMAIL`, `WHOISXML_API_KEY`, `PDNS_*`.
Prefer the OS keychain over a plaintext `.env` — full setup (keychain, Linux/Windows) in
**`WebPivot/INSTALL.md`**. **Without keys everything still works** (extraction + query generation +
passive Wayback/urlscan); WHOIS columns just come back blank without `WHOISXML_API_KEY`.

> **Where to run what.** Case data + KB tools (`cases/`, `knowledge/`, `tools/`) are relative to this
> **repo root** — run them from here. Skill scripts run by absolute path from anywhere
> (`~/.claude/skills/WebPivot/tools/pivot_extract.py`).

---

## 5. Run a case — pick how you want to drive it

Three front-ends, same result. Start with **(a)** if you just want output; use **(b)** to think
through a case; use **(c)** to batch many cases unattended.

### (a) One command — the deterministic fast path
No LLM, fully repeatable. Extract every seed → ingest into the KB → save cluster seeds.
```bash
cd <repo root>
CASE=cases/mycase; mkdir -p "$CASE"
printf 'suspicious-site.example\nother-domain.example\n' > "$CASE/domains.txt"

python3 tools/intel.py open mycase "$CASE/domains.txt"                  # extract → ingest → cluster
python3 tools/intel.py open mycase "$CASE/domains.txt" --render --operator "name"   # + graph + network.html
python3 tools/intel.py status mycase                                   # audit what the case persisted
```
Writes `cases/mycase/raw/<host>.json` (one per host, overwrites on re-run), ingests into
`knowledge/`, and saves cluster seeds to `cases/mycase/shared.txt`.

### (b) Conversationally, inside Claude Code — the IntelHarness skill
Best for exploring, mid-case judgment, and letting the agent decide the next pivot. In a session:
> **"Work case mycase from these seeds: site-a.example, site-b.example — collect, correlate, and tell me who the operator is."**

`IntelHarness` runs Collect → Correlate → Assess for you: it calls WebPivot to collect (archiving
evidence), never ends a cold seed on silence (falls back to crt.sh / Wayback / dorks), correlates
with IntelAnalysis, and writes a **versioned, cited assessment** to `cases/mycase/`. Follow-ups that
work: *"converge the case"*, *"cluster these 40 domains"*, *"render the network graph"*,
*"output the full cluster report"*, *"make it a PDF"*.

### (c) Unattended / batch — the Agent-SDK driver
Headless, scriptable, schema-forced JSON output. Needs `ANTHROPIC_API_KEY` (not the subscription).
```bash
source harness/.venv/bin/activate            # set up in §4
export ANTHROPIC_API_KEY=...
python3 harness/orchestrator.py CASE-0001 https://site-a.example https://site-b.example
python3 harness/orchestrator.py CASE-0001 --parallel --continue --depth 4 seed1.example seed2.example …
```
Prints a validated `Assessment` JSON and its **cost breakdown** to stderr. `--continue` loops to
convergence; `--parallel` scales to many domains by judging **clusters, not domains**. Full knobs
(model cascade, cost levers, evidence, guardrail) in **`harness/README.md`**.

**Convergence** — the case is *done* when a collect/pivot round adds no new shared artifact to the
cluster (`--continue` detects `CONVERGED` vs `EXPANDING`). That's the stop condition, not a fixed
depth: a tight cluster converges in a couple of rounds, a sprawling ring keeps expanding until the
shared indicators dry up.

### Sub-tasks you'll reach for in any mode

**A single page, with archiving + rendered DOM.** Hosted-builder funnels (GoHighLevel, etc.) inject
operator tokens **client-side**, so add `--render`:
```bash
WP=~/.claude/skills/WebPivot
python3 "$WP/tools/pivot_extract.py" https://target.example --render \
    -o cases/mycase/raw/target.example.json \
    --save-dom cases/mycase/dom/target.example.html \   # keep the collected DOM
    --submit                                             # archive to Wayback + urlscan
python3 "$WP/tools/pivot_extract.py" page.html --leads    # or just eyeball ranked leads, no file
```
> `--render` runs Playwright, so the python invoking `pivot_extract.py` must have `playwright` installed.

**The app the scam site pushes.** When WebPivot flags an `app:apk` / `app:desktop_installer` pivot,
run BinaryPivot on the file — it lands in the same case and clusters with the web infra via shared
signing-cert / backend-host / Firebase indicators:
```bash
BP=~/.claude/skills/BinaryPivot
python3 "$BP/tools/analyze_artifact.py" https://cdn.target.example/app.apk \
    --keep cases/mycase/bin -o cases/mycase/raw/app.target.example.json --case mycase --leads
python3 tools/kb/ingest_webpivot.py --kb knowledge cases/mycase/raw/*.json   # same ingester as WebPivot
```
> BinaryPivot is **static** extraction only — it never runs the sample. Pull files only from infra
> you're authorized to investigate, from non-attributable egress.

---

## 6. A worked example, start to finish

```bash
cd <repo root>
CASE=cases/acme; mkdir -p "$CASE"
printf 'acme-login.example\nacme-app-download.example\n' > "$CASE/domains.txt"

# 1) collect + ingest + cluster (fast path); add --render for client-side tokens
python3 tools/intel.py open acme "$CASE/domains.txt" --render --operator "Acme operator"

# 2) if a page pushes an APK, analyze it into the same case
python3 ~/.claude/skills/BinaryPivot/tools/analyze_artifact.py https://cdn.acme-app-download.example/app.apk \
    --keep "$CASE/bin" -o "$CASE/raw/app.acme.json" --case acme --leads
python3 tools/kb/ingest_webpivot.py --kb knowledge "$CASE"/raw/*.json
```
Then, **inside Claude Code**:
- *"Correlate the acme case — who is the operator, and how confident are you?"* → cited assessment
  saved to `knowledge/reports/acme/assessment.md`.
- *"Render the acme network graph."* → interactive `network.html` beside the report.
- *"Output the full report for that cluster."* → one whole-case ICD-203 rollup over every domain
  **and** binary in `cases/acme/raw/`.
- *"Make it a PDF and a Word doc."* → IntelReport renders `assessment.md` to PDF + DOCX.

---

## 7. Where things live

```
cases/<case>/
  domains.txt            your seed list                 raw/<host>.json   one pivot-JSON per host/binary
  shared.txt             cluster seeds (fast path)       dom/<host>.html   collected DOM
  SUMMARY.md             current assessment (harness)    screenshots/<host>.png
  assessments/<UTC>_*    immutable snapshots (audit)     evidence/manifest.jsonl + master_pivots.csv
  run_cost.jsonl         per-run Anthropic model cost    report/           rendered PDF/DOCX (IntelReport)
knowledge/               the attributed KB (facts, entities, edges, reports/)
MEMORY/api_usage.jsonl   third-party API credit ledger (FOFA/urlscan/WhoisXML/…)
```
Both collectors write the **same** pivot-JSON shape, so one ingester, one correlation pass, and one
cluster report cover websites and their apps together. Everything under `cases/` and `knowledge/` is
git-ignored.

---

## 8. Port to another machine — keep it clean

The included `.gitignore` already excludes secrets and private data: `.env`,
`.claude/settings.local.json`, `MEMORY/`, `cases/`, `knowledge/`, `knowledge_scratch/`, `.DS_Store`,
`__pycache__/`.
- **Via git (recommended):** commit and push; the `.gitignore` handles exclusions; clone on the target.
- **Via copy:** copy **only** the skill folders + `tools/` + `harness/`. Do **not** copy `.env`,
  `.claude/`, `MEMORY/`, or your `cases/` + `knowledge/` data.

On the target, set its **own** keys (env vars or a fresh `chmod 600 ./.env`) — never ship keys in the repo.

### Adding a new tool or skill — register it once
Per the repo `CLAUDE.md` (RULE 2): wrap a new CLI tool as an `@tool(...)` in `harness/tools.py`. That
single edit exposes it to the SDK `orchestrator.py` **and** the stdio `mcp_server.py` (auto-discovered)
**and** interactive Claude Code (via `.mcp.json` → server `intel`). A new *mode* of an existing tool
needs no new `@tool` — extend that tool's description so the model knows the new flag. Smoke-check:
```bash
WebPivot/.venv/bin/python3 harness/mcp_server.py   # then send a tools/list JSON-RPC; the tool must appear
```

---

## 9. Verify the install
```bash
# skills registered? — in Claude Code: /WebPivot /BinaryPivot /IntelAnalysis /IntelGraph /IntelReport /IntelHarness
python3 ~/.claude/skills/WebPivot/tools/pivot_extract.py --help           # tool runs
echo '<html><head><link rel=icon href=/favicon.ico></head></html>' \
  | python3 ~/.claude/skills/WebPivot/tools/pivot_extract.py - --leads    # offline smoke test
python3 ~/.claude/skills/BinaryPivot/tools/analyze_artifact.py --help     # BinaryPivot runs
python3 tools/kb/query.py --kb knowledge --stats                          # KB reachable
python3 tools/eval/run_eval.py                                            # regression suite (all green)
```

---

## 10. OPSEC — this is a shared tool

Multiple analysts use this kit. The skills are the shared, portable part; **your investigation data
is not.** Keep the two strictly separate so nobody's targets, sources, or identity leak through a commit.

**Never put into the committed skills/tools/docs:** real case names, target domains/hosts, operator or
victim names, org/team/handle names, IPs, wallets, emails, API keys, tracker/verification tokens, or
signing-cert hashes — including as a "worked example."

**Use only generic placeholders:** `site-a.example`, `target.example`, `com.example.app`, `1.1.1.1`,
`G-XXXXXXXXXX`, `CASE-0001`. The `.example` TLD is reserved and never resolves.

**Your private data stays git-ignored** (`cases/`, `knowledge/`, `knowledge_scratch/`, `MEMORY/`,
`.env`) — never `git add -f` them. Before you push:
```bash
git ls-files cases/ knowledge/ knowledge_scratch/     # must print NOTHING
git diff --cached                                     # eyeball staged docs/examples for real IOCs
git grep -nE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(bc1|0x[0-9a-f]{40})\b' -- WebPivot BinaryPivot IntelGraph IntelAnalysis IntelHarness
```
If you need a worked example, invent one — don't anonymize a real case (partial redaction leaks
structure). See the repo-root `CLAUDE.md` for the full rule.

---

## 11. Where to go deeper

| Doc | What it covers |
|---|---|
| **`PIPELINE.md`** | Step-by-step runbook for collect → correlate → visualize (CLI + in-Claude), a flags cheat-sheet, and a worked example. |
| **`harness/README.md`** | The Agent-SDK driver in depth — model cascade, cost levers, convergence, parallel cluster judgment, evidence, the egress guardrail, auth & billing. |
| **`WebPivot/INSTALL.md`** | Deeper WebPivot setup — API-key management (keychain, Linux/Windows), rendering, proxies. |
| **`WebPivot/SKILL.md`** + `references/` | The full pivot-artifact catalogue (incl. TLS, CORS/HTTP), per-engine query syntax, and reliability notes. |
| **`IntelHarness/SKILL.md`** | The in-Claude case-runner playbook (phases, when to reject, when to stop). |
| each **`SKILL.md`** + `Workflows/` | Per-skill tradecraft and worked flows. |

> ⚠️ **Authorized investigations only.** See `WebPivot/EthicalFramework.md`. Fetching a hostile site
> touches it directly — prefer passive sources (Wayback / urlscan) or non-attributable egress for
> adversarial targets.
