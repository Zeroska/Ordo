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
> in `cases/` and `knowledge/`, which are **git-ignored** and must never be committed. See **§8**.

---

## 1. What's in the box

### The skills (type `/<name>` in Claude Code once registered)

| Skill | Folder | What it does |
|---|---|---|
| **WebPivot** | `WebPivot/` | **Web collector.** Pulls pivot artifacts from a page — favicon hash, tracking/analytics IDs, WHOIS, crypto wallets, TLS cert, SaaS/no-code operator tokens, contact phone, Telegram, footer address — and emits ready-to-run pivot queries (Shodan, PublicWWW, crt.sh, urlscan…). Flags APK / desktop-installer download funnels. |
| **BinaryPivot** | `BinaryPivot/` | **File collector.** Static IOC extraction from the binary a scam site serves (APK / `.exe` / `.dmg` / `.msi`): file hash, APK signing-cert, package, embedded backend/C2 hosts, Firebase tenant, wallets. Emits WebPivot-shaped JSON so the app clusters with the web infra. |
| **IntelAnalysis** | `IntelAnalysis/` | **Analyst.** Correlates, attributes (same-kit / same-operator / same-actor), calibrates confidence, and decides the next pivot. Reasons over the KB — it does not collect. |
| **IntelGraph** | `IntelGraph/` | **Visualizer.** Charts, timelines, Gantt, and clustered interactive network graphs from the case data. |
| **IntelHarness** | `IntelHarness/` | **Case runner (in Claude Code).** Drives the whole Collect → Correlate → Assess pipeline over one or many seeds from your subscription — evidence archiving, versioned assessments, convergence, cluster-level judgment. The conversational front-end to the harness. |

### The harness (two front-ends, one core)

Both run the **same** Collect → Correlate → Assess pipeline over the **same** `cases/` + `knowledge/`
and produce the **same** versioned assessments + evidence — pick by how you want to run it:

| | **IntelHarness** skill | `harness/orchestrator.py` (Agent SDK) |
|---|---|---|
| Auth | your Claude **subscription** | **`ANTHROPIC_API_KEY`** (pay-per-token) |
| Mode | interactive, agent-in-the-loop | headless / scriptable / cron |
| Best for | exploring one case, mid-case judgment | batch, unattended, reproducible pipelines |

### Shared plumbing
`tools/intel.py` (the one-command pipeline) · `tools/kb/` (the attributed knowledge base) ·
`knowledge/` (the store) · `cases/` (per-investigation working dirs). Data stores are git-ignored.

---

## 2. Install once

### Prerequisites
- **Claude Code** (`claude --version`) and **Python 3.8+** (`python3 --version`).
- WebPivot's core needs **nothing** beyond the Python stdlib. Everything below is optional, per feature.

### Register the skills
Claude Code discovers skills from `~/.claude/skills/`. Symlink each folder across (edit once, live
everywhere):

```bash
# from the repo root after you clone/copy it
for s in WebPivot BinaryPivot IntelAnalysis IntelGraph IntelHarness; do
  ln -s "$PWD/$s" ~/.claude/skills/$s
done
```
(Or copy instead: `cp -R WebPivot ~/.claude/skills/WebPivot`, etc.) Restart Claude Code, then verify
each is registered: `/WebPivot`, `/BinaryPivot`, `/IntelAnalysis`, `/IntelGraph`, `/IntelHarness`.

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

# Agent-SDK harness — only if you use harness/orchestrator.py (§3c)
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

## 3. Run a case — pick how you want to drive it

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
*"output the full cluster report"*.

### (c) Unattended / batch — the Agent-SDK driver
Headless, scriptable, schema-forced JSON output. Needs `ANTHROPIC_API_KEY` (not the subscription).
```bash
source harness/.venv/bin/activate            # set up in §2
export ANTHROPIC_API_KEY=...
python3 harness/orchestrator.py CASE-0001 https://site-a.example https://site-b.example
python3 harness/orchestrator.py CASE-0001 --parallel --continue --depth 4 seed1.example seed2.example …
```
Prints a validated `Assessment` JSON and prints its **cost breakdown** to stderr. `--continue` loops
to convergence; `--parallel` scales to many domains by judging **clusters, not domains**. Full knobs
(model cascade, cost levers, evidence, guardrail) in **`harness/README.md`**.

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

## 4. A worked example, start to finish

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

---

## 5. Where things live

```
cases/<case>/
  domains.txt            your seed list                 raw/<host>.json   one pivot-JSON per host/binary
  shared.txt             cluster seeds (fast path)       dom/<host>.html   collected DOM
  SUMMARY.md             current assessment (harness)    screenshots/<host>.png
  assessments/<UTC>_*    immutable snapshots (audit)     evidence/manifest.jsonl + master_pivots.csv
knowledge/               the attributed KB (facts, entities, edges, reports/)
```
Both collectors write the **same** pivot-JSON shape, so one ingester, one correlation pass, and one
cluster report cover websites and their apps together. Everything under `cases/` and `knowledge/` is
git-ignored.

---

## 6. Port to another machine — keep it clean

The included `.gitignore` already excludes secrets and private data: `.env`,
`.claude/settings.local.json`, `MEMORY/`, `cases/`, `knowledge/`, `knowledge_scratch/`, `.DS_Store`,
`__pycache__/`.
- **Via git (recommended):** commit and push; the `.gitignore` handles exclusions; clone on the target.
- **Via copy:** copy **only** the skill folders + `tools/` + `harness/`. Do **not** copy `.env`,
  `.claude/`, `MEMORY/`, or your `cases/` + `knowledge/` data.

On the target, set its **own** keys (env vars or a fresh `chmod 600 ./.env`) — never ship keys in the repo.

---

## 7. Verify the install
```bash
# skills registered? — in Claude Code: /WebPivot /BinaryPivot /IntelAnalysis /IntelGraph /IntelHarness
python3 ~/.claude/skills/WebPivot/tools/pivot_extract.py --help           # tool runs
echo '<html><head><link rel=icon href=/favicon.ico></head></html>' \
  | python3 ~/.claude/skills/WebPivot/tools/pivot_extract.py - --leads    # offline smoke test
python3 ~/.claude/skills/BinaryPivot/tools/analyze_artifact.py --help     # BinaryPivot runs
python3 tools/kb/query.py --kb knowledge --stats                          # KB reachable
python3 tools/eval/run_eval.py                                            # regression suite (all green)
```

---

## 8. OPSEC — this is a shared tool

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

## 9. Where to go deeper

| Doc | What it covers |
|---|---|
| **`PIPELINE.md`** | Step-by-step runbook for collect → correlate → visualize (CLI + in-Claude), a flags cheat-sheet, and a worked example. |
| **`harness/README.md`** | The Agent-SDK driver in depth — model cascade, cost levers, convergence, parallel cluster judgment, evidence, the egress guardrail, auth & billing. |
| **`WebPivot/INSTALL.md`** | Deeper WebPivot setup — API-key management (keychain, Linux/Windows), rendering, proxies. |
| **`IntelHarness/SKILL.md`** | The in-Claude case-runner playbook (phases, when to reject, when to stop). |
| each **`SKILL.md`** + `Workflows/` | Per-skill tradecraft and worked flows. |

> ⚠️ **Authorized investigations only.** See `WebPivot/EthicalFramework.md`. Fetching a hostile site
> touches it directly — prefer passive sources (Wayback / urlscan) or non-attributable egress for
> adversarial targets.
