# intelligence_assist — OSINT skill bundle for Claude Code

Four Claude Code **skills** for authorized OSINT / cybercrime investigation, plus a shared
knowledge base and a one-command case pipeline. Install once, drive from Claude Code or the CLI.

The skills form a pipeline for tracing **scam / fraud infrastructure to the operator behind it** —
you rarely care about one domain, you care about the *cluster* and the identifiers that expose who
runs it:

```
   scam website ──▶ WebPivot ──┐
   pushed APK/  ──▶ BinaryPivot┤──▶ shared KB (tools/kb) ──▶ IntelAnalysis ──▶ IntelGraph
   installer                   │       (attributed facts)      (attribution)     (network graph)
                               └──────────────────────────────────────────────────────▶ cluster report
```

| Skill (registers as) | Folder | Role |
|---|---|---|
| **WebPivot** | `WebPivot/` | **Web collector** — extract pivot artifacts from a page (favicon hash, trackers, WHOIS, crypto, TLS cert, SaaS/no-code operator tokens; detects APK/desktop-installer download funnels) and emit ready-to-run pivot queries. |
| **BinaryPivot** | `BinaryPivot/` | **File collector** — static IOC extraction from the binaries a scam site serves (APK / .exe / .dmg / .msi): file hash, APK signing-cert, package, embedded backend/C2 hosts, Firebase tenant, wallets. Emits WebPivot-shaped JSON so apps cluster with the web infra. |
| **IntelAnalysis** | `IntelAnalysis/` | **Analyst** — correlate, attribute (same-kit / same-operator / same-actor), calibrate confidence, decide the next pivot. Reasons over the KB; does not collect. |
| **IntelGraph** | `IntelGraph/` | **Visualizer** — charts, timelines, Gantt, and clustered interactive network graphs from the case data. |

Both collectors write the **same** pivot-JSON shape into `cases/<case>/raw/`, so one KB ingester,
one correlation pass, and one cluster report cover websites and their apps together.

Shared plumbing: `tools/kb/` (the attributed knowledge base), `tools/intel.py` (the pipeline),
`knowledge/` (the store), `cases/` (per-investigation working dirs).

> 🔒 **Shared tool — keep it clean (OPSEC).** This bundle is meant to be used by more than one
> analyst. The committed skills contain **only generic, synthetic examples** (`brand-a.example`,
> `com.example.app`) — never real case names, target domains, operator names, IPs, wallets, or
> tokens. Your investigation data lives in `cases/` and `knowledge/`, which are **git-ignored** and
> must never be committed. See **§5 OPSEC** before you contribute a change.

---

## 1. Install on a machine

### Prerequisites
- **Claude Code** (`claude --version`) and **Python 3.8+** (`python3 --version`).
- WebPivot's core needs **nothing** beyond the Python stdlib. Everything below is optional, per feature.

### Register the three skills
Claude Code discovers skills from `~/.claude/skills/`. Each skill's folder name matches its registered
name, so symlink them straight across (edit one place, live everywhere):

```bash
# from the repo root after you clone/copy it
ln -s "$PWD/WebPivot"      ~/.claude/skills/WebPivot
ln -s "$PWD/BinaryPivot"   ~/.claude/skills/BinaryPivot
ln -s "$PWD/IntelAnalysis" ~/.claude/skills/IntelAnalysis
ln -s "$PWD/IntelGraph"    ~/.claude/skills/IntelGraph
```

(Or copy instead of symlink: `cp -R WebPivot ~/.claude/skills/WebPivot`, etc.)
Restart Claude Code (or start a new session). Verify: type `/WebPivot`, `/BinaryPivot`, `/IntelAnalysis`, `/IntelGraph`.

### Optional dependencies (install only what you use)
```bash
# WebPivot — faster fetch + rendered post-JS DOM (needed for hosted-builder funnels / --render)
pip install requests playwright && playwright install chromium

# BinaryPivot — zero required deps (stdlib). These OPTIONAL accelerators improve results if present:
#   keytool (any JDK) → APK signing-cert SHA-256 (the strongest same-operator pivot)
#   openssl           → signing-cert fallback;   file/strings → typing + faster string sweep
#   requests          → nicer streaming download (falls back to urllib)

# IntelGraph — data charts + entity graphs
pip install matplotlib graphviz          # graphviz also needs the `dot` binary: brew install graphviz
npm i -g @mermaid-js/mermaid-cli         # only for Mermaid flows/kill-chains
# render_network.py (clustered interactive graphs) is ZERO-dependency — JS libs are vendored.
```

### API keys (optional — unlocks live pivoting)
Read from the **environment first**, then a `chmod 600` `./.env`. Recognized:
`URLSCAN_API_KEY`, `FOFA_KEY` (or `FOFA_API_KEY`), `FOFA_EMAIL`, `WHOISXML_API_KEY`.
Prefer the OS keychain over a plaintext `.env`. Full setup (keychain, Linux/Windows): **`WebPivot/INSTALL.md §5`**.
Without keys everything still works (extraction + query generation + passive Wayback/urlscan).

### Working-directory convention (avoids "command not found")
- **Case data + KB tools** (`cases/`, `knowledge/`, `tools/`) are relative to this **project root** — run those from here.
- **Skill scripts** run by absolute path from anywhere: `~/.claude/skills/WebPivot/tools/pivot_extract.py`.

---

## 2. Apply the skills — quick start

### One command per case (the stable path)
```bash
cd <repo root>
CASE=cases/mycase; mkdir -p "$CASE"
printf 'suspicious-site.example\nother-domain.example\n' > "$CASE/domains.txt"

python3 tools/intel.py open mycase "$CASE/domains.txt"     # extract → ingest → cluster seeds
python3 tools/intel.py open mycase "$CASE/domains.txt" --render --operator "name"  # + graph + network.html
python3 tools/intel.py status mycase                        # audit what the case has persisted
```
Writes `cases/mycase/raw/<host>.json` (one per host, overwrites on re-run), ingests into `knowledge/`,
and saves cluster seeds to `cases/mycase/shared.txt`.

### Single page, with archiving + rendered DOM
Hosted-builder funnels (GoHighLevel, etc.) inject their operator tokens **client-side**, so use `--render`:
```bash
WP=~/.claude/skills/WebPivot
python3 "$WP/tools/pivot_extract.py" https://target.example --render \
    -o cases/mycase/raw/target.example.json \
    --save-dom cases/mycase/dom/target.example.html \   # store the collected DOM
    --submit                                             # archive to Wayback + urlscan
```
> `--render` runs Playwright, so the python invoking `pivot_extract.py` must have `playwright` installed.
> `tools/intel.py open` does **static** bulk extraction; for the render-only SaaS tokens, run the per-page
> `--render` command above (or ask to wire `--render` into the pipeline).

### Analyze the app the scam site pushes
When WebPivot flags an `app:apk` / `app:desktop_installer` pivot, run BinaryPivot on the file — it
lands in the same case and clusters with the web infra via shared signing-cert / backend-host / Firebase indicators:
```bash
BP=~/.claude/skills/BinaryPivot
python3 "$BP/tools/analyze_artifact.py" https://cdn.target.example/app.apk \
    --keep cases/mycase/bin -o cases/mycase/raw/app.target.example.json --case mycase --leads
python3 tools/kb/ingest_webpivot.py --kb knowledge cases/mycase/raw/*.json   # same ingester as WebPivot
```
> Pull artifacts only from infrastructure you're authorized to investigate, from non-attributable
> egress. BinaryPivot is **static** extraction only — it never executes the sample.

### Then reason and visualize (inside Claude Code)
- **IntelAnalysis:** "correlate the case, who is the operator?" → cited assessment saved to `knowledge/reports/<case>/assessment.md`.
- **IntelGraph:** "render the case graph" → interactive `network.html` beside the report.
- **Cluster report:** say *"output full report for that cluster"* → one whole-case ICD-203 rollup over every domain **and** binary in `cases/<case>/raw/` (not a single-domain report).

**Full step-by-step runbook: [`PIPELINE.md`](PIPELINE.md)** — how to invoke the collect → correlate →
visualize pipeline end to end (CLI and in-Claude), with a flags cheat-sheet and a worked example.

Per-skill detail lives in each `SKILL.md` and `Workflows/`. Deeper WebPivot guide: `WebPivot/INSTALL.md`.

---

## 3. Porting to another machine — keep it clean

The included **`.gitignore`** already excludes secrets, machine-local files, and private data:
`.env`, `.claude/settings.local.json`, `MEMORY/`, `cases/`, `knowledge/`, `.DS_Store`, `__pycache__/`.

- **Via git (recommended):** `git init && git add . && git commit` — the `.gitignore` handles exclusions; push and clone on the target.
- **Via copy:** copy **only** the skill folders — `WebPivot/`, `BinaryPivot/`, `IntelAnalysis/`, `IntelGraph/`, `tools/`.
  Do **not** copy `.env` (your API keys), `.claude/`, `MEMORY/`, or your `cases/`+`knowledge/` data.

On the target machine, set its **own** keys (env vars or a fresh `./.env`) — never ship keys in the repo.

---

## 5. OPSEC — this is a shared tool

Multiple analysts use this bundle. The skills are the shared, portable part; **your investigation
data is not**. Keep the two strictly separate so nobody's targets, sources, or identity leak through
a commit.

**What must never enter the committed skills** (`WebPivot/`, `BinaryPivot/`, `IntelAnalysis/`, `IntelGraph/`, `tools/`, `README`, docs):
- Real case names, target domains/hosts, operator or victim names, org names, or team/handle names.
- Real IPs, crypto wallets, emails, API keys, tracker/verification tokens, signing-cert hashes.
- Anything copied from an actual `cases/` or `knowledge/` run.

**Use only generic placeholders in examples:** `brand-a.example`, `target.example`, `com.example.app`,
`1.1.1.1`, `cases/<case>`. The `.example` TLD is reserved and never resolves.

**Your private data stays git-ignored.** `cases/`, `knowledge/`, `MEMORY/`, and `.env` are excluded
by `.gitignore` and must stay that way — do not `git add -f` them. Before you push, sanity-check:
```bash
git ls-files cases/ knowledge/           # must print NOTHING
git diff --cached                        # eyeball staged docs/examples for real IOCs
git grep -nE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b|\b(bc1|0x[0-9a-f]{40})\b' -- WebPivot BinaryPivot IntelGraph IntelAnalysis
```
If you must share a worked example, invent one — don't anonymize a real case (partial redaction leaks
structure). Each analyst brings their **own** API keys (env or a local `chmod 600 ./.env`); keys are
never committed.

---

## 4. Verify the install
```bash
# skills registered? — in Claude Code: /WebPivot  /BinaryPivot  /IntelAnalysis  /IntelGraph
python3 ~/.claude/skills/WebPivot/tools/pivot_extract.py --help          # tool runs
echo '<html><head><link rel=icon href=/favicon.ico></head></html>' \
  | python3 ~/.claude/skills/WebPivot/tools/pivot_extract.py - --leads   # offline smoke test
python3 ~/.claude/skills/BinaryPivot/tools/analyze_artifact.py --help    # BinaryPivot runs
python3 tools/kb/query.py --kb knowledge --stats                          # KB reachable
```

> ⚠️ **Authorized investigations only.** See `WebPivot/EthicalFramework.md`. Fetching a hostile site
> touches it directly — prefer passive sources (Wayback/urlscan) or non-attributable egress for
> adversarial targets.
