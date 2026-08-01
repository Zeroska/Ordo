# intelligence_assist — contributor rules

This repo ships **portable OSINT skills** (`WebPivot`, `IntelAnalysis`, `IntelGraph`,
`BinaryPivot`) plus shared tooling under `tools/`. The skills are imported onto other
machines and used by other people. Treat everything tracked here as **public-facing**.

## RULE 1 — Never put case / investigation data into a skill (CRITICAL)

Skills are **code + tradecraft only**. An investigation's data NEVER goes into a
`SKILL.md`, a workflow `.md`, a tool docstring/comment, a test fixture, or any tracked
file. This includes — in prose, comments, examples, fixtures, or hardcoded logic:

- **Real people / operators** — names, aliases, emails, phone / Zalo / Telegram / Messenger handles.
- **Real target infrastructure** — case domains, IPs, wallets, ASNs, hostnames.
- **Real owner artifacts** — actual GA4/GTM/UA IDs, ahrefs/GSC tokens, favicon/DOM hashes tied to a case.
- **Case identifiers** — `CASE-YYYY-NN` IDs, case-folder names, per-case hardcoded paths.
- **Operator PII / attribution** of any kind, even as a "worked example".

Investigation data lives ONLY in the git-ignored stores: `cases/`, `knowledge/`,
`MEMORY/`, `.env`, and the operator registry. It is never committed and never referenced
by identifier inside a skill.

## RULE 2 — Register every new tool/skill with the MCP (so Claude Code can use it)

When you add a **tool** or a **skill**, publish it through the one typed surface both front-ends
share (`harness/tools.py` → the SDK `orchestrator.py` **and** the stdio `harness/mcp_server.py`,
which auto-discovers every `@tool`). Do NOT leave a new capability reachable only as a raw
`python3 …` bash line.

- **New CLI tool** (`WebPivot/tools/*.py`, `tools/*.py`): wrap it as an `@tool(name, description,
  {params})` in `harness/tools.py`. `mcp_server.py` discovers it automatically (no second edit) and
  it appears to Claude Code via the repo-root `.mcp.json` server `intel`. Keep the description one
  tight paragraph — it is context cost paid on every SDK phase (see below).
- **New mode of an existing tool** (e.g. IPPivot is just `pivot_extract.py` with a bare-IP source):
  no new `@tool` — extend the existing tool's description so the model knows the new input/flag.
- **New skill** (`WebPivot`, `IntelAnalysis`, …): add its `SKILL.md`, symlink it into
  `~/.claude/skills/`, and if it exposes a scriptable step, surface that step as an `@tool` too.
- **Smoke-check registration:** `WebPivot/.venv/bin/python3 harness/mcp_server.py` then send a
  `tools/list` JSON-RPC — the new tool must be listed. In Claude Code, confirm with `/mcp`.

## Cost visibility

- **Anthropic model cost** (the agent's reasoning): the **SDK harness** captures the SDK's own
  `total_cost_usd` per phase and persists a per-run line to `cases/<case>/run_cost.jsonl`
  (`orchestrator._report_cost`) — that is the ledger to sum for "what did this case cost". In
  **interactive Claude Code** the model can't read its own `total_cost_usd`; run `/cost` to see it.
- **Third-party API credits are NOT in `total_cost_usd`.** `pivot_extract.py` and friends spend
  FOFA / WhoisXML / urlscan / IPinfo / Shodan credits (and make **zero** Anthropic calls
  themselves). They are logged to `MEMORY/api_usage.jsonl` by `api_usage.record(...)` and reported
  via `WebPivot/tools/api_usage.py report` (or the `api_usage` MCP tool); every run also prints an
  "API usage this run" summary. State the split when reporting cost; don't imply `total_cost_usd`
  covers the API credits. **Any NEW licensed/metered API call MUST call `api_usage.record(...)`.**

## When a skill genuinely needs an example

Use obvious, non-real placeholders — never a value lifted from a live case:

| Kind | Use |
|---|---|
| domain | `example.com`, `site-a.example`, `site-b.example` |
| email | `registrant@example.com`, `operator@example.com` |
| person / operator | `"Registrant Name"`, `Operator A`, `operator-a` |
| GA4 / GTM / UA | `G-XXXXXXXXXX`, `GTM-XXXXXXX`, `UA-100000001` |
| case ID | `CASE-0001` (or a CLI arg — never hardcode a real one) |
| favicon / hash | a clearly-synthetic value (e.g. `123456789`) |

Generic public constants are fine (registrar/privacy-proxy addresses, CDN ranges, the Wix
/ Sedo default-favicon hashes, real third-party SaaS *provider* hostnames) — they describe
the tooling, not a case.

## Before you commit

- Keep case data in `cases/` / `knowledge/` — never at the repo root. Stray root-level
  case files (`cases_*.txt`, `*_hosts.txt`) are git-ignored precisely because the `cases/`
  rule doesn't match root files; don't defeat that.
- Grep your diff for identifiers before committing a skill change, e.g.:
  ```bash
  git diff --cached | grep -inE 'CASE-20|@gmail|@163|G-[A-Z0-9]{6}|UA-[0-9]{6}' || echo clean
  ```
- If a tool needs case-specific behavior, take it as a **parameter/CLI arg**, don't bake
  the case into the code.

## Where things live (context map)

Jump to the right file instead of re-deriving structure each session. All paths are
tracked code/docs — **case data is never here** (see RULE 1); it lives only in the
git-ignored stores.

| When you need… | Read / edit |
|---|---|
| How a case runs end-to-end (Collect → Correlate → Assess) | `PIPELINE.md`, `harness/README.md` |
| The collector engine (pivot artifacts, WHOIS, JARM, impersonation) | `WebPivot/tools/pivot_extract.py` + the `WebPivot/tools/wp_*.py` modules |
| The analyst / judgment layer (correlation, attribution, confidence) | `IntelAnalysis/` |
| The knowledge base (entities, clusters, noise filters, reference) | `tools/kb/` |
| Case state / resumable convergence loop | `tools/case_state.py`, `tools/intel.py` |
| Register a tool or skill for the MCP + SDK (RULE 2) | `harness/tools.py` (auto-discovered by `harness/mcp_server.py`) |
| The two harness front-ends (SDK vs Claude-Code-native) | `harness/orchestrator.py`, `IntelHarness/` |
| Agent roles & phase prompts | `harness/agents.py`, `harness/prompts/` |
| Alternate model backend (DeepSeek/Kimi/local) | `harness/openai_backend.py` |
| The regression gate before changing `pivot_extract` | `tools/eval/run_eval.py` |
| Report / diagram rendering | `IntelReport/`, `IntelGraph/`, `harness/render.py` |
| The MCP surface exposed to Claude Code | `.mcp.json` (server `intel`), `harness/mcp_server.py` |
| Anthropic-model cost ledger vs third-party API credits | `cases/<case>/run_cost.jsonl` vs `MEMORY/api_usage.jsonl` (see **Cost visibility**) |
