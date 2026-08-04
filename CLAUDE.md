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

## RULE 3 — Separate DATA from LOGIC: reference lists live in JSON, never in code

An analyst must be able to tune a denylist, threshold or lookup table **without editing Python
and without a redeploy**. Code holds the *matching logic*; the values it matches against are data.

- **Any list, map or threshold an analyst may reasonably want to extend goes in a JSON file** —
  denylists/allowlists (managed DNS, parking hosts, privacy-proxy contacts, noise phones), scoring
  thresholds, ASN/CIDR tables, brand/keyword sets, provider registries. If you catch yourself
  appending a literal to a Python tuple/set/dict, it belongs in JSON instead.
- **Where it lives:** `<module>/references/<name>.json` — e.g. `WebPivot/references/cdn_ranges.json`,
  `IntelAnalysis/references/risk_indicators.json`, `tools/kb/references/noise_filters.json`.
- **Shape:** a top-level `_comment` explaining the file, then one object per group with its own
  `_comment` and a `values` array (or named scalars for thresholds). The `_comment` keys are the
  analyst's documentation — write them for a human who has never read the code. Keys beginning
  with `_` are ignored by loaders.
- **Loading:** use the shared loader — `wp_refs.py` (WebPivot), `kb_refs.py` (`tools/kb`),
  `bp_refs.py` (BinaryPivot), `ig_refs.py` (IntelGraph):
  `load_ref(ref_path(__file__, "<name>.json"), _FALLBACK)`. It
  **falls back to your minimal embedded default on missing/malformed/incomplete input and warns
  on stderr**. Never fail open silently — a filter that quietly returns `False` everywhere
  manufactures false clusters, which is worse than crashing. Keep the existing module-level
  constant names so importers don't break. The four loaders are **byte-identical copies on
  purpose** (each skill is imported standalone, so it can't depend on a repo-root package) with
  **distinct module names on purpose** (`tools/kb` and `WebPivot/tools` both land on `sys.path`
  in the same process, so a shared `refs.py` would collide); `tests/test_references.py` asserts
  they stay in sync.
- **One group, one owner.** If two modules match the same values, they read the same JSON group —
  never re-paste the list. That duplication is what let the registrant-noise denylists drift
  across six modules before this layer existed.
- **Normalise on load**, so analysts can enter values in any reasonable format (a phone as
  `+354.421 2434` or `3544212434`; a host with or without a trailing dot).
- **Test the data file itself** in `tests/test_references.py`: it asserts every `references/*.json`
  parses and is documented (`_comment` at the top and per group), that each consumer's loaded
  values are the JSON's and **not** the fallback's, and that a broken file degrades loudly. Add
  your new file's consumers to its `consumers` list — a module silently running on its stub still
  imports and still produces output, it just stops filtering. It runs in the eval gate too.
- **RULE 1 still applies.** These JSON files are tracked and public-facing: generic provider/
  infrastructure constants only, never case data. Case-specific tuning belongs in the git-ignored
  `knowledge/` store.

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
- **Censys is the tightest quota — treat it as a budget, not a log.** 100 credits a MONTH on the
  free plan, no rollover, and the quota is **per account**, so overspending in one case removes
  Censys from every later case. A lookup is 1 credit, a search 5 — **and running the emitted CenQL
  in the web UI costs the same 5**, so the UI link is not a free escape hatch. Prefer the keyless
  CenQL builder and the 1-credit `cert` lookup; check `wp_censys.py budget` before a batch. The
  guard in `wp_censys` caps spend per month and per run from the same ledger.
- **A run's COLLECTION capability is also cost-visible.** `wp_capabilities.py` reports which keys
  are absent and what evidence class each absence removes; it is embedded in every result as
  `meta.capability`. Report a keyless/`--free-only` run as such — its zero API cost bought a
  correspondingly smaller search of the internet.

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
| The CENSYS layer — CenQL query builder (keyless) + the three free-plan lookups (certificate `names`, host, web property). Free Censys = **lookup endpoints only**; search is Starter+ and degrades to a UI link. **100 credits/MONTH, per account, no rollover — and the UI link costs the same 5 credits as an API search**; the spend guard caps it per month + per run | `WebPivot/tools/wp_censys.py` (tool; `budget` subcommand) + `WebPivot/references/censys_queries.json` (fields/prices/tiers + `credit_budget`) + `references/Setup.md` (getting the key) |
| The CAPABILITY / keyless-disclosure layer — which keys exist, what each absence removes, and the rule that a keyless run must SAY so before any "nothing found" (a missing reverse index ≠ evidence of absence) | `WebPivot/tools/wp_capabilities.py` (tool + `meta.capability` + the run banner) + `WebPivot/references/api_keys.json` (per-key consequences) + `WebPivot/SKILL.md` § *API keys* |
| The analyst / judgment layer (correlation, attribution, confidence) | `IntelAnalysis/` |
| The knowledge base (entities, clusters, noise filters, reference) | `tools/kb/` |
| Case state / resumable convergence loop | `tools/case_state.py`, `tools/intel.py` |
| Where a case artifact belongs — `cases/` vs `knowledge/` | `README.md` § *`cases/` vs `knowledge/`*. Short version: **every per-case deliverable lives in `cases/<case>/`**; `knowledge/` is the cross-case KB only. `assessment.md` is the analyst's and is never overwritten; the loop's render goes to `loop_assessment.md` |
| Register a tool or skill for the MCP + SDK (RULE 2) | `harness/tools.py` (auto-discovered by `harness/mcp_server.py`) |
| Tunable reference DATA — denylists, thresholds, tables (RULE 3) | `<module>/references/*.json` — `tools/kb/` (`noise_filters`, `registrant_noise`), `WebPivot/` (`registrant_noise`, `third_party_noise`, `generic_labels`, `impersonation`, `mail_providers`, `pivot_tables`, `asn_registry`, `cdn_ranges`, `censys_queries`, `api_keys`), `BinaryPivot/binary_indicators.json`, `IntelAnalysis/risk_indicators.json`, `tools/kb/references/victim_profile.json` (panel signatures, access-vector hypotheses + thresholds), `IntelGraph/references/evidence_sources.json` (evidence permalinks, source grading, staleness) |
| The reference-data loader + its gate | `wp_refs.py` / `kb_refs.py` / `bp_refs.py` / `ig_refs.py` (identical), `tests/test_references.py` |
| The TEMPORAL layer — lifecycle timeline, hosting windows, expiry cohorts, evidence ledger | `IntelGraph/scripts/case_timeline.py` (tool) + `IntelAnalysis/SKILL.md` §1.5 & `Workflows/Timeline.md` (tradecraft) |
| The VICTIM layer — when the operator serves from hostnames they don't own; infers the ACCESS VECTOR (provider breach / panel exploit / CMS exploit / agency / stolen-or-bought credentials) from the victim set's shape | `tools/kb/victim_profile.py` (tool) + `IntelAnalysis/SKILL.md` §1.6 & `Workflows/VictimProfile.md` (tradecraft) |
| The two harness front-ends (SDK vs Claude-Code-native) | `harness/orchestrator.py`, `IntelHarness/` |
| Agent roles & phase prompts | `harness/agents.py`, `harness/prompts/` |
| Alternate model backend (DeepSeek/Kimi/local) | `harness/openai_backend.py` |
| The regression gate before changing `pivot_extract` | `tools/eval/run_eval.py` |
| Report / diagram rendering | `IntelReport/`, `IntelGraph/`, `harness/render.py` |
| The MCP surface exposed to Claude Code | `.mcp.json` (server `intel`), `harness/mcp_server.py` |
| Anthropic-model cost ledger vs third-party API credits | `cases/<case>/run_cost.jsonl` vs `MEMORY/api_usage.jsonl` (see **Cost visibility**) |
