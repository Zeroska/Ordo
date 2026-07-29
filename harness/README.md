# OSINT harness (skeleton)

A **controlled agent loop** around the existing skills + tools. The LLM still
reasons and picks tools — the harness fixes the *environment* so a run is
repeatable. This is the middle of the spectrum:

```
Interactive Claude Code  ──►  THIS HARNESS  ──►  Deterministic pipeline (intel.py open)
  reasoning, unconstrained      reasoning inside a fixed scaffold      no reasoning
```

## How it works

Three phases; each is one `query()` call, wired so consistency comes from the scaffold:

| Phase | Skill as `system_prompt` | Tools exposed | Output |
|---|---|---|---|
| **Collect** | `WebPivot/SKILL.md` | `pivot_extract`, `kb_ingest` | raw JSON in `cases/<case>/raw/`, ingested to KB |
| **Correlate** | `IntelAnalysis/SKILL.md` | `kb_query_shared`, `risk_signals` (read-only) | in-context reasoning |
| **Assess** | `IntelAnalysis/SKILL.md` | read-only | **schema-forced `Assessment` JSON** |

- Context carries across phases via `resume=<session_id>`.
- The final phase uses `output_format={"type":"json_schema", ...}` → validated
  `Assessment` (see `schemas.py`). That's the deterministic checkpoint.
- **Per-phase model + effort** are set by two `Profile`s in `orchestrator.py`:
  `COLLECT` = `haiku`/`low` (cheap, mechanical) and `JUDGE` = `opus`/`high` (deep reasoning).
  Override per run without editing code:
  ```bash
  HARNESS_COLLECT_MODEL=haiku HARNESS_COLLECT_EFFORT=low \
  HARNESS_JUDGE_MODEL=opus   HARNESS_JUDGE_EFFORT=high  \
  python3 harness/orchestrator.py CASE-0001 https://site-a.example
  ```
- Each run prints its **cost breakdown** (SDK `total_cost_usd`, per phase + total) to stderr,
  so stdout stays clean JSON. Use it to measure real cost-per-case on your first runs.

## Files
- `tools.py` — your CLI scripts wrapped as in-process `@tool`s (+ the egress guardrail).
- `schemas.py` — the `Assessment` Pydantic model (the structured checkpoint).
- `orchestrator.py` — the Collect→Correlate→Assess driver + CLI.
- `agents.py` — *optional* subagent definitions for parallel fan-out (ParallelBatch).

## Run
```bash
python3 -m venv harness/.venv && source harness/.venv/bin/activate
pip install -r harness/requirements.txt
export ANTHROPIC_API_KEY=...        # or be logged into Claude Code

python3 harness/orchestrator.py CASE-0001 https://site-a.example https://site-b.example
python3 harness/orchestrator.py CASE-0001 --hostile https://sketchy.example
```
Prints the validated `Assessment` as JSON. Reads/writes the same `cases/` + `knowledge/`
stores as the skills (both git-ignored).

## Don't re-investigate what's already known
Before collecting, the harness prints a **prior-knowledge** line per seed (already-collected / attributed / NEW), and `pivot_extract` **reuses the cached pivot JSON** if the domain was investigated in *any* prior case — no re-fetch, no API spend. Pass `force=true` (or `HARNESS_FORCE=1`) to refresh. The judgment phase also has a **`domain_verdict`** tool that returns a domain's prior verdict (operator-registry attribution + KB facts), so a resolved seed is *shown*, not re-worked.

## Collection behavior & outputs
Every `pivot_extract` call now, by default:
- runs **full enrichment** — WHOIS + FOFA + urlscan (needs the API keys in `.env`); `HARNESS_NO_ENRICH=1` turns it off for cheap smoke runs only;
- **saves the raw DOM** to `cases/<case>/dom/<host>.html` so you can manually analyze it or re-run a pivoting script over it;
- **detects Cloudflare** (`meta.cloudflare`) and auto-retries the bypass — a real browser via `--render` (uses `WebPivot/.venv`), or FlareSolverr if `HARNESS_FLARESOLVERR=http://host:8191/v1` is set.

The judgment phase also has a **`reverse_whois`** tool that returns only high-value pivots: it refuses privacy/registrar terms and flags a bulk registrant (`> max_domains` = reseller = noise) instead of dumping it.

Every run prints/saves the standard **Domain Summary table** (`tools/domain_table.py`) — Domain · Status · Registered · Expires · Registrar · Nameservers · Registrant · IP·ASN · Attribution · Context — for the domains collected this run, above the assessment.

New env knobs: `HARNESS_FLARESOLVERR` (CF solver URL) · `HARNESS_RENDER_PY` (playwright python, default `WebPivot/.venv`).

## The guardrail seam
`tools.POLICY["hostile"]` is flipped by the orchestrator for `--hostile` runs; the
`pivot_extract` tool then **refuses a live fetch** unless called with `passive=true`
or a `proxy`. That's your egress tradecraft as code. For production, enforce the same
rule with a `PreToolUse` hook or the `can_use_tool` callback so it can't be bypassed
in-process, and drop `permission_mode="bypassPermissions"`.

## Auth & billing (read before running)
The Agent SDK authenticates with an **`ANTHROPIC_API_KEY` (pay-per-token)**, or Bedrock /
Vertex / AWS / Foundry — **not** a Claude Pro/Max subscription. Per the docs, claude.ai
login is not a supported/allowed auth path for SDK-built agents. To run on your existing
subscription instead, drive **Claude Code headless** (`claude -p "<prompt>" --output-format
json`) as a subprocess rather than this SDK library (personal/internal use only; you lose
schema-forced `output_format`). If you ever distribute this to other users, they each need
API-key auth — subscription auth can't power a shared product.

## Two SDK gotchas baked in (verified against the docs)
1. **We inline each `SKILL.md` as the phase `system_prompt`** for explicitness/portability.
   (The SDK *can* auto-load skills from `.claude/` when `setting_sources` includes
   `"project"`/`"user"` — same as Claude Code — but inlining doesn't depend on the skills
   being registered/symlinked into `.claude/`, so it's self-contained.)
2. **The Python `@tool` decorator forwards only `content` + `is_error`** — *not*
   `structuredContent`. So tools return JSON as text (the model reads it), and machine
   validation happens only at the final `output_format` checkpoint.

## Adjust before real use (integration seams)
- **CLI flags** in `tools.py` are illustrative — match them to your actual scripts
  (`pivot_extract` `--crawl`/`--rotate-ua`, `risk_signals` options, etc.).
- **Model aliases** `sonnet`/`opus` — pin exact IDs if you want reproducibility across
  model updates.
- **Regression-gate the agent**: add end-to-end golden cases to `tools/eval/` (fixed
  seed → expected `Assessment` shape) so a prompt/tool change can't silently drift it.
- Verified against the Agent SDK docs (code.claude.com/docs/en/agent-sdk) at build time;
  re-check `query` / `ClaudeAgentOptions` / `@tool` signatures if you bump the SDK.
