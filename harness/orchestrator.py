"""OSINT harness — a phased agent loop over your existing skills + tools.

The LLM still reasons and chooses tools; the harness fixes the ENVIRONMENT so the
run is repeatable:
  - each phase uses a pinned skill body as its system_prompt (WebPivot / IntelAnalysis)
  - each phase exposes only its own tool subset
  - judgment (Correlate->Assess) runs in its OWN session and reads facts from the KB via
    tools, rather than resuming the large collect transcript (keeps Opus cost down)
  - the final Assess phase is schema-forced (output_format) -> validated Assessment,
    rendered to a rich terminal report + cases/<case>/assessment.{md,json}

Phases:  Collect -> Correlate -> Assess

Run:
  export ANTHROPIC_API_KEY=...            # or be logged into Claude Code
  python3 harness/orchestrator.py CASE-0001 https://site-a.example https://site-b.example
  python3 harness/orchestrator.py CASE-0001 --hostile https://sketchy.example
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import time
from dataclasses import dataclass

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    ToolUseBlock,
    query,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import render  # noqa: E402
import tools as T  # noqa: E402
from schemas import Assessment  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@dataclass(frozen=True)
class Profile:
    """Per-phase model + reasoning effort. Cheap model / minimal thinking for the
    mechanical collection phase; strong model / deep thinking for judgment. Tune per
    run via env vars — no code edit needed."""

    model: str
    effort: str  # low | medium | high | xhigh | max


# Mechanical collection -> cheap model, minimal reasoning.
COLLECT = Profile(
    os.environ.get("HARNESS_COLLECT_MODEL", "haiku"),
    os.environ.get("HARNESS_COLLECT_EFFORT", "low"),
)
# Judgment (correlate + assess) -> strong model, deep reasoning.
JUDGE = Profile(
    os.environ.get("HARNESS_JUDGE_MODEL", "opus"),
    os.environ.get("HARNESS_JUDGE_EFFORT", "high"),
)


MAX_TURNS = int(os.environ.get("HARNESS_MAX_TURNS", "40"))  # lower for cheap smoke runs


def _log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _argpreview(inp: object) -> str:
    if not isinstance(inp, dict):
        return ""
    return ", ".join(f"{k}={str(v)[:36]}" for k, v in inp.items())


def _report_cost(phases: dict[str, object]) -> None:
    """Print the SDK's own per-run cost estimate (ResultMessage.total_cost_usd) to
    stderr, so stdout stays clean for the assessment JSON. Values are per phase; the
    total is their sum — sanity-check against the Console on your first few runs."""
    print("\n--- run cost (SDK total_cost_usd) ---", file=sys.stderr)
    total = 0.0
    for name, r in phases.items():
        c = getattr(r, "total_cost_usd", None)
        total += c or 0.0
        print(f"  {name:<10} {(f'${c:.4f}' if c is not None else 'n/a'):>10}", file=sys.stderr)
    print(
        f"  {'TOTAL':<10} {('$%.4f' % total):>10}   "
        f"(collect={COLLECT.model}/{COLLECT.effort}, judge={JUDGE.model}/{JUDGE.effort})",
        file=sys.stderr,
    )


def _skill(name: str) -> str:
    """Load a SKILL.md body to use as a phase system prompt (inlined for portability;
    the SDK can also auto-load skills from .claude/ via setting_sources)."""
    with open(os.path.join(ROOT, name, "SKILL.md"), encoding="utf-8") as f:
        return f.read()


def _domain_table(case: str) -> str:
    """Render the standard analyst Domain Summary table for the case's collected domains."""
    raw = os.path.join(ROOT, "cases", case, "raw")
    files = [os.path.join(raw, f) for f in os.listdir(raw)] if os.path.isdir(raw) else []
    if not files:
        return ""
    r = subprocess.run(
        [sys.executable, os.path.join("tools", "domain_table.py"), *files,
         "--case", case, "--kb", T.KB_DIR],
        cwd=ROOT, capture_output=True, text=True, timeout=180)
    return r.stdout if r.returncode == 0 else ""


def _prior_knowledge(seeds: list[str]) -> str:
    """Per-seed status so collect can skip re-work: already collected? already attributed?"""
    lines = []
    for s in seeds:
        host = T._host(s)
        collected = bool(T._find_cached_raw(host))
        op = subprocess.run(
            [sys.executable, os.path.join("tools", "kb", "operator_registry.py"), "find", host],
            cwd=ROOT, capture_output=True, text=True)
        first = (op.stdout or "").strip().splitlines()
        attributed = bool(first) and "not attributed" not in first[0].lower()
        tags = [t for t, on in (("already-collected", collected), ("attributed", attributed)) if on]
        note = f"  [{first[0]}]" if attributed else ""
        lines.append(f"- {host}: {', '.join(tags) if tags else 'NEW'}{note}")
    return "\n".join(lines)


async def _phase(prompt, *, label, system, tools, servers, resume=None,
                 model=None, effort=None, output_schema=None, hostile=False):
    T.POLICY["hostile"] = hostile
    t0 = time.time()
    _log(f"\n▶ {label}  ·  {model}/{effort}")
    opts = ClaudeAgentOptions(
        system_prompt=system,
        mcp_servers=servers,
        tools=[],             # remove ALL built-ins (Bash/Read/…) -> force the clean MCP tools,
        allowed_tools=tools,  #   not shell flailing over the skill prompt's bash instructions
        # headless: no approval prompts. The egress guardrail lives inside the tool;
        # for an interactive/safer harness use permission_mode="default" + can_use_tool.
        permission_mode="bypassPermissions",
        setting_sources=[],          # don't inherit machine/project .claude settings
        resume=resume,
        max_turns=MAX_TURNS,
        model=model,
        effort=effort,
        output_format=(
            {"type": "json_schema", "schema": output_schema.model_json_schema()}
            if output_schema else None
        ),
    )
    result = None
    try:
        async for msg in query(prompt=prompt, options=opts):
            if isinstance(msg, AssistantMessage):
                for block in msg.content:            # live worklog: each tool call + its args
                    if isinstance(block, ToolUseBlock):
                        _log(f"    · {block.name.split('__')[-1]}({_argpreview(block.input)})")
            elif isinstance(msg, ResultMessage):
                result = msg
    except Exception:  # query() raises AFTER yielding an error ResultMessage
        if result is None:
            raise
    cost = getattr(result, "total_cost_usd", None)
    _log(f"  ✓ {label} · {time.time() - t0:.0f}s"
         + (f" · ${cost:.4f}" if cost is not None else ""))
    return result


async def investigate(seeds: list[str], case: str, hostile: bool = False) -> Assessment:
    seed_lines = "\n".join(f"- {s}" for s in seeds)
    seed_csv = ", ".join(seeds)

    # PHASE 1 — COLLECT  (WebPivot brain, cheap model). Writes raw + ingests into the KB.
    prior = _prior_knowledge(seeds)
    _log("prior knowledge:\n" + prior)
    p1 = await _phase(
        "You have ONLY the provided tools (pivot_extract, kb_ingest) — no shell or filesystem. "
        "Ignore any shell commands in the instructions; call the tools directly.\n\n"
        f"Case `{case}`. Prior knowledge — do NOT re-collect seeds already collected/attributed "
        f"(pivot_extract returns cached data for those instantly); spend live collection only on NEW seeds:\n"
        f"{prior}\n\n"
        "For EACH seed: call pivot_extract, then kb_ingest the case.\n"
        + ("Targets are HOSTILE — pass passive=true or a proxy on pivot_extract.\n" if hostile else "")
        + f"Seeds:\n{seed_lines}",
        label="collect",
        system=_skill("WebPivot"),
        tools=T.COLLECT_TOOLS,
        servers={"collect": T.COLLECT_SERVER},
        model=COLLECT.model,
        effort=COLLECT.effort,
        hostile=hostile,
    )
    # We do NOT resume the collect session into judgment. The facts now live in the KB,
    # which the judgment phases read via tools — carrying the (large) collect transcript
    # into every Opus turn was the main cost driver. Judgment runs in its own session.

    # PHASE 2 — CORRELATE  (IntelAnalysis brain, judge model). Fresh session, reads the KB.
    p2 = await _phase(
        "You have ONLY the provided tools (kb_query_shared, risk_signals, reverse_whois, "
        "domain_verdict) — no shell or filesystem. Ignore shell commands in the instructions.\n\n"
        f"Case `{case}` (seeds: {seed_csv}). Collection is already ingested into the knowledge "
        "base. Call kb_query_shared (min 2) and risk_signals for the case, then triage the shared "
        "artifacts by tier and name the candidate same-operator cluster(s). Reason only.",
        label="correlate",
        system=_skill("IntelAnalysis"),
        tools=T.ANALYZE_TOOLS,
        servers={"analyze": T.ANALYZE_SERVER},
        model=JUDGE.model,
        effort=JUDGE.effort,
    )
    session = p2.session_id if p2 else None
    if not session:
        raise RuntimeError("correlate phase produced no session")

    # PHASE 3 — ASSESS  (resume CORRELATE; schema-forced structured assessment)
    p3 = await _phase(
        "Produce the final assessment as JSON matching the schema: BLUF with an estimative word; "
        "the cluster and the artifacts binding it; the attribution level and the evidence for it; "
        "gaps / competing explanation; prioritised next pivots.",
        label="assess",
        system=_skill("IntelAnalysis"),
        tools=T.ANALYZE_TOOLS,
        servers={"analyze": T.ANALYZE_SERVER},
        resume=session,
        model=JUDGE.model,
        effort=JUDGE.effort,
        output_schema=Assessment,
    )

    _report_cost({"collect": p1, "correlate": p2, "assess": p3})

    if p3 and p3.subtype == "success" and p3.structured_output:
        return Assessment.model_validate(p3.structured_output)
    raise RuntimeError(f"assessment failed (subtype={getattr(p3, 'subtype', None)})")


def _main() -> None:
    argv = sys.argv[1:]
    hostile = "--hostile" in argv
    argv = [a for a in argv if a != "--hostile"]
    if len(argv) < 2:
        sys.exit("usage: orchestrator.py <CASE-ID> [--hostile] <seed-url> [seed-url ...]")
    case, seeds = argv[0], argv[1:]
    assessment = asyncio.run(investigate(seeds, case, hostile=hostile))

    table_md = _domain_table(case)                            # standard Domain Summary table
    render.render_terminal(assessment, table_md=table_md)     # colored report -> stdout
    md = render.save_markdown(assessment, case, ROOT, table_md=table_md)  # cases/<case>/assessment.md
    json_path = os.path.join(ROOT, "cases", case, "assessment.json")
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(assessment.model_dump_json(indent=2))
    _log(f"\n saved · {md}\n saved · {json_path}")


if __name__ == "__main__":
    _main()
