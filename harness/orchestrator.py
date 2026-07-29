"""OSINT harness — a phased agent loop over your existing skills + tools.

The LLM still reasons and chooses tools; the harness fixes the ENVIRONMENT so the
run is repeatable:
  - each phase uses a pinned skill body as its system_prompt (WebPivot / IntelAnalysis)
  - each phase exposes only its own tool subset
  - context carries across phases via resume=<session_id>
  - the final Assess phase is schema-forced (output_format) -> validated JSON

Phases:  Collect -> Correlate -> Assess

Run:
  export ANTHROPIC_API_KEY=...            # or be logged into Claude Code
  python3 harness/orchestrator.py CASE-0001 https://site-a.example https://site-b.example
  python3 harness/orchestrator.py CASE-0001 --hostile https://sketchy.example
"""
from __future__ import annotations

import asyncio
import os
import sys
from dataclasses import dataclass

from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
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


async def _phase(prompt, *, system, tools, servers, resume=None,
                 model=None, effort=None, output_schema=None, hostile=False):
    T.POLICY["hostile"] = hostile
    opts = ClaudeAgentOptions(
        system_prompt=system,
        mcp_servers=servers,
        allowed_tools=tools,
        # headless: no approval prompts. The egress guardrail lives inside the tool;
        # for an interactive/safer harness use permission_mode="default" + can_use_tool.
        permission_mode="bypassPermissions",
        setting_sources=[],          # don't inherit machine/project .claude settings
        resume=resume,
        max_turns=40,
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
            if isinstance(msg, ResultMessage):
                result = msg
    except Exception:  # query() raises AFTER yielding an error ResultMessage
        if result is None:
            raise
    return result


async def investigate(seeds: list[str], case: str, hostile: bool = False) -> Assessment:
    seed_lines = "\n".join(f"- {s}" for s in seeds)

    # PHASE 1 — COLLECT  (WebPivot brain, collection tools)
    p1 = await _phase(
        f"Case `{case}`. For EACH seed below: call pivot_extract, then kb_ingest the case.\n"
        + ("Targets are HOSTILE — pass passive=true or a proxy on pivot_extract.\n" if hostile else "")
        + f"Seeds:\n{seed_lines}",
        system=_skill("WebPivot"),
        tools=T.COLLECT_TOOLS,
        servers={"collect": T.COLLECT_SERVER},
        model=COLLECT.model,
        effort=COLLECT.effort,
        hostile=hostile,
    )
    session = p1.session_id if p1 else None
    if not session:
        raise RuntimeError("collect phase produced no session")

    # PHASE 2 — CORRELATE  (IntelAnalysis brain, read-only tools, same session)
    p2 = await _phase(
        "Correlate what was just ingested: call kb_query_shared (min 2) and risk_signals for the "
        "case. Triage shared artifacts by tier and name the candidate same-operator cluster(s). "
        "Reason only — do not write files.",
        system=_skill("IntelAnalysis"),
        tools=T.ANALYZE_TOOLS,
        servers={"analyze": T.ANALYZE_SERVER},
        resume=session,
        model=JUDGE.model,
        effort=JUDGE.effort,
    )

    # PHASE 3 — ASSESS  (schema-forced structured assessment)
    p3 = await _phase(
        "Produce the final assessment as JSON matching the schema: BLUF with an estimative word; "
        "the cluster and the artifacts binding it; the attribution level and the evidence for it; "
        "gaps / competing explanation; prioritised next pivots.",
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
    print(assessment.model_dump_json(indent=2))


if __name__ == "__main__":
    _main()
