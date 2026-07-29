"""Your existing Python CLI tools, wrapped as in-process Agent-SDK tools.

Each wrapper shells out to the real script (the tools stay the source of truth)
and returns the result as a TEXT content block. NOTE: the Python `@tool` decorator
forwards only `content` and `is_error` — it does NOT forward `structuredContent`
(that needs a standalone MCP server). So the model reads the JSON as text here;
machine-validated structure is enforced separately at the final assessment via
ClaudeAgentOptions.output_format (see orchestrator.py).

ADJUST: the exact CLI flags below are the integration seam — tweak them to match
your scripts (e.g. pivot_extract's --crawl / --rotate-ua, risk_signals' options).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from typing import Any
from urllib.parse import urlparse

from claude_agent_sdk import ToolAnnotations, create_sdk_mcp_server, tool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root (harness/..)
PY = sys.executable
READONLY = ToolAnnotations(readOnlyHint=True)  # lets the model batch these in parallel

# --- egress-policy guardrail (the tradecraft-as-code seam) -------------------
# The orchestrator flips this before a hostile-target run. This is deliberately a
# simple module global for the skeleton; in production enforce the same rule with
# a PreToolUse hook or the can_use_tool callback so it can't be bypassed in-process.
POLICY: dict[str, bool] = {"hostile": False}


def _host(url: str) -> str:
    return urlparse(url if "://" in url else "http://" + url).hostname or url


def _run(cmd: list[str], timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)


def _err(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "is_error": True}


def _ok(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}]}


# ---------------------------------------------------------------- COLLECT tools
@tool(
    "pivot_extract",
    "Extract pivot artifacts (favicon hash, tracking/analytics IDs, wallets, emails, "
    "third-party infra) from a URL and write the JSON into the case. For hostile targets "
    "pass passive=true (Wayback/urlscan) or proxy='<cidr>' — a live fetch is refused otherwise.",
    {"url": str, "case": str},  # passive:bool / proxy:str are optional -> read via args.get()
)
async def pivot_extract(args: dict[str, Any]) -> dict[str, Any]:
    url, case = args["url"], args["case"]
    passive, proxy = args.get("passive", False), args.get("proxy")
    if POLICY["hostile"] and not passive and not proxy:
        return _err(
            "BLOCKED by egress policy: target is flagged hostile. Re-call with passive=true "
            "or proxy='<cidr>' before any live fetch."
        )
    raw_dir = os.path.join(ROOT, "cases", case, "raw")
    os.makedirs(raw_dir, exist_ok=True)
    out = os.path.join(raw_dir, _host(url) + ".json")
    cmd = [PY, os.path.join("WebPivot", "tools", "pivot_extract.py"), url, "--pretty", "-o", out]
    if proxy:
        cmd += ["--proxy-range", proxy]  # ADJUST to your flag name
    r = _run(cmd)
    if r.returncode != 0:
        return _err(f"pivot_extract failed: {r.stderr[-800:]}")
    try:
        data = json.load(open(out, encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        return _err(f"wrote {out} but could not parse JSON: {e}")
    n = len(data.get("pivots", []))
    return _ok(f"Extracted {n} pivots from {url} -> {out}\n{json.dumps(data, ensure_ascii=False)[:6000]}")


@tool(
    "kb_ingest",
    "Ingest a case's raw pivot JSON into the knowledge base so it becomes correlatable. "
    "Run this after pivot_extract; a run that isn't ingested is invisible to correlation.",
    {"case": str},
)
async def kb_ingest(args: dict[str, Any]) -> dict[str, Any]:
    raw = os.path.join(ROOT, "cases", args["case"], "raw")
    files = [os.path.join(raw, f) for f in os.listdir(raw)] if os.path.isdir(raw) else []
    if not files:
        return _err(f"no raw pivot JSON in {raw}")
    r = _run([PY, os.path.join("tools", "kb", "ingest_webpivot.py"), "--kb", "knowledge", *files])
    return {"content": [{"type": "text", "text": (r.stdout + r.stderr) or "ingested"}],
            "is_error": r.returncode != 0}


# ---------------------------------------------------------------- ANALYZE tools
@tool(
    "kb_query_shared",
    "List indicators shared by >= min domains in the KB — the cluster seeds. Read-only.",
    {"min": int},
    annotations=READONLY,
)
async def kb_query_shared(args: dict[str, Any]) -> dict[str, Any]:
    r = _run([PY, os.path.join("tools", "kb", "query.py"),
              "--kb", "knowledge", "--shared", "--min", str(args.get("min", 2))])
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


@tool(
    "risk_signals",
    "Score a case's hosts for NRD / bulletproof-hosting / money-trail risk. Read-only.",
    {"case": str},
    annotations=READONLY,
)
async def risk_signals(args: dict[str, Any]) -> dict[str, Any]:
    r = _run([PY, os.path.join("tools", "kb", "risk_signals.py"), "--case", args["case"]])
    return {"content": [{"type": "text", "text": r.stdout or r.stderr}], "is_error": r.returncode != 0}


# ---------------------------------------------------------------- servers + names
COLLECT_SERVER = create_sdk_mcp_server("collect", tools=[pivot_extract, kb_ingest])
ANALYZE_SERVER = create_sdk_mcp_server("analyze", tools=[kb_query_shared, risk_signals])

COLLECT_TOOLS = ["mcp__collect__pivot_extract", "mcp__collect__kb_ingest"]
ANALYZE_TOOLS = ["mcp__analyze__kb_query_shared", "mcp__analyze__risk_signals"]
