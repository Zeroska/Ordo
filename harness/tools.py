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

import glob
import json
import os
import shutil
import subprocess
import sys
from typing import Any
from urllib.parse import urlparse

from claude_agent_sdk import ToolAnnotations, create_sdk_mcp_server, tool

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # repo root (harness/..)
PY = sys.executable
READONLY = ToolAnnotations(readOnlyHint=True)  # lets the model batch these in parallel

# knobs (env) — cheap/isolated smoke runs without touching the real KB:
KB_DIR = os.environ.get("HARNESS_KB", "knowledge")        # e.g. HARNESS_KB=knowledge_scratch
SMOKE = bool(os.environ.get("HARNESS_NO_ENRICH"))         # skip FOFA/urlscan/WHOIS (fast, no credits)
FORCE = bool(os.environ.get("HARNESS_FORCE"))             # re-collect even if already investigated

# CF-bypass: --render needs a playwright-capable python (the WebPivot venv); FlareSolverr needs a URL.
RENDER_PY = os.environ.get("HARNESS_RENDER_PY") or (
    _wp if os.path.exists(_wp := os.path.join(ROOT, "WebPivot", ".venv", "bin", "python3")) else PY)
FLARESOLVERR = os.environ.get("HARNESS_FLARESOLVERR")     # e.g. http://localhost:8191/v1

# reuse the KB's registrant/privacy noise filter for reverse-WHOIS triage
sys.path.insert(0, os.path.join(ROOT, "tools", "kb"))
try:
    from noise_filters import is_noise_email as _is_noise_email  # noqa: E402
except Exception:  # noqa: BLE001
    def _is_noise_email(_e: str) -> bool:
        return False

# --- egress-policy guardrail (the tradecraft-as-code seam) -------------------
# The orchestrator flips this before a hostile-target run. This is deliberately a
# simple module global for the skeleton; in production enforce the same rule with
# a PreToolUse hook or the can_use_tool callback so it can't be bypassed in-process.
POLICY: dict[str, bool] = {"hostile": False}


def _host(url: str) -> str:
    return urlparse(url if "://" in url else "http://" + url).hostname or url


def _run(cmd: list[str], timeout: int = 180) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)


def _load_json(path: str):
    try:
        return json.load(open(path, encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def _load_json_str(s: str):
    try:
        return json.loads(s)
    except Exception:  # noqa: BLE001
        return None


def _find_cached_raw(host: str, exclude: str = "") -> str:
    """Newest existing pivot JSON for this host across ALL cases (already investigated?)."""
    hits = [p for p in glob.glob(os.path.join(ROOT, "cases", "*", "raw", host + ".json")) if p != exclude]
    hits.sort(key=os.path.getmtime, reverse=True)
    return hits[0] if hits else ""


def _err(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "is_error": True}


def _ok(text: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}]}


# ---------------------------------------------------------------- COLLECT tools
@tool(
    "pivot_extract",
    "Extract pivot artifacts (favicon hash, tracking/analytics IDs, wallets, emails, "
    "third-party infra) from a URL and write the JSON into the case. If the domain was ALREADY "
    "investigated (a pivot JSON exists in any case), it returns the cached data instead of "
    "re-collecting — pass force=true to refresh. For HOSTILE targets a direct live fetch is "
    "refused — pass proxy='<cidr>' to rotate egress, or passive=true with url set to an "
    "already-saved/archived HTML file (captured out-of-band via Wayback/urlscan).",
    {"url": str, "case": str},  # force/passive:bool, proxy:str are optional -> read via args.get()
)
async def pivot_extract(args: dict[str, Any]) -> dict[str, Any]:
    url, case = args["url"], args["case"]
    passive, proxy = args.get("passive", False), args.get("proxy")
    raw_dir = os.path.join(ROOT, "cases", case, "raw")
    dom_dir = os.path.join(ROOT, "cases", case, "dom")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(dom_dir, exist_ok=True)
    host = _host(url)
    out = os.path.join(raw_dir, host + ".json")
    dom = os.path.join(dom_dir, host + ".html")

    # ALREADY INVESTIGATED? reuse the cached pivot rather than blindly (and expensively) re-collecting.
    if not (FORCE or args.get("force")):
        prior = out if os.path.exists(out) else _find_cached_raw(host, exclude=out)
        data = _load_json(prior) if prior else None
        if data is not None:
            if prior != out:
                shutil.copyfile(prior, out)  # bring it into this case so kb_ingest still sees it
            n = len(data.get("pivots", []))
            return _ok(f"ALREADY INVESTIGATED — reused cached pivot for {host} ({n} pivots, from "
                       f"{os.path.relpath(prior, ROOT)}); NOT re-collected. force=true to refresh.\n"
                       f"{json.dumps(data, ensure_ascii=False)[:4000]}")

    if POLICY["hostile"] and not passive and not proxy:
        return _err(
            "BLOCKED by egress policy: target is flagged hostile. Re-call with passive=true "
            "or proxy='<cidr>' before any live fetch."
        )
    # ALWAYS: full WHOIS + FOFA + urlscan enrichment (default), and save the raw DOM for manual review.
    base = [os.path.join("WebPivot", "tools", "pivot_extract.py"), url, "--pretty", "-o", out, "--save-dom", dom]
    if proxy:
        base += ["--proxy-range", proxy]
    if SMOKE:
        base += ["--no-enrich", "--no-whois"]  # cheap smoke only
    r = _run([PY, *base], timeout=240)
    data = _load_json(out)
    if data is None:
        return _err(f"pivot_extract failed: {(r.stderr or '')[-800:]}")
    # Cloudflare interstitial? retry once with a real browser (--render) or FlareSolverr (--solve-cf).
    cf = (data.get("meta") or {}).get("cloudflare")
    used = "direct"
    if cf and not SMOKE:
        if FLARESOLVERR:
            _run([PY, *base, "--solve-cf", "--flaresolverr", FLARESOLVERR], timeout=300)
            used = "flaresolverr"
        else:
            _run([RENDER_PY, *base, "--render"], timeout=300)
            used = "render(browser)"
        data = _load_json(out) or data
    n = len(data.get("pivots", []))
    walled = (data.get("meta") or {}).get("cloudflare")
    cfnote = f"  · CF {cf} → {used} ({'STILL WALLED' if walled else 'bypassed'})" if cf else ""
    return _ok(f"Extracted {n} pivots from {url}{cfnote}\nDOM saved for manual review: {dom}\n"
               f"{json.dumps(data, ensure_ascii=False)[:6000]}")


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
    r = _run([PY, os.path.join("tools", "kb", "ingest_webpivot.py"), "--kb", KB_DIR, *files])
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
              "--kb", KB_DIR, "--shared", "--min", str(args.get("min", 2))])
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


@tool(
    "reverse_whois",
    "Reverse-WHOIS a registrant email or name and return only the HIGH-VALUE pivots. Refuses a "
    "privacy/registrar term outright, and flags a bulk registrant (> max_domains = a shared "
    "reseller/agency = NOISE) instead of dumping it. Use on a leaked registrant identity. "
    "kind = 'email' or 'name'.",
    {"term": str, "kind": str},  # max_domains optional (default 150)
    annotations=READONLY,
)
async def reverse_whois(args: dict[str, Any]) -> dict[str, Any]:
    term, kind = args["term"], args.get("kind", "email")
    cap = int(args.get("max_domains", 150))
    if kind == "email" and _is_noise_email(term):
        return _err(f"'{term}' is a privacy/registrar address (shared by every domain there) — "
                    "NOT a registrant pivot. Do not reverse it.")
    flag = "--reverse-email" if kind == "email" else "--reverse-name"
    r = _run([PY, os.path.join("WebPivot", "tools", "whois_enrich.py"), flag, term,
              "--search-type", "historic", "--json"], timeout=150)
    data = _load_json_str(r.stdout) or {}
    rec = data.get("reverse_email") or data.get("reverse_name") or {}
    if not rec or rec.get("error"):
        return _err(f"reverse-WHOIS failed for '{term}': {rec.get('error') or (r.stderr or '')[-300:]}")
    domains, count = rec.get("domains") or [], rec.get("count", 0)
    if count > cap:
        return _ok(f"'{term}' registers {count} domains (> {cap}) — a shared reseller/agency; "
                   "treat as NOISE, do NOT cluster on it.")
    return _ok(f"'{term}' → {count} domains (high-value reverse-WHOIS pivots; privacy/bulk filtered):\n"
               + ("\n".join(domains) if domains else "(none)"))


@tool(
    "domain_verdict",
    "The PRIOR verdict for a domain already in the store: who it's attributed to (operator "
    "registry) + its known KB facts/edges. Call this before treating a seed as new — if it's "
    "already resolved, show the verdict instead of re-investigating.",
    {"domain": str},
    annotations=READONLY,
)
async def domain_verdict(args: dict[str, Any]) -> dict[str, Any]:
    d = _host(args["domain"])
    op = _run([PY, os.path.join("tools", "kb", "operator_registry.py"), "find", d])
    kb = _run([PY, os.path.join("tools", "kb", "query.py"), "--kb", KB_DIR, "--entity", d])
    verdict = (op.stdout or "").strip() or "not attributed to any known operator"
    facts = (kb.stdout or "").strip() or "no KB record for this domain"
    collected = bool(_find_cached_raw(d))
    return _ok(f"VERDICT for {d}  (pivot data on file: {'yes' if collected else 'no'})\n"
               f"[operator] {verdict}\n[KB] {facts[:3000]}")


# ---------------------------------------------------------------- servers + names
COLLECT_SERVER = create_sdk_mcp_server("collect", tools=[pivot_extract, kb_ingest])
ANALYZE_SERVER = create_sdk_mcp_server(
    "analyze", tools=[kb_query_shared, risk_signals, reverse_whois, domain_verdict])

COLLECT_TOOLS = ["mcp__collect__pivot_extract", "mcp__collect__kb_ingest"]
ANALYZE_TOOLS = ["mcp__analyze__kb_query_shared", "mcp__analyze__risk_signals",
                 "mcp__analyze__reverse_whois", "mcp__analyze__domain_verdict"]
