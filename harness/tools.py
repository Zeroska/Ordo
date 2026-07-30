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

import concurrent.futures
import datetime
import glob
import json
import os
import shutil
import subprocess
import sys
import threading
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
SHOT = bool(os.environ.get("HARNESS_SCREENSHOT"))         # capture a page screenshot as visual evidence (needs browser)
NO_ARCHIVE = bool(os.environ.get("HARNESS_NO_ARCHIVE"))   # disable Wayback SPN + master ledger (evidence capture is ON by default)


_MANIFEST_LOCK = threading.Lock()   # collect_many appends the manifest from worker threads


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _append_manifest(case: str, host: str, data: dict, *, reused: bool,
                     dom_path: str = "", shot_path: str = "") -> None:
    """Append one provenance row per collection to cases/<case>/evidence/manifest.jsonl — the
    evidence index answering WHERE (source URL + which enrichment services), WHEN (collected_at),
    and WHAT WAS ARCHIVED (saved DOM, screenshot, Wayback flag) for every host we touched. The
    per-pivot detail (kind/value/query) lives alongside it in master_pivots.csv (--master)."""
    meta = data.get("meta") or {}
    ev_dir = os.path.join(ROOT, "cases", case, "evidence")
    os.makedirs(ev_dir, exist_ok=True)
    row = {
        "case": case, "host": host,
        "collected_at": meta.get("collected_at"),          # when the evidence was actually gathered (UTC)
        "logged_at": _utcnow(),                            # when this manifest row was written
        "reused_cache": reused,                            # true = served from a prior run, not re-fetched
        "source_url": meta.get("source"), "final_url": meta.get("final_url"),
        "fetched_with": meta.get("fetched_with"), "recovered_via": meta.get("recovered_via"),
        "enriched_with": meta.get("enriched_with"),        # which services corroborated (crtsh/fofa/urlscan/…)
        "archived_via_wayback": meta.get("archived_via_wayback"),
        "n_pivots": len(data.get("pivots", [])),
        "dom_path": os.path.relpath(dom_path, ROOT) if dom_path and os.path.exists(dom_path) else None,
        "screenshot_path": os.path.relpath(shot_path, ROOT) if shot_path and os.path.exists(shot_path) else None,
        "ledger": os.path.join("cases", case, "evidence", "master_pivots.csv"),
    }
    with _MANIFEST_LOCK:
        with open(os.path.join(ev_dir, "manifest.jsonl"), "a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

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
    "Extract pivot artifacts and write the JSON into the case. `url` may be a URL/host "
    "(domainPivot: favicon hash, tracking/analytics IDs, wallets, emails, third-party infra) OR a "
    "bare IP (IPPivot: passive IP recon — IPinfo ASN/abuse, FOFA ip= ports/services/co-hosted "
    "domains, Shodan host, dig MX/NS/TXT/PTR; a shared CDN/hosting IP is marked information not a "
    "same-operator pivot, and its ASN is banked to references/asn_registry.json). If ALREADY "
    "investigated (a pivot JSON exists in any case), it returns the cached data instead of "
    "re-collecting — pass force=true to refresh. For HOSTILE targets a direct live fetch is "
    "refused — pass proxy='<cidr>' to rotate egress, or passive=true with url set to an "
    "already-saved/archived HTML file (captured out-of-band via Wayback/urlscan).",
    {"url": str, "case": str},  # force/passive:bool, proxy:str are optional -> read via args.get()
)
async def pivot_extract(args: dict[str, Any]) -> dict[str, Any]:
    res = collect_one(args["url"], args["case"], hostile=POLICY["hostile"],
                      passive=args.get("passive", False), proxy=args.get("proxy"),
                      force=bool(args.get("force")))
    if res.get("error"):
        return _err(res["error"])
    blob = json.dumps(res.get("data") or {}, ensure_ascii=False)
    if res["reused"]:
        return _ok(f"ALREADY INVESTIGATED — reused cached pivot for {res['host']} "
                   f"({res['n_pivots']} pivots); NOT re-collected. force=true to refresh.\n{blob[:4000]}")
    return _ok(f"Extracted {res['n_pivots']} pivots from {res['host']}{res['note']}\n"
               f"DOM saved for manual review: {res['dom']}\n{blob[:6000]}")


def collect_one(url: str, case: str, *, hostile: bool = False, passive: bool = False,
                proxy: str | None = None, force: bool = False) -> dict[str, Any]:
    """Collect ONE host end-to-end (cache-reuse → live fetch + enrichment → evidence capture →
    manifest). Sync + self-contained (no globals beyond config) so it is safe to fan out across
    threads via collect_many. Returns a summary dict, never raises."""
    raw_dir = os.path.join(ROOT, "cases", case, "raw")
    dom_dir = os.path.join(ROOT, "cases", case, "dom")
    shot_dir = os.path.join(ROOT, "cases", case, "screenshots")
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(dom_dir, exist_ok=True)
    host = _host(url)
    out = os.path.join(raw_dir, host + ".json")
    dom = os.path.join(dom_dir, host + ".html")
    shot = os.path.join(shot_dir, host + ".png")

    # ALREADY INVESTIGATED? reuse the cached pivot rather than (expensively) re-collecting.
    if not (FORCE or force):
        prior = out if os.path.exists(out) else _find_cached_raw(host, exclude=out)
        data = _load_json(prior) if prior else None
        if data is not None:
            if prior != out:
                shutil.copyfile(prior, out)  # bring it into this case so kb_ingest still sees it
            _append_manifest(case, host, data, reused=True, dom_path=dom if os.path.exists(dom) else "")
            return {"host": host, "ok": True, "reused": True, "error": None, "dom": dom,
                    "n_pivots": len(data.get("pivots", [])), "note": " (cached)", "data": data}

    if hostile and not passive and not proxy:
        return {"host": host, "ok": False, "reused": False, "n_pivots": 0, "data": None, "dom": dom,
                "note": "", "error": (f"BLOCKED by egress policy: {host} is hostile. Re-call with "
                                      "passive=true or proxy='<cidr>'.")}
    base = [os.path.join("WebPivot", "tools", "pivot_extract.py"), url, "--pretty", "-o", out, "--save-dom", dom]
    if proxy:
        base += ["--proxy-range", proxy]
    if SMOKE:
        base += ["--no-enrich", "--no-whois"]                # cheap smoke only
    elif not NO_ARCHIVE:
        # EVIDENCE CAPTURE (default on): Wayback SPN snapshot + master evidence ledger, case-tagged.
        base += ["--archive-missing", "--master", "--case", case]
    screenshot_py = PY
    if SHOT and not SMOKE and not (hostile and not proxy):    # screenshot needs a browser
        base += ["--render", "--screenshot", shot]
        screenshot_py = RENDER_PY
    r = _run([screenshot_py, *base], timeout=300 if SHOT else 240)
    data = _load_json(out)
    if data is None:
        return {"host": host, "ok": False, "reused": False, "n_pivots": 0, "data": None, "dom": dom,
                "note": "", "error": f"pivot_extract failed for {host}: {(r.stderr or '')[-500:]}"}
    cf = (data.get("meta") or {}).get("cloudflare")            # Cloudflare interstitial? retry via browser/FS
    used = "direct"
    if cf and not SMOKE:
        if FLARESOLVERR:
            _run([PY, *base, "--solve-cf", "--flaresolverr", FLARESOLVERR], timeout=300)
            used = "flaresolverr"
        else:
            _run([RENDER_PY, *base, "--render"], timeout=300)
            used = "render(browser)"
        data = _load_json(out) or data
    _append_manifest(case, host, data, reused=False, dom_path=dom, shot_path=shot)
    walled = (data.get("meta") or {}).get("cloudflare")
    cfnote = f"  · CF {cf} → {used} ({'STILL WALLED' if walled else 'bypassed'})" if cf else ""
    archnote = "" if (SMOKE or NO_ARCHIVE) else "  · archived + logged"
    return {"host": host, "ok": True, "reused": False, "error": None, "dom": dom,
            "n_pivots": len(data.get("pivots", [])), "note": cfnote + archnote, "data": data}


def collect_many(seeds: list[str], case: str, *, hostile: bool = False,
                 max_workers: int = 8) -> list[dict[str, Any]]:
    """Fan collect_one across `seeds` concurrently (mechanical, no LLM) — the Phase-3 collector
    that scales to a big seed set without blowing one model session's context/turn budget."""
    results: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(collect_one, s, case, hostile=hostile): s for s in seeds}
        for fu in concurrent.futures.as_completed(futs):
            try:
                results.append(fu.result())
            except Exception as e:  # noqa: BLE001
                results.append({"host": _host(futs[fu]), "ok": False, "reused": False,
                                "n_pivots": 0, "error": str(e), "data": None})
    return results


def ingest(case: str) -> tuple[bool, str]:
    """Ingest a case's raw pivot JSON into the KB (sync). Run once after collect_many."""
    raw = os.path.join(ROOT, "cases", case, "raw")
    files = [os.path.join(raw, f) for f in os.listdir(raw)] if os.path.isdir(raw) else []
    if not files:
        return False, f"no raw pivot JSON in {raw}"
    r = _run([PY, os.path.join("tools", "kb", "ingest_webpivot.py"), "--kb", KB_DIR, *files])
    return r.returncode == 0, (r.stdout + r.stderr) or "ingested"


@tool(
    "fallback_probe",
    "LAST-RESORT probe — call this when pivot_extract returns ZERO/near-zero pivots or an "
    "empty-favicon/parked/NXDOMAIN page, i.e. WHOIS+FOFA+urlscan all came back empty. Never end "
    "a seed on a silent 'nothing found'. Keyless sweep of the corners that survive a dead front "
    "page: crt.sh certs (SAN-sibling domains = strongest same-owner link), the full Wayback "
    "capture TIMELINE (parked-today was often a live scam last year), archive.today mementos, "
    "ready-to-run search dorks, and the local KB (already known/attributed?). Returns a VERDICT: "
    "PIVOTABLE (a lead survived) or NO-PIVOT-YET (genuinely cold + explicit next steps).",
    {"domain": str},
    annotations=READONLY,
)
async def fallback_probe(args: dict[str, Any]) -> dict[str, Any]:
    r = _run([PY, os.path.join("tools", "fallback_probe.py"), _host(args["domain"]),
              "--kb", KB_DIR], timeout=120)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "probe produced no output"}],
            "is_error": r.returncode != 0}


@tool(
    "kb_ingest",
    "Ingest a case's raw pivot JSON into the knowledge base so it becomes correlatable. "
    "Run this after pivot_extract; a run that isn't ingested is invisible to correlation.",
    {"case": str},
)
async def kb_ingest(args: dict[str, Any]) -> dict[str, Any]:
    ok, msg = ingest(args["case"])
    if not ok and msg.startswith("no raw"):
        return _err(msg)
    return {"content": [{"type": "text", "text": msg or "ingested"}], "is_error": not ok}


# ---------------------------------------------------------------- ANALYZE tools
@tool(
    "kb_cluster",
    "Peers of ONE domain — the domains sharing an indicator with it (its cluster neighborhood). "
    "PREFER this over kb_query_shared: it returns only the seed's subgraph, not the whole KB, so "
    "it is far cheaper.",
    {"domain": str},
    annotations=READONLY,
)
async def kb_cluster(args: dict[str, Any]) -> dict[str, Any]:
    r = _run([PY, os.path.join("tools", "kb", "query.py"),
              "--kb", KB_DIR, "--cluster", _host(args["domain"])])
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no peers"}],
            "is_error": r.returncode != 0}


@tool(
    "kb_entity",
    "One entity's facts + edges + provenance (a domain, email, indicator, or operator). "
    "A focused lookup — cheaper than dumping the whole KB.",
    {"value": str},
    annotations=READONLY,
)
async def kb_entity(args: dict[str, Any]) -> dict[str, Any]:
    r = _run([PY, os.path.join("tools", "kb", "query.py"),
              "--kb", KB_DIR, "--entity", args["value"]])
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no record"}],
            "is_error": r.returncode != 0}


@tool(
    "kb_query_shared",
    "The WHOLE-KB view: every indicator shared by >= min domains. LARGE/expensive — use only when "
    "you need the global picture; prefer kb_cluster/kb_entity for a specific seed. Read-only.",
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
    "cert_overlap",
    "TLS certificate / SAN-overlap check across 2+ domains (comma-separated in `domains`) — a "
    "CORRELATION signal. Two domains sharing a TLS cert is near-decisive same-operator proof: SAN "
    "names are chosen by whoever controls the cert. Keyless dual-source CT (Shodan CTL + crt.sh). "
    "Returns a VERDICT: SHARED-CERT / SAN cross-cover (decisive), SIBLING-OVERLAP (certs share a "
    "third registrable domain = strong), or NO-CT-OVERLAP. Run this on candidate same-operator "
    "seeds before asserting a cluster — it either corroborates or refutes at the TLS layer.",
    {"domains": str},
    annotations=READONLY,
)
async def cert_overlap(args: dict[str, Any]) -> dict[str, Any]:
    doms = [d.strip() for d in str(args["domains"]).replace(",", " ").split() if d.strip()]
    if len({_host(d) for d in doms}) < 2:
        return _err("cert_overlap needs at least two distinct domains (comma-separated).")
    r = _run([PY, os.path.join("tools", "cert_overlap.py"), *doms], timeout=120)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


@tool(
    "reference_check",
    "Check a hash/keyword against the curated fingerprint reference BEFORE trusting it as a "
    "same-operator link. Returns BENIGN (a globally common logo/CDN/CSS-framework artifact — a "
    "FALSE POSITIVE, do NOT cluster on it), SIGNAL (a distinctive fingerprint from a prior case — "
    "pivot on it, and see which case), or UNKNOWN. Pass the indicator string (e.g. favicon:123, "
    "css_hash:ab12, urlscan_resource:<h>) or a keyword. Read-only.",
    {"value": str},
    annotations=READONLY,
)
async def reference_check(args: dict[str, Any]) -> dict[str, Any]:
    val = str(args["value"])
    chk = _run([PY, os.path.join("tools", "kb", "reference.py"), "--kb", KB_DIR, "check", val])
    srch = _run([PY, os.path.join("tools", "kb", "reference.py"), "--kb", KB_DIR, "search", val])
    return _ok((chk.stdout or chk.stderr or "").rstrip() + "\n--- related reference entries ---\n"
               + (srch.stdout or "").rstrip())


@tool(
    "reference_add",
    "Remember a fingerprint in the reference so it improves every future case. Use verdict="
    "'benign' when a hash/keyword turned out to be a common logo / CDN / CSS-framework / template "
    "default (it will be SUPPRESSED from clustering everywhere), or verdict='signal' for a "
    "distinctive hash/keyword worth watching for (a watchlist tied to this case). Give a short "
    "label; pass the case so signal provenance is kept.",
    {"value": str, "verdict": str, "label": str},  # optional: case, note, type via args.get
)
async def reference_add(args: dict[str, Any]) -> dict[str, Any]:
    verdict = str(args.get("verdict", "")).lower()
    if verdict not in ("benign", "signal"):
        return _err("verdict must be 'benign' or 'signal'.")
    cmd = [PY, os.path.join("tools", "kb", "reference.py"), "--kb", KB_DIR, "add",
           "--value", str(args["value"]), "--verdict", verdict,
           "--label", str(args.get("label", ""))]
    if args.get("case"):
        cmd += ["--case", str(args["case"])]
    if args.get("note"):
        cmd += ["--note", str(args["note"])]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "added"}],
            "is_error": r.returncode != 0}


@tool(
    "which_cases",
    "Cross-case provenance: given a domain OR an indicator string (favicon:<h>, ga:<id>, "
    "wallet:<coin>:<addr>, email:<addr>, social:<net>:<handle>), report which CASE(S) it already "
    "appears in across the cases/ store. Call this before pivoting on a known artifact — a hit "
    "means it carries prior case context (don't treat it as new); an indicator seen across "
    "MULTIPLE cases is a cross-case link worth surfacing. Read-only.",
    {"artifact": str},
    annotations=READONLY,
)
async def which_cases(args: dict[str, Any]) -> dict[str, Any]:
    r = _run([PY, os.path.join("tools", "case_index.py"), str(args["artifact"])])
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


@tool(
    "domain_verdict",
    "The PRIOR verdict for a domain already in the store: which CASE(S) it appears in, who it's "
    "attributed to (operator registry) + its known KB facts/edges. Call this before treating a "
    "seed as new — if it's already resolved or belongs to a known case, show that instead of "
    "re-investigating.",
    {"domain": str},
    annotations=READONLY,
)
async def domain_verdict(args: dict[str, Any]) -> dict[str, Any]:
    d = _host(args["domain"])
    op = _run([PY, os.path.join("tools", "kb", "operator_registry.py"), "find", d])
    kb = _run([PY, os.path.join("tools", "kb", "query.py"), "--kb", KB_DIR, "--entity", d])
    ci = _run([PY, os.path.join("tools", "case_index.py"), d])
    verdict = (op.stdout or "").strip() or "not attributed to any known operator"
    facts = (kb.stdout or "").strip() or "no KB record for this domain"
    cases = (ci.stdout or "").strip() or f"{d} (domain): NOT seen in any existing case."
    collected = bool(_find_cached_raw(d))
    return _ok(f"VERDICT for {d}  (pivot data on file: {'yes' if collected else 'no'})\n"
               f"[cases] {cases}\n[operator] {verdict}\n[KB] {facts[:3000]}")


@tool(
    "api_usage",
    "Report LICENSED/metered API credit usage (FOFA, urlscan, WhoisXML, IPinfo, Shodan) from the "
    "ledger every collection writes. Pass case=<ID> to scope to one case, since=YYYY-MM-DD to bound "
    "by date, last=<N> to also list the most recent calls. Shows credits per provider / day / case. "
    "Read-only — use it to answer 'how many credits did this case/run cost'.",
    {},   # all optional: case, since (str), last (int) via args.get()
    annotations=READONLY,
)
async def api_usage(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("WebPivot", "tools", "api_usage.py"), "report"]
    if args.get("case"):
        cmd += ["--case", str(args["case"])]
    if args.get("since"):
        cmd += ["--since", str(args["since"])]
    if args.get("last"):
        cmd += ["--last", str(int(args["last"]))]
    r = _run(cmd)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


# ---------------------------------------------------------------- RENDER tools
@tool(
    "render_diagram",
    "Turn a graph_build.py case_graph.json into an EDITABLE Mermaid diagram source (.mmd) and "
    "render it to PNG + SVG (+ thumb) via IntelGraph. Use this when you want the relationship web "
    "as a static, hand-editable figure to drop into a report — unlike render_network.py's opaque "
    "interactive HTML, the .mmd is plain text you can tweak (rename a cluster, prune a node) and "
    "re-render. Faithful encoding: node shape = entity type, node fill = Louvain cluster, operator "
    "= red anchor, edge color = evidence class (operator/kit/infra/link), dashed = inferred. "
    "Required: graph_json (path), stem (output path, no extension). Optional: title, direction "
    "(LR|TB|RL|BT), legend=true (append an edge-color legend), no_render=true (emit only the .mmd).",
    {"graph_json": str, "stem": str},
)
async def render_diagram(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("IntelGraph", "scripts", "graph_to_diagram.py"),
           str(args["graph_json"]), str(args["stem"])]
    if args.get("title"):
        cmd += ["--title", str(args["title"])]
    if args.get("direction"):
        cmd += ["--direction", str(args["direction"])]
    if args.get("legend"):
        cmd += ["--legend"]
    if args.get("no_render"):
        cmd += ["--no-render"]
    r = _run(cmd, timeout=180)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


@tool(
    "render_report",
    "Render an assessment MARKDOWN file into a polished PDF and/or DOCX via pandoc, using the "
    "IntelReport house style (muted editorial palette matching IntelGraph, cover page, TOC, running "
    "header/footer with the classification + case id, embedded figures, Vietnamese-safe fonts). No "
    "analyst name is ever stamped; date defaults to UTC today. Title/case-id/classification/subtitle "
    "are read from the markdown's YAML frontmatter unless overridden. Required: markdown (path), stem "
    "(output path, no extension). Optional: title, subtitle, case_id, classification (e.g. TLP:AMBER), "
    "date (YYYY-MM-DD), pdf=true / docx=true (default: both). Embed IntelGraph figures with a normal "
    "markdown image whose path is resolvable from the markdown file's directory.",
    {"markdown": str, "stem": str},
)
async def render_report(args: dict[str, Any]) -> dict[str, Any]:
    cmd = [PY, os.path.join("IntelReport", "scripts", "render_report.py"),
           str(args["markdown"]), str(args["stem"])]
    for k, flag in (("title", "--title"), ("subtitle", "--subtitle"),
                    ("case_id", "--case-id"), ("classification", "--classification"),
                    ("date", "--date")):
        if args.get(k):
            cmd += [flag, str(args[k])]
    if args.get("pdf"):
        cmd += ["--pdf"]
    if args.get("docx"):
        cmd += ["--docx"]
    r = _run(cmd, timeout=300)
    return {"content": [{"type": "text", "text": r.stdout or r.stderr or "no output"}],
            "is_error": r.returncode != 0}


# ---------------------------------------------------------------- servers + names
COLLECT_SERVER = create_sdk_mcp_server("collect", tools=[pivot_extract, fallback_probe, kb_ingest])
ANALYZE_SERVER = create_sdk_mcp_server(
    "analyze", tools=[kb_cluster, kb_entity, kb_query_shared, risk_signals,
                      reverse_whois, cert_overlap, reference_check, reference_add,
                      which_cases, domain_verdict, api_usage,
                      render_diagram, render_report])

COLLECT_TOOLS = ["mcp__collect__pivot_extract", "mcp__collect__fallback_probe",
                 "mcp__collect__kb_ingest"]
ANALYZE_TOOLS = ["mcp__analyze__kb_cluster", "mcp__analyze__kb_entity",
                 "mcp__analyze__kb_query_shared", "mcp__analyze__risk_signals",
                 "mcp__analyze__reverse_whois", "mcp__analyze__cert_overlap",
                 "mcp__analyze__reference_check", "mcp__analyze__reference_add",
                 "mcp__analyze__which_cases", "mcp__analyze__domain_verdict",
                 "mcp__analyze__api_usage",
                 "mcp__analyze__render_diagram", "mcp__analyze__render_report"]
