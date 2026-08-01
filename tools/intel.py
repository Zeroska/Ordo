#!/usr/bin/env python3
"""
intel.py — one deterministic command that turns a domain list into a persisted case.

Orchestrates the existing tools (it reimplements nothing) so a case is produced the SAME
way every time and always lands on disk:

    python3 tools/intel.py open <case> domains.txt

    cases/<case>/raw/<host>.json     one pivot_extract JSON per host (overwrites on re-run)
    knowledge/                        ingested (idempotent) so IntelAnalysis can reason
    cases/<case>/shared.txt           the --shared cluster seeds, saved not just printed
    cases/<case>/case_graph.json      + network.html   (unless --no-graph)

Runs from anywhere: all tool paths are resolved from this file's location, not the CWD.
Zero third-party dependencies — stdlib + the repo's own tools.

Subcommands:
    open <case> <domains-file>   full pipeline (extract -> ingest -> shared [-> graph])
    status <case>                audit an existing case: which hosts have raw JSON / are in KB

Common flags for `open`:
    --jobs N            parallel extractions (default 4; archive.org rate-limits above ~4)
    --whois-reverse     run reverse-WHOIS live during extraction (costs WhoisXML credits)
    --render            also build + render the interactive network graph
    --no-graph          skip the graph build entirely (default: build case_graph.json)
    --operator NAME     operator persona node for the graph
    --operator-links a.com,b.com   domains tied to that operator
    --min N             --shared threshold (default 2)
    --timeout S         per-fetch timeout (default 20)
"""
import argparse
import concurrent.futures as cf
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)                          # intelligence_assist project root
WP = os.path.join(ROOT, "WebPivot", "tools")
KB_TOOLS = os.path.join(ROOT, "tools", "kb")
KB = os.path.join(ROOT, "knowledge")
# confirmed-operator registry (git-ignored, lives under knowledge/). The LEARN step of an
# investigation appends to it; `open` reads it so a new case inherits prior attributions.
OPERATORS = os.path.join(KB, "operators.jsonl")

# IntelGraph scripts: repo copy first, then the installed skill symlink
_GRAPH_CANDIDATES = [
    os.path.join(ROOT, "IntelGraph", "scripts"),
    os.path.expanduser("~/.claude/skills/IntelGraph/scripts"),
]
GRAPH = next((p for p in _GRAPH_CANDIDATES if os.path.isdir(p)), _GRAPH_CANDIDATES[0])


def _host(raw):
    """Bare hostname for a domain/URL line: no scheme, no path, no trailing dot."""
    s = raw.strip()
    s = re.sub(r"^\w+://", "", s)
    s = s.split("/", 1)[0].split("?", 1)[0].strip().rstrip(".")
    return s.lower()


def _load_env():
    """Load project .env into os.environ so child tools see the API keys (env still wins)."""
    p = os.path.join(ROOT, ".env")
    if not os.path.isfile(p):
        return
    for line in open(p, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k, v = k.strip(), v.strip().strip('"').strip("'")
        os.environ.setdefault(k, v)   # don't clobber a real exported key


def _read_domains(path):
    if not os.path.isfile(path):
        sys.exit(f"domains file not found: {path}")
    seen, out = set(), []
    for line in open(path, encoding="utf-8"):
        h = _host(line.replace("\r", ""))
        if h and not h.startswith("#") and h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _run(cmd, **kw):
    return subprocess.run(cmd, **kw)


def _load_operators():
    """Read the confirmed-operator registry (git-ignored). Returns domain -> [operator,…]."""
    import json
    dom2op = {}
    if not os.path.isfile(OPERATORS):
        return dom2op
    for line in open(OPERATORS, encoding="utf-8"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rec = json.loads(line)
        except Exception:
            continue
        op = rec.get("operator") or rec.get("name")
        for d in rec.get("domains", []):
            if op:
                dom2op.setdefault(_host(d), []).append(op)
    return dom2op


def _prior_overlap(hosts, min_shared=1):
    """LEARN-FROM-THE-PAST: after ingest, surface which of this case's seeds already
    connect — through a shared indicator in the KB — to domains from PRIOR work, and to
    any confirmed operator in the registry. This is the auto-correlation payoff made visible
    (it was previously latent in shared.txt). Zero web I/O — pure KB read.
    """
    sys.path.insert(0, KB_TOOLS)
    try:
        from knowledge_base import KB as _KB  # noqa: E402
    except Exception as e:
        print(f"   note: prior-overlap check skipped ({e})")
        return
    kb = _KB(KB)
    seeds = {h.lower() for h in hosts}
    edges = kb.edges()
    # indicator (type,value) -> set(domains that use it)
    ind_domains = {}
    for e in edges:
        if e["src_type"] == "domain" and e["dst_type"] in ("indicator", "email", "person", "org"):
            ind_domains.setdefault((e["dst_type"], e["dst"]), set()).add(e["src"].lower())
    # for each seed, the prior (non-seed) domains it shares an indicator with, and via what
    prior_peers = {}     # peer_domain -> set("kind:value")
    for (dt, dv), doms in ind_domains.items():
        if not (seeds & doms):
            continue
        for peer in doms - seeds:
            prior_peers.setdefault(peer, set()).add(dv if ":" in str(dv) else f"{dt}:{dv}")

    dom2op = _load_operators()
    hit_ops = {}
    for peer in prior_peers:
        for op in dom2op.get(peer, []):
            hit_ops.setdefault(op, set()).add(peer)

    print("\n== prior-knowledge overlap (does this case connect to what we already know?) ==")
    if not prior_peers:
        print("   none — these seeds share no KB indicator with any previously-seen domain (new cluster).")
        return
    if hit_ops:
        print("   ⚠ CONFIRMED-OPERATOR MATCH:")
        for op, doms in sorted(hit_ops.items(), key=lambda x: -len(x[1])):
            print(f"      • {op}  (via {len(doms)} known domain(s): {', '.join(sorted(doms)[:5])}"
                  + (" …" if len(doms) > 5 else "") + ")")
    strong = [(p, v) for p, v in prior_peers.items() if len(v) >= min_shared]
    print(f"   {len(strong)} prior domain(s) share an indicator with this case's seeds:")
    for peer, via in sorted(strong, key=lambda x: -len(x[1]))[:15]:
        tag = f"  [{', '.join(dom2op[peer])}]" if peer in dom2op else ""
        print(f"      {peer}{tag}  via {len(via)}: {', '.join(sorted(via)[:4])}"
              + (" …" if len(via) > 4 else ""))
    if len(strong) > 15:
        print(f"      … and {len(strong) - 15} more (see shared.txt for the full cluster).")


def _extract_one(host, case_dir, timeout, whois_reverse, fofa_full=False, render=False,
                 free_only=False):
    """Extract one host into raw/<host>.json. Returns (host, ok, note)."""
    out_file = os.path.join(case_dir, "raw", f"{host}.json")
    cmd = [sys.executable, os.path.join(WP, "pivot_extract.py"),
           f"https://{host}", "--pretty", "--timeout", str(timeout), "-o", out_file]
    if free_only:
        cmd.append("--free-only")   # keyless-only enrichment — the autonomous loop spends no credits
    if whois_reverse:
        cmd.append("--whois-reverse")
    if fofa_full:
        cmd.append("--fofa-full")   # FOFA reverses over all historical data (full=true)
    if render:
        cmd.append("--render")      # post-JS DOM — unlocks SaaS/analytics tokens

    def attempt():
        r = _run(cmd, capture_output=True, text=True)
        # a "miss" = no file, or extraction produced no host (rate-limit / dead site)
        if not os.path.isfile(out_file):
            return False
        import json
        try:
            data = json.load(open(out_file, encoding="utf-8"))
        except Exception:
            return False
        return bool((data.get("meta") or {}).get("host"))

    if attempt():
        return (host, True, "ok")
    if attempt():                       # one retry (archive.org / transient rate-limit)
        return (host, True, "ok (retry)")
    return (host, False, "no host extracted (rate-limit / unreachable)")


def _risk_signals(raw_files):
    """Score each freshly-collected host for NRD / BPH / money-trail. Pure local read."""
    sys.path.insert(0, KB_TOOLS)
    try:
        import json as _json
        import risk_signals as _rs  # noqa: E402
    except Exception as e:
        print(f"   note: risk-signals check skipped ({e})")
        return
    print("\n== scam red-flags (newly-registered / bulletproof-hosting / money-trail) ==")
    esc = []
    for rf in sorted(raw_files):
        try:
            s = _rs.score_domain(_json.load(open(rf, encoding="utf-8")))
        except Exception:
            continue
        print(_rs._fmt(s))
        if s.get("escalate"):
            esc.append(s)
    if esc:
        print("   ⚠ escalate: " +
              "; ".join(f"{s['host']}[{','.join(s['escalate'])}]" for s in esc[:10]))


def cmd_open(a):
    _load_env()
    case_dir = os.path.join(ROOT, "cases", a.case)
    os.makedirs(os.path.join(case_dir, "raw"), exist_ok=True)
    hosts = _read_domains(a.domains)
    if not hosts:
        sys.exit("no domains to process")

    print(f"== intel: case '{a.case}' — {len(hosts)} host(s), jobs={a.jobs} ==")
    if not os.environ.get("WHOISXML_API_KEY"):
        print("   note: WHOISXML_API_KEY not set — WHOIS registrant spine will be empty.")

    # 1) extract (parallel) --------------------------------------------------
    ok, failed = [], []
    with cf.ThreadPoolExecutor(max_workers=max(1, a.jobs)) as ex:
        futs = {ex.submit(_extract_one, h, case_dir, a.timeout, a.whois_reverse,
                          a.fofa_full, a.render_extract): h
                for h in hosts}
        for fut in cf.as_completed(futs):
            host, good, note = fut.result()
            print(f"   [{'ok ' if good else 'MISS'}] {host}  {note}")
            (ok if good else failed).append(host)

    raw_glob = os.path.join(case_dir, "raw")
    raw_files = [os.path.join(raw_glob, f) for f in os.listdir(raw_glob) if f.endswith(".json")]
    if not raw_files:
        sys.exit("no raw JSON produced — nothing to ingest.")

    # 2) ingest into the KB (idempotent) ------------------------------------
    print(f"== ingesting {len(raw_files)} raw file(s) into {os.path.relpath(KB, ROOT)} ==")
    _run([sys.executable, os.path.join(KB_TOOLS, "ingest_webpivot.py"),
          "--kb", KB, *raw_files])

    # 2.5) prior-knowledge overlap — surface cross-case learning, not just latent in shared.txt
    _prior_overlap(hosts)

    # 2.6) scam red-flag signals — NRD / bulletproof-hosting / money-trail per seed
    _risk_signals(raw_files)

    # 3) shared cluster seeds — saved to the case, not just printed ----------
    shared_path = os.path.join(case_dir, "shared.txt")
    print(f"== cluster seeds (--shared --min {a.min}) -> {os.path.relpath(shared_path, ROOT)} ==")
    r = _run([sys.executable, os.path.join(KB_TOOLS, "query.py"),
              "--kb", KB, "--shared", "--min", str(a.min)],
             capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    with open(shared_path, "w", encoding="utf-8") as fh:
        fh.write(r.stdout)

    # 4) graph (default on; --no-graph to skip) -----------------------------
    graph_json = os.path.join(case_dir, "case_graph.json")
    if not a.no_graph:
        print(f"== building case graph -> {os.path.relpath(graph_json, ROOT)} ==")
        gcmd = [sys.executable, os.path.join(WP, "graph_build.py"), *raw_files, "-o", graph_json]
        if a.operator:
            gcmd += ["--operator", a.operator]
        if a.operator_links:
            gcmd += ["--operator-links", a.operator_links]
        _run(gcmd)
        if a.render:
            net_html = os.path.join(case_dir, "network.html")
            rn = os.path.join(GRAPH, "render_network.py")
            if os.path.isfile(rn):
                print(f"== rendering -> {os.path.relpath(net_html, ROOT)} ==")
                _run([sys.executable, rn, graph_json, net_html,
                      "--title", f"Case: {a.case}"])
            else:
                print(f"   note: render_network.py not found at {rn}; skipped --render.")

    # 5) cluster intelligence assessment (ICD-203) -> cases/<case>/assessment.md
    if not a.no_report:
        assess_path = os.path.join(case_dir, "assessment.md")
        print(f"== rendering ICD-203 cluster assessment -> {os.path.relpath(assess_path, ROOT)} ==")
        try:
            sys.path.insert(0, WP)
            import evidence_report
            import json as _json
            results = []
            for rf in raw_files:
                try:
                    results.append(_json.load(open(rf, encoding="utf-8")))
                except Exception:
                    pass
            md = evidence_report.render_cluster_report(
                results, case=a.case, analyst=a.analyst,
                classification=a.classification)
            with open(assess_path, "w", encoding="utf-8") as fh:
                fh.write(md)
        except Exception as e:
            print(f"   note: assessment render failed ({e}); skipped.")

    # 6) completeness summary (stable output is auditable) ------------------
    print("\n== summary ==")
    print(f"   extracted: {len(ok)}/{len(hosts)}   raw files: {len(raw_files)}")
    if failed:
        print(f"   MISSES ({len(failed)}) — re-run these: {', '.join(failed)}")
    print(f"   case dir : {os.path.relpath(case_dir, ROOT)}/  (raw/, shared.txt"
          + ("" if a.no_graph else ", case_graph.json")
          + (", network.html" if a.render and not a.no_graph else "") + ")")
    print(f"   next     : IntelAnalysis over knowledge/ -> knowledge/reports/{a.case}/assessment.md")


def _all_raw(case_dir):
    d = os.path.join(case_dir, "raw")
    return [os.path.join(d, f) for f in os.listdir(d) if f.endswith(".json")] if os.path.isdir(d) else []


def _ingest_case(raw_files):
    _run([sys.executable, os.path.join(KB_TOOLS, "ingest_webpivot.py"), "--kb", KB, *raw_files])


def _write_shared(case_dir, min_shared):
    """(re)compute the --shared cluster seeds into shared.txt (persisted, not just printed)."""
    r = _run([sys.executable, os.path.join(KB_TOOLS, "query.py"),
              "--kb", KB, "--shared", "--min", str(min_shared)], capture_output=True, text=True)
    with open(os.path.join(case_dir, "shared.txt"), "w", encoding="utf-8") as fh:
        fh.write(r.stdout or "")


_DOMAIN_RE = re.compile(r'\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,})\b', re.I)


def _domains_in_text(s):
    """Domain-like tokens in a free-text string (for reading an analyst's next_pivots / gaps)."""
    return {m.group(1).lower().rstrip(".") for m in _DOMAIN_RE.finditer(s or "")}


def _render_assessment(case_dir, case, raw_files, fr, verdict, a):
    """Write the human ICD-203 assessment.md, and a machine-readable assessment.json that conforms to
    the SAME schema the SDK/IntelAnalysis path uses (bluf, cluster, attribution_level, confidence,
    evidence, gaps, next_pivots[str]) — loop-specific detail lives under an additive `loop` key.

    CONSISTENCY: if assessment.json was written by the ANALYST / SDK (not this loop), we do NOT
    overwrite it — we READ its next_pivots + gaps for domain leads and fold them into the frontier
    (the "read assessment.json, fill the gaps" chain). Returns that set of analyst-named leads."""
    import json as _json
    results = []
    for rf in raw_files:
        try:
            results.append(_json.load(open(rf, encoding="utf-8")))
        except Exception:
            pass
    try:
        sys.path.insert(0, WP)
        import evidence_report
        md = evidence_report.render_cluster_report(
            results, case=case, analyst=a.analyst, classification=a.classification)
        with open(os.path.join(case_dir, "assessment.md"), "w", encoding="utf-8") as fh:
            fh.write(md)
    except Exception as e:
        print(f"   note: assessment.md render failed ({e}); skipped.")

    apath = os.path.join(case_dir, "assessment.json")
    existing = None
    if os.path.isfile(apath):
        try:
            existing = _json.load(open(apath, encoding="utf-8"))
        except Exception:
            existing = None
    # read analyst-authored leads (any assessment.json — canonical strings) for the chain
    analyst_leads = set()
    if existing:
        for s in list(existing.get("next_pivots") or []) + list(existing.get("gaps") or []):
            analyst_leads |= _domains_in_text(str(s))

    cluster = []
    sp = os.path.join(case_dir, "shared.txt")
    if os.path.isfile(sp):
        cluster = [l.strip() for l in open(sp, encoding="utf-8") if l.strip() and not l.startswith("#")][:100]
    gaps = []
    if fr["candidate_total"]:
        gaps.append(f"{fr['candidate_total']} discovered apex(es) not yet collected "
                    f"(next {len(fr['pending'])} queued): {', '.join(fr['pending'][:10])}")
    if fr["metered_leads"]:
        gaps.append(f"{len(fr['metered_leads'])} metered pivot(s) deferred for analyst approval "
                    f"(FOFA/WhoisXML) — would spend credits.")
    if verdict["verdict"] == "CONVERGED":
        gaps.append("Free frontier exhausted / no new growth — cluster looks converged.")
    collected = sorted({(r.get("meta") or {}).get("host") for r in results if (r.get("meta") or {}).get("host")})
    # canonical next_pivots as STRINGS (schema parity); structured detail kept under loop.frontier
    next_pivots = [f"collect {ap} (via {', '.join(fr['candidates'].get(ap, {}).get('sources', []))}) — free"
                   for ap in fr["pending"]]
    next_pivots += [f"[metered — approve first] {ml['service']} {ml['query']} — {ml['why']}"
                    for ml in fr["metered_leads"]]
    doc = {
        "bluf": (f"Deterministic convergence loop, round {fr['round']}: {len(collected)} host(s) "
                 f"collected, {verdict['verdict'].lower()}; {len(fr['pending'])} free lead(s) pending, "
                 f"{len(fr['metered_leads'])} metered deferred. Attribution pending IntelAnalysis judgment."),
        "cluster": [{"domain": h, "shared_artifacts": []} for h in collected],
        "attribution_level": "inconclusive",   # the mechanical loop never attributes — IntelAnalysis does
        "confidence": "low",
        "evidence": [f"convergence: {verdict['verdict']} ({verdict.get('rounds', 0)} round(s))",
                     f"{len(cluster)} shared cluster seed(s) recorded in shared.txt"],
        "gaps": gaps,
        "next_pivots": next_pivots,
        "_generator": "intel-loop",
        "loop": {
            "round": fr["round"], "generated": _iso_now(), "convergence": verdict,
            "collected": collected, "cluster_shared": cluster,
            "frontier": [{"seed": ap, "why": fr["candidates"].get(ap, {}).get("sources", []),
                          "cost": "free"} for ap in fr["pending"]],
            "metered_leads": fr["metered_leads"],
            "assessment_md": os.path.relpath(os.path.join(case_dir, "assessment.md"), ROOT),
        },
    }
    # only (over)write assessment.json when it is absent or loop-authored — never clobber the analyst's
    if not existing or existing.get("_generator") == "intel-loop":
        with open(apath, "w", encoding="utf-8") as fh:
            _json.dump(doc, fh, indent=2, ensure_ascii=False)
    else:
        # analyst assessment present — keep it; drop the loop view in a sidecar so nothing is lost
        with open(os.path.join(case_dir, "loop_assessment.json"), "w", encoding="utf-8") as fh:
            _json.dump(doc, fh, indent=2, ensure_ascii=False)
        print("   analyst assessment.json present — not overwritten; loop view -> loop_assessment.json")
    return analyst_leads


def _iso_now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def cmd_loop(a):
    """Resumable convergence feedback loop: collect (free-only WebPivot) -> ingest -> snapshot ->
    assess (md+json) -> chase the discovered free frontier -> repeat until CONVERGED, cold (no free
    frontier left), or the round cap (awaiting-analyst). Checkpoints cases/<case>/state.json every
    round, so an interrupt resumes and a cold case re-mines against the current KB on re-run."""
    _load_env()
    import case_state as cs
    case = a.case
    case_dir = os.path.join(ROOT, "cases", case)
    os.makedirs(os.path.join(case_dir, "raw"), exist_ok=True)

    st = cs.load_state(case)
    st["depth_limit"] = a.max_rounds
    # seed the pending queue: a domains file or a comma list, merged (first run or added evidence)
    if a.seeds:
        if os.path.isfile(a.seeds):
            new = _read_domains(a.seeds)
        else:
            new = [_host(x) for x in a.seeds.split(",") if _host(x)]
        have = {h.lower() for h in st.get("pending", [])} | {h.lower() for h in st.get("consumed", [])}
        for h in new:
            if h not in have:
                st.setdefault("pending", []).append(h)
        if st.get("status") in ("converged", "cold"):
            st["status"] = "expanding"          # new evidence reopens a finished case
    # reconcile against ground truth on disk (robust to a mid-round interrupt)
    collected = cs.collected_hosts(case_dir)
    st["collected"] = sorted(collected)
    st["pending"] = [h for h in st.get("pending", []) if h.lower() not in collected]
    if not st["pending"] and not collected:
        sys.exit("no seeds — first run needs a domains file or comma list: "
                 "intel.py loop <case> seeds.txt")
    cs.save_state(case, st)

    print(f"== intel loop: case '{case}' — status={st['status']}, "
          f"{len(collected)} collected, {len(st['pending'])} pending, max {a.max_rounds} round(s) ==")

    for _ in range(a.max_rounds):
        # replenish the queue from the discovered free frontier when empty
        if not st["pending"]:
            fr = cs.frontier(case, max_new=a.max_new)
            st["pending"] = fr["pending"]
            st["metered_leads"] = fr["metered_leads"]
            if not st["pending"]:
                st["status"] = "cold"
                cs.save_state(case, st)
                print("   frontier empty — no free leads left. status=cold.")
                break
        batch = st["pending"]
        st["pending"] = []
        st["round"] += 1
        print(f"\n-- round {st['round']}: collecting {len(batch)} host(s) (free-only): "
              f"{', '.join(batch[:8])}{' …' if len(batch) > 8 else ''}")

        # 1) collect (parallel, FREE-ONLY — no metered credits) ---------------
        ok, failed = [], []
        with cf.ThreadPoolExecutor(max_workers=max(1, a.jobs)) as ex:
            futs = {ex.submit(_extract_one, h, case_dir, a.timeout, False, False, a.render_extract,
                              True): h for h in batch}
            for fut in cf.as_completed(futs):
                host, good, note = fut.result()
                print(f"   [{'ok ' if good else 'MISS'}] {host}  {note}")
                (ok if good else failed).append(host)
        for h in batch:                              # consumed even on miss (don't re-queue a dead host)
            if h.lower() not in {c.lower() for c in st["consumed"]}:
                st["consumed"].append(h.lower())

        raw_files = _all_raw(case_dir)
        # 2) ingest whole case (idempotent), 3) refresh shared cluster seeds --
        _ingest_case(raw_files)
        _write_shared(case_dir, a.min)
        # 4) convergence snapshot (convergence.py owns rounds.jsonl) ----------
        _run([sys.executable, os.path.join(KB_TOOLS, "convergence.py"), "snapshot", case])
        verdict = cs.convergence_verdict(case, stale=a.stale)
        # 5) compute the next free frontier + assess (md + json) -------------
        fr = cs.frontier(case, max_new=a.max_new)
        st["collected"] = sorted(cs.collected_hosts(case_dir))
        st["metered_leads"] = fr["metered_leads"]
        analyst_leads = _render_assessment(case_dir, case, raw_files, fr, verdict, a)
        st["history"].append({"round": st["round"], "collected": len(st["collected"]),
                              "new_hosts": verdict.get("new_hosts_recent"),
                              "verdict": verdict["verdict"], "ts": _iso_now()})
        # CHAIN: fold any domains the analyst named in assessment.json (next_pivots/gaps) into the
        # frontier — an analyst-directed lead outranks the mechanically-discovered ones.
        done = {c.lower() for c in st["consumed"]} | {h.lower() for h in st["collected"]}
        analyst_new = sorted(d for d in (analyst_leads or set()) if d.lower() not in done)
        if analyst_new:
            print(f"   + {len(analyst_new)} analyst-directed lead(s) from assessment.json: "
                  f"{', '.join(analyst_new[:6])}")
        print(f"   collected={len(st['collected'])}  convergence={verdict['verdict']}  "
              f"fresh-frontier={fr['candidate_total']}  metered-leads={len(fr['metered_leads'])}")

        # 6) stop conditions -------------------------------------------------
        #    analyst-directed leads keep the case alive even if the mechanical frontier converged.
        if verdict["verdict"] == "CONVERGED" and not analyst_new:
            st["status"] = "converged"
            cs.save_state(case, st)
            print(f"   CONVERGED after round {st['round']}. Stop; write the final assessment.")
            break
        st["pending"] = analyst_new + [h for h in fr["pending"] if h.lower() not in done]
        if not st["pending"]:
            st["status"] = "cold"
            cs.save_state(case, st)
            print("   no free frontier left. status=cold.")
            break
        cs.save_state(case, st)                       # checkpoint every round (resumable)
    else:
        # hit the round cap with free work still queued → paused for the analyst to resume/approve
        st["status"] = "awaiting-analyst" if st["pending"] else st["status"]
        cs.save_state(case, st)
        print(f"\n   reached max {a.max_rounds} round(s); status={st['status']} "
              f"(resume: intel.py loop {case} --max-rounds N).")

    print(f"\n== loop done: status={st['status']}, {len(st['collected'])} host(s), "
          f"{st['round']} round(s) ==")
    print(f"   assessment: cases/{case}/assessment.md  (+ assessment.json: gaps, next_pivots)")
    if st.get("metered_leads"):
        print(f"   ⚠ {len(st['metered_leads'])} metered lead(s) await approval — see "
              f"assessment.json → loop.metered_leads (would spend FOFA/WhoisXML credits).")
    print(f"   state: cases/{case}/state.json  (resume/reopen: intel.py loop {case}  |  "
          f"case_state.py reopen {case})")


def cmd_status(a):
    case_dir = os.path.join(ROOT, "cases", a.case)
    raw_dir = os.path.join(case_dir, "raw")
    if not os.path.isdir(raw_dir):
        sys.exit(f"no such case: {os.path.relpath(case_dir, ROOT)}")
    raw = sorted(f[:-5] for f in os.listdir(raw_dir) if f.endswith(".json"))
    print(f"case '{a.case}': {len(raw)} raw host file(s)")
    for h in raw:
        print(f"   raw  {h}")
    for extra in ("shared.txt", "case_graph.json", "network.html"):
        mark = "yes" if os.path.isfile(os.path.join(case_dir, extra)) else "MISSING"
        print(f"   {extra:16} {mark}")


def main():
    ap = argparse.ArgumentParser(description="Deterministic OSINT case pipeline over the repo tools.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    o = sub.add_parser("open", help="run the full extract->ingest->shared[->graph] pipeline")
    o.add_argument("case")
    o.add_argument("domains", help="file with one domain/URL per line")
    o.add_argument("--jobs", type=int, default=4)
    o.add_argument("--whois-reverse", action="store_true")
    o.add_argument("--fofa-full", action="store_true",
                   help="FOFA reverses over ALL historical data (full=true), not just ~1yr")
    o.add_argument("--render-extract", action="store_true",
                   help="render post-JS DOM per page (unlocks SaaS/analytics tokens; needs playwright)")
    o.add_argument("--render", action="store_true")
    o.add_argument("--no-graph", action="store_true")
    o.add_argument("--operator", default=None)
    o.add_argument("--operator-links", default=None)
    o.add_argument("--min", type=int, default=2)
    o.add_argument("--timeout", type=int, default=20)
    o.add_argument("--no-report", action="store_true",
                   help="skip the ICD-203 cluster assessment (default: write assessment.md)")
    o.add_argument("--analyst", default=None, help="analyst handle stamped on the assessment")
    o.add_argument("--classification", default="UNCLASSIFIED//FOR OFFICIAL USE ONLY",
                   help="classification banner for the assessment")
    o.set_defaults(func=cmd_open)

    lp = sub.add_parser("loop", help="resumable convergence feedback loop (collect→assess→chase gaps)")
    lp.add_argument("case")
    lp.add_argument("seeds", nargs="?", default=None,
                    help="first run / added evidence: a domains file OR a comma list (omit to resume)")
    lp.add_argument("--max-rounds", type=int, default=6, help="round cap before pausing (default 6)")
    lp.add_argument("--max-new", type=int, default=8, help="new frontier seeds collected per round")
    lp.add_argument("--stale", type=int, default=2,
                    help="consecutive zero-growth rounds that mean CONVERGED (default 2)")
    lp.add_argument("--jobs", type=int, default=4)
    lp.add_argument("--timeout", type=int, default=20)
    lp.add_argument("--render-extract", action="store_true",
                    help="render post-JS DOM per page (needs playwright)")
    lp.add_argument("--min", type=int, default=2, help="--shared cluster threshold")
    lp.add_argument("--analyst", default=None)
    lp.add_argument("--classification", default="UNCLASSIFIED//FOR OFFICIAL USE ONLY")
    lp.set_defaults(func=cmd_loop)

    s = sub.add_parser("status", help="audit an existing case's persisted outputs")
    s.add_argument("case")
    s.set_defaults(func=cmd_status)

    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
