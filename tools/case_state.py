#!/usr/bin/env python3
"""
case_state.py — resumable stage machine + gap/frontier extractor for the convergence loop.

WHY THIS EXISTS
---------------
A case is worked as a feedback loop: collect (WebPivot) -> assess (IntelAnalysis) -> read the
assessment -> chase the unresolved gaps back into WebPivot -> repeat until nothing new can be
collected for free or the analyst says stop. Two things were missing to run that loop safely and
resumably, and this module supplies exactly those two:

  1. A single per-case STATE file (`cases/<case>/state.json`) — the loop's stage/cursor: status
     (expanding / converged / cold / awaiting-analyst), round number, the pending/collected/consumed
     seed queues, deferred metered leads, and a compact history. An interrupt leaves this on disk, so
     the next run RESUMES instead of restarting; a cold/old case re-opened after new evidence lands
     re-mines its frontier against the CURRENT knowledge base and picks up cross-case breakthroughs.

  2. A FRONTIER extractor — the bridge nothing had before. It mines each collected `raw/*.json` for
     concrete NEW candidate domains already discovered *for free* during the round (crt.sh SAN
     siblings, passive-DNS co-hosted hosts, urlscan related domains, TLS co-SAN cross-apex, CORS
     trusted origins, impersonation lookalikes, and any reverse-WHOIS siblings a prior keyed run
     left behind), reduces them to new registrable apexes, drops shared-infra/noise, and dedupes
     against everything already collected/queued. Pivots that would need a METERED call to expand
     (FOFA ip=/icon_hash=, WhoisXML reverse) are NOT auto-run — they are recorded as `metered_leads`
     for analyst approval, honoring "auto-chase on free sources only; pause before spending credits."

This module is deterministic and side-effect-free except for reading/writing state.json; the round
loop that calls it lives in `tools/intel.py loop`. Convergence itself is delegated to the existing
`tools/kb/convergence.py` (single authority: it owns rounds.jsonl); here we only READ its verdict.

CLI:
  python3 tools/case_state.py status   <case>
  python3 tools/case_state.py frontier <case> [--max-new N] [--json]
  python3 tools/case_state.py reopen   <case> [seed ...]   # cold-case reopen (+ optional new seeds)
"""
import argparse
import glob
import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WP = os.path.join(ROOT, "WebPivot", "tools")
KB_TOOLS = os.path.join(ROOT, "tools", "kb")
for _p in (WP, KB_TOOLS):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# registrable-domain reducer — reuse WebPivot's so apex logic matches the collectors exactly.
try:
    from wp_common import _registrable  # noqa: E402
except Exception:
    def _registrable(host):
        parts = (host or "").strip(".").lower().split(".")
        # crude fallback (no PSL): keep last 2 labels, or 3 for common multi-part TLDs
        if len(parts) >= 3 and parts[-2] in ("com", "co", "org", "net", "gov", "edu"):
            return ".".join(parts[-3:])
        return ".".join(parts[-2:]) if len(parts) >= 2 else host

# noise / convergence helpers from the KB toolkit (best-effort — degrade gracefully)
try:
    import convergence as _conv  # tools/kb/convergence.py
except Exception:
    _conv = None
try:
    from whois_enrich import is_privacy as _is_privacy  # registrar/privacy-proxy filter
except Exception:
    def _is_privacy(_):
        return False

STATE_VERSION = 1

# Apexes that are shared infrastructure, CDNs, SaaS, or analytics — NEVER same-operator leads, so
# they must never enter the frontier (reversing/collecting them is pure noise). Kept deliberately
# small and generic; the per-indicator noise gate in convergence/ingest handles the long tail.
SHARED_INFRA = {
    "google.com", "googleapis.com", "gstatic.com", "googletagmanager.com", "google-analytics.com",
    "googleusercontent.com", "goog.gl", "youtube.com", "doubleclick.net", "recaptcha.net",
    "cloudflare.com", "cloudflare.net", "cloudflareinsights.com", "cdnjs.com", "jsdelivr.net",
    "unpkg.com", "jquery.com", "bootstrapcdn.com", "fontawesome.com", "amazonaws.com",
    "cloudfront.net", "azureedge.net", "akamai.net", "akamaihd.net", "akamaized.net", "fastly.net",
    "fbcdn.net", "facebook.com", "fb.com", "instagram.com", "twitter.com", "x.com", "t.co",
    "gravatar.com", "wp.com", "wordpress.org", "gstatic.cn", "bing.com", "microsoft.com",
    "office.com", "live.com", "windows.net", "sentry.io", "hotjar.com", "sedoparking.com",
    "wixpress.com", "wix.com", "squarespace.com", "shopify.com", "myshopify.com", "cdn.shopify.com",
    "gg.gg", "bit.ly", "linktr.ee", "gmail.com", "storage.googleapis.com",
}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _case_dir(case):
    return case if os.path.isdir(case) else os.path.join(ROOT, "cases", case)


def state_path(cdir):
    return os.path.join(cdir, "state.json")


def _fresh_state(case):
    return {
        "version": STATE_VERSION, "case": case, "created": _now(), "updated": _now(),
        "status": "expanding",          # expanding | converged | cold | awaiting-analyst | error
        "round": 0, "depth_limit": None,
        "collected": [], "pending": [], "consumed": [],
        "metered_leads": [], "history": [], "reopen_count": 0, "note": None,
    }


def load_state(case):
    cdir = _case_dir(case)
    p = state_path(cdir)
    if os.path.isfile(p):
        try:
            with open(p, encoding="utf-8") as fh:
                st = json.load(fh)
            st.setdefault("case", case)
            return st
        except Exception:
            pass
    return _fresh_state(case)


def save_state(case, st):
    cdir = _case_dir(case)
    os.makedirs(cdir, exist_ok=True)
    st["updated"] = _now()
    p = state_path(cdir)
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(st, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, p)          # atomic — an interrupt never leaves a half-written state.json
    return p


def collected_hosts(cdir):
    """Ground truth of what has actually been collected = the hosts on disk in raw/*.json.
    Used to reconcile state after a mid-round interrupt (raw/ is the real checkpoint)."""
    hosts = set()
    for path in glob.glob(os.path.join(cdir, "raw", "*.json")):
        try:
            with open(path, encoding="utf-8") as fh:
                obj = json.load(fh)
            h = (obj.get("meta") or {}).get("host") or os.path.basename(path)[:-5]
            if h:
                hosts.add(h.lower())
        except Exception:
            hosts.add(os.path.basename(path)[:-5].lower())
    return hosts


def _is_noise_apex(apex, seed_apexes):
    if not apex or "." not in apex:
        return True
    if apex in seed_apexes:            # the seed itself / its own subdomains — not a NEW lead
        return True
    if apex in SHARED_INFRA:
        return True
    # any label-suffix match against shared infra (e.g. foo.cloudfront.net -> cloudfront.net)
    return any(apex == d or apex.endswith("." + d) for d in SHARED_INFRA)


def _add_cand(cands, host, source, seed_apexes):
    """Reduce a discovered host to its registrable apex and record it as a free frontier candidate."""
    apex = _registrable((host or "").strip().lower().rstrip("."))
    if _is_noise_apex(apex, seed_apexes):
        return
    slot = cands.setdefault(apex, {"sources": set(), "examples": set()})
    slot["sources"].add(source)
    if host and host.lower() != apex:
        slot["examples"].add(host.lower())


def _free_candidates_from_raw(obj, cands, seed_apexes):
    """Mine one raw pivot_extract JSON for NEW registrable apexes discovered FOR FREE this round."""
    for piv in obj.get("pivots", []) or []:
        kind, val = piv.get("kind", ""), piv.get("value")
        # pivots whose VALUE is itself a co-domain / lookalike / trusted-origin host
        if kind in ("tls_cert:co_san", "cors_allowed_origin", "impersonation:candidate",
                    "urlscan_related_domain"):
            _add_cand(cands, str(val), kind.split(":")[0], seed_apexes)
        lr = piv.get("live_results") or {}
        if kind == "domain":
            crt = lr.get("crtsh") or {}
            for sd in crt.get("subdomains") or []:
                _add_cand(cands, sd, "crtsh_san", seed_apexes)
            for cert in crt.get("certs") or []:
                for nm in cert.get("names") or []:
                    _add_cand(cands, nm, "crtsh_san", seed_apexes)
            for h in (lr.get("passivedns") or {}).get("hosts") or []:
                _add_cand(cands, h.get("host") if isinstance(h, dict) else h, "passive_dns", seed_apexes)
            for d in (lr.get("urlscan") or {}).get("domains") or []:
                _add_cand(cands, d, "urlscan_related", seed_apexes)
            # co-hosted domains from a PRIOR keyed run (already paid for — reusing is free)
            for key in ("fofa_ip_reverse", "pdns_ip_reverse"):
                blk = lr.get(key) or {}
                for row in (blk.get("results") or blk.get("hosts") or []):
                    host = row.get("host") if isinstance(row, dict) else row
                    _add_cand(cands, host, "ip_cohost", seed_apexes)
        # reverse-WHOIS siblings left behind by a prior --whois-reverse run
        for st in ("reverse_whois_current", "reverse_whois_historic"):
            for d in (lr.get(st) or {}).get("domains") or []:
                _add_cand(cands, d, "reverse_whois", seed_apexes)
    # top-level urlscan-related infra attached when the page itself was gone
    for d in ((obj.get("related_urlscan") or {}).get("domains") or []):
        _add_cand(cands, d, "urlscan_related", seed_apexes)


def _metered_leads_from_raw(obj, leads):
    """Pivots that would need a METERED call to expand — deferred for analyst approval, never
    auto-run by the free loop. Keyed by (service,value) so they dedupe across hosts."""
    host = (obj.get("meta") or {}).get("host") or "?"
    for piv in obj.get("pivots", []) or []:
        kind, val = piv.get("kind", ""), piv.get("value")
        if kind == "favicon_hash" and val is not None:
            leads[("FOFA", f"icon_hash={val}")] = {
                "service": "FOFA", "query": f'icon_hash="{val}"', "cost": "metered",
                "why": f"reverse favicon hash to find co-branded siblings (seen on {host})"}
        elif kind == "whois:registrant_email" and val and not _is_privacy(val):
            leads[("WhoisXML", f"reverse_email={val}")] = {
                "service": "WhoisXML", "query": f'reverse-whois email="{val}"', "cost": "metered",
                "why": f"reverse-WHOIS the registrant email for the owner's other domains ({host})"}
    # origin-candidate IPs -> FOFA ip= reverse (find more co-hosted domains)
    for piv in obj.get("pivots", []) or []:
        if piv.get("kind") != "domain":
            continue
        dns = (piv.get("live_results") or {}).get("dns") or {}
        for c in dns.get("ip_classification") or []:
            if c.get("cdn") is False and c.get("ip"):
                leads[("FOFA", f"ip={c['ip']}")] = {
                    "service": "FOFA", "query": f'ip="{c["ip"]}"', "cost": "metered",
                    "why": f"reverse the origin IP {c['ip']} for co-hosted domains (from {host})"}


def frontier(case, max_new=8):
    """Compute the next FREE frontier + deferred metered leads for a case, from its raw/*.json.

    Returns dict: pending (new apexes to collect next, capped), candidates (apex->why), and
    metered_leads (analyst-approval pivots). Pure read — does not touch state.json."""
    cdir = _case_dir(case)
    st = load_state(case)
    collected = collected_hosts(cdir)
    consumed = {h.lower() for h in st.get("consumed", [])}
    seed_apexes = {_registrable(h) for h in collected} | {_registrable(h) for h in consumed}
    cands, leads = {}, {}
    for path in sorted(glob.glob(os.path.join(cdir, "raw", "*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                obj = json.load(fh)
        except Exception:
            continue
        _free_candidates_from_raw(obj, cands, seed_apexes)
        _metered_leads_from_raw(obj, leads)
    # drop apexes already collected or already queued/consumed; rank by # of corroborating sources
    already = {_registrable(h) for h in collected} | {_registrable(h) for h in consumed}
    fresh = {a: v for a, v in cands.items() if a not in already}
    ranked = sorted(fresh.items(), key=lambda kv: (-len(kv[1]["sources"]), kv[0]))
    pending = [a for a, _ in ranked][:max_new] if max_new else [a for a, _ in ranked]
    return {
        "case": st["case"], "round": st.get("round", 0),
        "pending": pending,
        "candidates": {a: {"sources": sorted(v["sources"]),
                           "examples": sorted(v["examples"])[:4]} for a, v in ranked},
        "candidate_total": len(fresh),
        "metered_leads": list(leads.values()),
    }


def convergence_verdict(case, stale=2):
    """Read the convergence verdict from rounds.jsonl (convergence.py owns writing it)."""
    cdir = _case_dir(case)
    if _conv is None:
        return {"verdict": "UNKNOWN", "rounds": 0, "reason": "convergence module unavailable"}
    rounds = _conv._load_rounds(cdir)
    if not rounds:
        return {"verdict": "EXPANDING", "rounds": 0, "reason": "no snapshots yet"}
    recent = rounds[-stale:]
    converged = (len(rounds) >= stale and
                 all(r["new_hosts"] == 0 and r["new_indicators"] == 0 for r in recent))
    last = rounds[-1]
    return {"verdict": "CONVERGED" if converged else "EXPANDING", "rounds": len(rounds),
            "hosts": last.get("hosts"), "indicators": last.get("indicators"),
            "new_hosts_recent": sum(r["new_hosts"] for r in recent),
            "new_indicators_recent": sum(r["new_indicators"] for r in recent)}


def reopen(case, new_seeds=None):
    """Cold-case reopen: flip status back to expanding, merge any new seeds into pending, and let
    the next loop re-mine the frontier against the CURRENT KB (cross-case breakthroughs included)."""
    st = load_state(case)
    st["status"] = "expanding"
    st["reopen_count"] = st.get("reopen_count", 0) + 1
    st["note"] = f"reopened {_now()}"
    if new_seeds:
        have = {h.lower() for h in st.get("pending", [])} | {h.lower() for h in st.get("consumed", [])}
        for s in new_seeds:
            h = s.strip().lower()
            if h and h not in have:
                st.setdefault("pending", []).append(h)
    save_state(case, st)
    return st


# ------------------------------------------------------------------------- CLI
def _print_status(case):
    st = load_state(case)
    cdir = _case_dir(case)
    if not os.path.isdir(cdir):
        print(f"no such case: {case}", file=sys.stderr)
        return 2
    v = convergence_verdict(case)
    print(f"# Case state — {case}")
    print(f"  status   : {st.get('status')}   (round {st.get('round')}, reopened×{st.get('reopen_count', 0)})")
    print(f"  collected: {len(collected_hosts(cdir))} host(s) on disk")
    print(f"  pending  : {len(st.get('pending', []))}  consumed: {len(st.get('consumed', []))}")
    print(f"  converge : {v['verdict']}  ({v.get('rounds', 0)} round(s); "
          f"recent +{v.get('new_hosts_recent', 0)} hosts / +{v.get('new_indicators_recent', 0)} indicators)")
    if st.get("metered_leads"):
        print(f"  metered leads awaiting approval: {len(st['metered_leads'])}")
    for h in st.get("history", [])[-6:]:
        print(f"    r{h.get('round')}: +{h.get('new_hosts', 0)} hosts  {h.get('verdict', '')}  {h.get('ts', '')}")
    return 0


def main():
    ap = argparse.ArgumentParser(description="Resumable case stage machine + gap/frontier extractor.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("status", help="show the case's stage, queues, and convergence verdict")
    s.add_argument("case")
    f = sub.add_parser("frontier", help="compute the next FREE frontier + deferred metered leads")
    f.add_argument("case")
    f.add_argument("--max-new", type=int, default=8)
    f.add_argument("--json", action="store_true")
    r = sub.add_parser("reopen", help="cold-case reopen (+ optional new seeds), re-mine next run")
    r.add_argument("case")
    r.add_argument("seeds", nargs="*", help="optional new seed domains to merge into pending")
    a = ap.parse_args()

    if a.cmd == "status":
        return _print_status(a.case)
    if a.cmd == "frontier":
        fr = frontier(a.case, max_new=a.max_new)
        if a.json:
            print(json.dumps(fr, indent=2, ensure_ascii=False))
            return 0
        print(f"# Frontier — {a.case}  (round {fr['round']})")
        print(f"  {fr['candidate_total']} fresh apex candidate(s); next {len(fr['pending'])} to collect:")
        for apex in fr["pending"]:
            why = fr["candidates"].get(apex, {})
            print(f"    {apex:32} via {', '.join(why.get('sources', []))}")
        if fr["metered_leads"]:
            print(f"  {len(fr['metered_leads'])} metered lead(s) — need approval before spending credits:")
            for ml in fr["metered_leads"][:12]:
                print(f"    [{ml['service']}] {ml['query']}   — {ml['why']}")
        return 0
    if a.cmd == "reopen":
        st = reopen(a.case, a.seeds or None)
        print(f"reopened '{a.case}' → status={st['status']}, pending={len(st['pending'])} "
              f"(reopened×{st['reopen_count']}). Re-run: python3 tools/intel.py loop {a.case}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
