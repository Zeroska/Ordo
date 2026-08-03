#!/usr/bin/env python3
"""
victim_profile.py — profile the VICTIMS of a hostname-hijack campaign to infer the operator's
ACCESS VECTOR.

WHY THIS EXISTS
---------------
When an operator serves their content from hostnames they do not own — a phishing page on
`login.<someone-elses-domain>`, a dangling CNAME, a compromised CMS — the usual analysis chases
the operator's infrastructure and stops. That leaves the most operationally useful question
unasked:

    To obtain these hostnames, what did the operator have to be able to DO?

The victim set answers it, because the victims are a SAMPLE OF THE OPERATOR'S CAPABILITY:

  * victims all on ONE provider .................. that provider is breached, or an insider
  * victims all on ONE control panel, many hosts . the operator has a panel exploit or default creds
  * victims all on ONE CMS ....................... a CMS/plugin vulnerability
  * victims share a small DNS operator / agency .. a reseller or IT contractor was compromised
  * victims share NOTHING technical .............. stolen or purchased credentials

That last line is the one analysts get wrong. Dispersion reads like a dead end — "no pattern" —
when it is in fact a positive finding with a name: a credential LIST has no technical common
factor, because it was assembled by infostealer malware or an access broker across whatever
machines happened to be infected. Absence of a shared platform is the signature.

This matters operationally: the remediation differs completely. A panel exploit is fixed by a
vendor patch. A provider breach is fixed by that provider. A credential supply is fixed only by
per-victim credential resets, and until they happen the operator simply moves to the next name on
their list — which is why taking down the page achieves close to nothing.

WHAT IT DOES NOT DO
-------------------
It does not attribute, and it does not touch the victims. Victims are not the target: everything
here is PASSIVE (DNS records and, if already collected, WHOIS). We never scan or probe a victim's
infrastructure. The panel is identified from the subdomains a panel creates in its customer's own
zone, which is public DNS.

It also does not decide. It reports the victim set's SHAPE and which hypothesis that shape
supports under thresholds an analyst can edit in
`IntelAnalysis/references/victim_profile.json`. The judgment stays with the analyst.

Reference data: RULE 3 — see that JSON. Loader: kb_refs.load_ref (RULE 3 failure contract).
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from kb_refs import load_ref, ref_path  # noqa: E402

# --- reference data (RULE 3): minimal embedded fallback, real values live in the JSON ----------
_VP_FALLBACK = {
    "panel_dns_signatures": {"cpanel": ["cpanel", "webdisk"], "plesk": ["plesk"]},
    "panel_host_signatures": {"cpanel": [".cprapid.com"], "plesk": [".plesk.page"]},
    "managed_dns_operators": ["cloudflare.com", "awsdns-"],
    "hypotheses": {},
    "thresholds": {"min_victims_for_any_call": 4, "onset_tight_days": 30,
                   "high_concentration": 0.8, "moderate_concentration": 0.6},
    "victim_sectors": {"real_estate": ["realit"], "health": ["clinic"]},
}
_REF = load_ref(ref_path(__file__, "victim_profile.json"), _VP_FALLBACK)

PANEL_DNS = _REF["panel_dns_signatures"]
PANEL_HOST = _REF["panel_host_signatures"]
MANAGED_DNS = _REF["managed_dns_operators"]
HYPOTHESES = _REF["hypotheses"]
THRESHOLDS = _REF["thresholds"]
SECTORS = _REF["victim_sectors"]

_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


# --------------------------------------------------------------------------- passive DNS helpers
def _dig(name: str, rtype: str) -> list[str]:
    """One passive `dig +short` lookup. Never raises; returns [] on any failure."""
    try:
        r = subprocess.run(["dig", "+short", "+time=3", "+tries=1", name, rtype],
                           capture_output=True, text=True, timeout=12)
        return [ln.strip().rstrip(".") for ln in r.stdout.splitlines() if ln.strip()]
    except Exception:
        return []


def _apex(host: str) -> str:
    """Best-effort registrable domain. Handles the common two-label public suffixes we meet."""
    host = host.strip().lower().rstrip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two = {"co.uk", "co.za", "com.eg", "com.ng", "co.il", "com.au", "com.br", "com.tr",
           "com.vn", "net.au", "org.uk", "ac.uk", "gov.uk", "com.mx", "co.nz", "com.sg"}
    if ".".join(parts[-2:]) in two:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _asn_of(ip: str) -> str:
    """Origin ASN via Team Cymru's DNS interface — keyless, passive, no account."""
    if not _IPV4.match(ip or ""):
        return ""
    rev = ".".join(reversed(ip.split(".")))
    for txt in _dig(f"{rev}.origin.asn.cymru.com", "TXT"):
        m = re.search(r'"?\s*(\d+)\s*\|', txt)
        if m:
            return "AS" + m.group(1)
    return ""


def _is_managed(ns_suffix: str) -> bool:
    return any(m in ns_suffix for m in MANAGED_DNS)


# ------------------------------------------------------------------------------ victim profiling
def profile_victim(apex: str, hijacked: list[str] | None = None) -> dict:
    """Passively profile ONE victim apex. DNS only — the victim is never probed or scanned."""
    prof: dict = {"apex": apex, "hijacked_labels": sorted(hijacked or [])}

    ips = [x for x in _dig(apex, "A") if _IPV4.match(x)]
    prof["apex_ip"] = ips[0] if ips else None
    prof["apex_asn"] = _asn_of(ips[0]) if ips else ""

    ns = [n.lower() for n in _dig(apex, "NS")]
    prof["nameservers"] = ns
    # The DNS OPERATOR is the registrable domain of the nameservers — that is the account the
    # attacker needed to write into, so it is the dimension a provider breach concentrates on.
    prof["dns_operator"] = _apex(ns[0]) if ns else ""
    prof["dns_managed"] = _is_managed(prof["dns_operator"])

    mx = [m.split()[-1].lower() for m in _dig(apex, "MX") if m.split()]
    prof["mx_operator"] = _apex(mx[0]) if mx else ""

    # PANEL — identified from the subdomains a control panel creates in its OWN customer's zone.
    # Public DNS, no contact with the victim's server.
    panel_hits: dict[str, list[str]] = {}
    for panel, labels in PANEL_DNS.items():
        for label in labels:
            if _dig(f"{label}.{apex}", "A"):
                panel_hits.setdefault(panel, []).append(label)
    # cPanel's autodiscover/webmail labels are also created by mail providers; require a
    # panel-exclusive label before naming cPanel, so Microsoft 365 tenants aren't miscounted.
    if "cpanel" in panel_hits:
        exclusive = {"cpanel", "whm", "webdisk", "cpcalendars", "cpcontacts"}
        if not (set(panel_hits["cpanel"]) & exclusive):
            panel_hits.pop("cpanel")
    prof["panel_evidence"] = {k: sorted(v) for k, v in panel_hits.items()}
    prof["panel"] = max(panel_hits, key=lambda k: len(panel_hits[k])) if panel_hits else "unknown"

    label = apex.split(".")[0]
    prof["sector"] = next((s for s, kws in SECTORS.items()
                           if any(k in label for k in kws)), "unknown")
    prof["tld"] = apex.rsplit(".", 1)[-1]
    return prof


# ----------------------------------------------------------------------------------- the analysis
def _concentration(values: list[str], ignore=("", "unknown")) -> tuple[str, float, int]:
    """Largest share of one value in a dimension -> (value, share, n_known)."""
    known = [v for v in values if v not in ignore]
    if not known:
        return ("", 0.0, 0)
    top, count = collections.Counter(known).most_common(1)[0]
    return (top, count / len(known), len(known))


def assess(profiles: list[dict]) -> dict:
    """Score the victim set against every hypothesis in the reference file."""
    n = len(profiles)
    dims = {
        "dns_operator": [p.get("dns_operator", "") for p in profiles],
        "panel": [p.get("panel", "unknown") for p in profiles],
        "cms": [p.get("cms", "unknown") for p in profiles],
        "registrar": [p.get("registrar", "") for p in profiles],
        "apex_asn": [p.get("apex_asn", "") for p in profiles],
        "tld": [p.get("tld", "") for p in profiles],
        "sector": [p.get("sector", "unknown") for p in profiles],
        "mx_operator": [p.get("mx_operator", "") for p in profiles],
    }
    shape = {}
    for dim, vals in dims.items():
        top, share, known = _concentration(vals)
        shape[dim] = {"top": top, "concentration": round(share, 3),
                      "known": known, "distinct": len({v for v in vals if v not in ("", "unknown")})}

    providers = {p.get("dns_operator", "") for p in profiles if p.get("dns_operator")}
    n_providers = len(providers)

    min_n = THRESHOLDS.get("min_victims_for_any_call", 4)
    if n < min_n:
        return {"victims": n, "shape": shape, "distinct_dns_operators": n_providers,
                "supported": [],
                "verdict": f"INSUFFICIENT VICTIMS — {n} profiled, {min_n} needed. With a set this "
                           f"small every dimension looks concentrated by chance. Widen the victim "
                           f"sweep before drawing an access-vector conclusion."}

    # A dimension whose dominant value is the world's default (e.g. cPanel) is CONFOUNDED: it looks
    # concentrated in any victim set, related or not. Such a dimension must not be allowed to mask
    # genuine dispersion, so it is excluded from the dispersion test and reported separately.
    base_rate = set()
    for h in HYPOTHESES.values():
        if isinstance(h, dict):
            base_rate.update(h.get("high_base_rate_values") or [])
    confounded = [d for d, s in shape.items() if s["top"] in base_rate and s["known"]]

    supported = []
    for name, h in HYPOTHESES.items():
        if not isinstance(h, dict):
            continue
        if n < h.get("min_victims", min_n):
            continue
        dim = h.get("dimension", "*")
        if dim == "*":                                     # dispersion hypothesis
            testable = [d for d in ("dns_operator", "panel", "cms", "registrar", "apex_asn")
                        if d not in confounded]
            worst = max((shape[d]["concentration"] for d in testable), default=1.0)
            if (worst <= h.get("max_concentration", 0.6)
                    and n_providers >= h.get("min_distinct_providers", 3)):
                entry = {"hypothesis": name, "basis":
                         f"no discriminating dimension exceeds {worst:.0%} concentration across "
                         f"{n_providers} distinct DNS operators"}
                if confounded:
                    entry["caution"] = (
                        f"excluded from this test as base-rate confounded: "
                        f"{', '.join(confounded)}")
                supported.append(entry)
            continue
        s = shape.get(dim)
        if not s:
            continue
        if s["concentration"] < h.get("min_concentration", 0.8):
            continue
        if h.get("exclude_managed") and _is_managed(s["top"]):
            continue
        if n_providers < h.get("min_distinct_providers", 0):
            continue
        if h.get("requires_sector_or_country_concentration"):
            mod = THRESHOLDS.get("moderate_concentration", 0.6)
            if max(shape["sector"]["concentration"], shape["tld"]["concentration"]) < mod:
                continue
        entry = {"hypothesis": name, "basis":
                 f"{dim} concentrated at {s['concentration']:.0%} on '{s['top']}' "
                 f"across {n_providers} DNS operators"}
        # A concentration on a value that is ALREADY the world's default is close to what you get
        # by sampling at random — flag it rather than letting it read as a finding.
        if s["top"] in (h.get("high_base_rate_values") or []):
            entry["caution"] = (
                f"BASE RATE — '{s['top']}' is the default for most hosting, so this concentration "
                f"is expected even in an unrelated victim set. Do NOT report this as support "
                f"unless you can also show a shared VERSION or vulnerable component.")
        supported.append(entry)

    if supported:
        verdict = "SUPPORTED: " + ", ".join(x["hypothesis"] for x in supported)
    else:
        verdict = ("NO HYPOTHESIS MET ITS THRESHOLD — the victim set is neither concentrated "
                   "enough for a shared-platform explanation nor dispersed across enough "
                   "providers to call credential supply. Collect more victims.")
    return {"victims": n, "shape": shape, "distinct_dns_operators": n_providers,
            "supported": supported, "verdict": verdict}


# ------------------------------------------------------------------------------------------- I/O
def victims_from_case(case_dir: str) -> dict[str, list[str]]:
    """Derive {victim apex: [hijacked labels]} from a case's collected hosts.

    A collected host is treated as a hijacked label on a victim apex when the host is a SUBDOMAIN
    (not the apex itself) — the apex is the victim's own name, the label is what the operator
    added. Hosts the operator registered outright have no victim and are skipped.
    """
    out: dict[str, list[str]] = {}
    for path in sorted(glob.glob(os.path.join(case_dir, "raw", "*.json"))):
        try:
            with open(path, encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception:
            continue
        host = ((doc.get("meta") or {}).get("host") or "").lower().rstrip(".")
        if not host:
            continue
        apex = _apex(host)
        if host == apex:
            continue                                        # operator-registered, no victim
        out.setdefault(apex, []).append(host[: -(len(apex) + 1)])
    return out


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Profile hijack VICTIMS to infer the operator's access vector.")
    ap.add_argument("victims", nargs="*",
                    help="victim apex domains (or hijacked hostnames — the apex is derived)")
    ap.add_argument("--case", help="derive the victim set from a case folder's collected hosts")
    ap.add_argument("--exclude", default="",
                    help="comma list of apexes the OPERATOR registered themselves. A domain the "
                         "operator bought has no victim and must not be counted as one — it would "
                         "otherwise inflate provider diversity and skew every concentration. The "
                         "tool cannot detect this: only you know which names the operator owns.")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of a report")
    ap.add_argument("-o", "--out", help="write JSON here as well")
    args = ap.parse_args()

    here = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(os.path.dirname(here))

    victims: dict[str, list[str]] = {}
    if args.case:
        case_dir = args.case if os.path.isdir(args.case) else os.path.join(root, "cases", args.case)
        if not os.path.isdir(case_dir):
            print(f"no such case: {case_dir}", file=sys.stderr)
            return 2
        victims = victims_from_case(case_dir)
    for v in args.victims:
        a = _apex(v)
        victims.setdefault(a, [])
        if a != v.strip().lower().rstrip("."):
            victims[a].append(v.strip().lower().rstrip(".")[: -(len(a) + 1)])
    for ex in (x.strip().lower() for x in args.exclude.split(",") if x.strip()):
        victims.pop(_apex(ex), None)
    if not victims:
        print("no victims given (pass apexes, or --case <name>)", file=sys.stderr)
        return 2

    profiles = [profile_victim(a, labels) for a, labels in sorted(victims.items())]
    result = {"victims": profiles, "assessment": assess(profiles)}

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    a = result["assessment"]
    print(f"\nVICTIM PROFILE — {a['victims']} victim domain(s), "
          f"{a['distinct_dns_operators']} distinct DNS operator(s)\n")
    print(f"{'victim':34s} {'dns operator':20s} {'panel':11s} {'asn':9s} {'sector':13s} labels")
    print("-" * 104)
    for p in profiles:
        print(f"{p['apex'][:33]:34s} {(p['dns_operator'] or '?')[:19]:20s} "
              f"{p['panel'][:10]:11s} {(p['apex_asn'] or '?')[:8]:9s} "
              f"{p['sector'][:12]:13s} {','.join(p['hijacked_labels'])[:28]}")
    print("\nDIMENSION CONCENTRATION (largest share on one value):")
    for dim, s in a["shape"].items():
        if s["known"]:
            print(f"  {dim:14s} {s['concentration']:5.0%} on '{s['top'][:26]}' "
                  f"({s['distinct']} distinct / {s['known']} known)")
    print(f"\nVERDICT: {a['verdict']}")
    for s in a["supported"]:
        print(f"  - {s['hypothesis']}: {s['basis']}")
        if s.get("caution"):
            print(f"      ! {s['caution']}")
    print("\nThis is a decision aid. Thresholds live in "
          "IntelAnalysis/references/victim_profile.json — tune them, then write the judgment "
          "yourself.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
