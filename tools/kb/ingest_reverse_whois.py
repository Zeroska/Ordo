#!/usr/bin/env python3
"""
ingest_reverse_whois.py — fold a reverse-WHOIS result into the KB, WITH a bulk-registrant
guard so a shared reseller/agency email doesn't blow up the graph.

Tradecraft encoded (IntelAnalysis §1-2): a registrant term tied to a handful of
thematically-consistent domains is attribution-grade (same operator). A term tied to
hundreds/thousands of unrelated domains is a shared registration service — NOISE — and
must not become an operator hub. This tool refuses to ingest above --max-domains and
reports the decision instead of silently linking.

Usage:
  python3 ingest_reverse_whois.py --kb knowledge --email registrant@example.com
  python3 ingest_reverse_whois.py --kb knowledge --name "Registrant Name" --max-domains 150
"""
import os
import sys
import argparse
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "..", "WebPivot", "tools"))
from knowledge_base import KB  # noqa: E402
import whois_enrich  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Ingest a reverse-WHOIS result with a bulk-registrant guard.")
    ap.add_argument("--kb", required=True)
    ap.add_argument("--email")
    ap.add_argument("--name")
    ap.add_argument("--person", help="person label to attach to the email (optional)")
    ap.add_argument("--search-type", choices=["current", "historic"], default="historic")
    ap.add_argument("--max-domains", type=int, default=200,
                    help="above this, treat the term as a shared registrar/reseller (noise) and DO NOT link")
    args = ap.parse_args()
    if not (args.email or args.name):
        ap.error("give --email or --name")

    term = args.email or args.name
    kind = "email" if args.email else "name"
    r = whois_enrich.reverse_whois(term, kind, search_type=args.search_type)
    if r is None:
        print("no WHOISXML_API_KEY set — cannot run.", file=sys.stderr); sys.exit(2)
    if r.get("error"):
        print(f"reverse-whois error: {r['error']}", file=sys.stderr); sys.exit(1)

    count = r.get("count", 0)
    domains = r.get("domains", [])
    print(f"reverse-whois {kind} '{term}' ({args.search_type}): {count} domains")

    if count > args.max_domains:
        print(f"  ⚠ GUARD TRIPPED: {count} > --max-domains {args.max_domains}.")
        print("  Treating as a shared registration service (reseller/agency) = NOISE.")
        print("  NOT linking these domains. Re-run with a higher --max-domains to override.")
        # record the decision as an attributed fact on the term itself, for audit
        kb = KB(args.kb)
        observed = datetime.now(timezone.utc).isoformat()
        etype = "email" if args.email else "person"
        kb.add_fact(etype, term.lower() if args.email else term, "bulk_registrant",
                    {"domain_count": count, "verdict": "shared-service/noise",
                     "search_type": args.search_type},
                    "whoisxml", "reverse_whois", observed, "high")
        return

    kb = KB(args.kb)
    observed = datetime.now(timezone.utc).isoformat()
    ev = kb.save_evidence("whoisxml_reverse", term, r, observed[:10])
    n = 0
    for d in domains:
        if not d:
            continue
        kb.add_edge("domain", d, "registered_by",
                    "email" if args.email else "person",
                    term.lower() if args.email else term,
                    "whoisxml", "reverse_whois", observed, "medium", ev)
        n += 1
    if args.person and args.email:
        kb.add_edge("email", args.email.lower(), "identity_of", "person", args.person,
                    "whoisxml", "reverse_whois", observed, "medium", ev)
    print(f"  linked {n} domains -> {kind}:{term}  (attribution-grade cluster)")


if __name__ == "__main__":
    main()
