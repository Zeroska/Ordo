#!/usr/bin/env python3
"""
query.py — read the knowledge base (no web I/O). The cheap, cited substrate the
IntelAnalysis skill and the reporter read from instead of re-querying the world.

  python3 query.py --kb knowledge --stats
  python3 query.py --kb knowledge --shared --min 2      # cluster seeds
  python3 query.py --kb knowledge --entity lambangnhanh.online
  python3 query.py --kb knowledge --cluster lambangnhanh.vip
  python3 query.py --kb knowledge --type person
"""
import os
import sys
import argparse
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from knowledge_base import KB  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description="Query the OSINT knowledge base.")
    ap.add_argument("--kb", required=True)
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--shared", action="store_true", help="indicators shared by >= --min domains")
    ap.add_argument("--min", type=int, default=2)
    ap.add_argument("--entity", help="dump one entity's facts + edges")
    ap.add_argument("--cluster", help="domains sharing an indicator with this domain")
    ap.add_argument("--type", help="list entities of a type")
    args = ap.parse_args()
    kb = KB(args.kb)

    if args.stats:
        ents = list(kb.all_entities())
        print(f"entities: {len(ents)}   facts: {sum(len(e['facts']) for e in ents)}   edges: {len(kb.edges())}")
        print("by type:", dict(Counter(e["type"] for e in ents)))
        print("edges by rel:", dict(Counter(e["rel"] for e in kb.edges())))
        print("facts by source:", dict(Counter(f["source"] for e in ents for f in e["facts"])))

    if args.shared:
        print(f"\n# Shared indicators (>= {args.min} domains) — cluster seeds\n")
        for s in kb.shared_indicators(args.min):
            print(f"[{s['domain_count']}] {s['indicator_type']}:{s['indicator']}  ({', '.join(s['rels'])})")
            print(f"     {', '.join(s['domains'])}")

    if args.type:
        print(f"\n# entities of type '{args.type}'")
        for e in sorted(kb.all_entities(), key=lambda x: x["value"]):
            if e["type"] == args.type:
                print(f"  {e['value']}   ({len(e['facts'])} facts)")

    if args.entity:
        # find it across types
        found = [e for e in kb.all_entities() if e["value"] == args.entity]
        for e in found:
            print(f"\n# {e['type']}: {e['value']}   (first {e.get('first_seen')} … last {e.get('last_seen')})")
            for f in e["facts"]:
                print(f"  · {f['attribute']} = {f['value']}   [{f['source']}/{f['collector']} conf {f['confidence']}]")
            nb = kb.neighbors(e["type"], e["value"])
            if nb:
                print("  edges:")
                for dt, dv, rel, conf in nb:
                    print(f"    -{rel}-> {dt}:{dv}   (conf {conf})")

    if args.cluster:
        # 1-hop through shared indicators: domains that share any indicator with target
        target = args.cluster
        inds = {(dt, dv) for dt, dv, rel, c in kb.neighbors("domain", target)
                if dt in ("indicator", "email", "person", "org")}
        peers = {}
        for e in kb.edges():
            if e["src_type"] == "domain" and (e["dst_type"], e["dst"]) in inds and e["src"] != target:
                peers.setdefault(e["src"], set()).add(f"{e['rel']}:{e['dst']}")
        print(f"\n# Domains sharing an indicator with {target}\n")
        for dom, via in sorted(peers.items(), key=lambda x: -len(x[1])):
            print(f"  {dom}   via {len(via)} shared: {', '.join(sorted(via)[:4])}{' …' if len(via) > 4 else ''}")


if __name__ == "__main__":
    main()
