#!/usr/bin/env python3
"""
export_graph.py — project the KNOWLEDGE BASE into a scannable, domain-centric graph.

Fixes two problems with building the graph from raw pivot_extract JSON:
  1. it missed KB-only edges (reverse-WHOIS registrant links) — so e.g. lambangsieunhanh.com
     never connected to ductaibc1@gmail.com.
  2. it drew every domain<->indicator as its own line = a 200-node hairball.

This reads ALL KB edges and COLLAPSES them to domain<->domain edges weighted by shared
*attribution-grade* artifacts (registrant email/name, UA/GA4/GTM, verification token,
favicon), plus person/email operator anchors. Same registrant + same UA between two
domains = a strong, short edge → the sub-clusters pull apart visibly. Louvain communities
color the sub-clusters. Reuses graph_build's analytics (communities, betweenness, sizing).

  python3 export_graph.py --kb knowledge -o cases/unified/kb_graph.json
"""
import os
import sys
import json
import argparse
from itertools import combinations
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "WebPivot", "tools"))
sys.path.insert(0, HERE)
import graph_build as gb  # noqa: E402
from knowledge_base import KB  # noqa: E402

# relations that count as attribution-grade for the domain projection (draw an edge)
STRONG = {"registered_by", "uses_analytics", "uses_verification", "uses_favicon"}
# also drawn (weaker, but real cross-cluster bridges — e.g. a shared Messenger handle)
BRIDGE = {"uses_contact"}
DRAWN = STRONG | BRIDGE
# same-kit relations — shown only as node context / weak edges, never the backbone
KIT = {"uses_theme", "same_template", "same_inline_css", "same_comment",
       "uses_contact", "uses_nameserver", "uses_tracker"}
# short human labels for the shared-artifact classes
RELNAME = {"registered_by": "registrant", "uses_analytics": "analytics-ID",
           "uses_verification": "verif-token", "uses_favicon": "favicon",
           "uses_contact": "contact", "uses_theme": "theme", "same_template": "template",
           "same_inline_css": "css", "same_comment": "comment", "uses_nameserver": "NS"}


def main():
    ap = argparse.ArgumentParser(description="Project the KB into a domain-centric graph.")
    ap.add_argument("--kb", required=True)
    ap.add_argument("-o", "--out", default="kb_graph.json")
    ap.add_argument("--max-indicator-degree", type=int, default=25,
                    help="ignore an indicator shared by more than this many domains (boilerplate/CDN noise)")
    args = ap.parse_args()

    kb = KB(args.kb)
    ind_domains = defaultdict(set)   # (dst_type,dst) -> {domains}
    ind_rel = {}                     # (dst_type,dst) -> rel
    for e in kb.edges():
        if e["src_type"] == "domain" and e["dst_type"] in ("indicator", "email", "person", "org"):
            k = (e["dst_type"], e["dst"])
            ind_domains[k].add(e["src"])
            ind_rel[k] = e["rel"]

    g = gb.Graph()
    # 1) domain<->domain edges from SHARED strong artifacts (collapsed, weighted)
    pair = defaultdict(lambda: defaultdict(list))   # (d1,d2) -> relclass -> [indicator]
    for k, doms in ind_domains.items():
        rel = ind_rel[k]
        if rel not in DRAWN:
            continue
        if not (2 <= len(doms) <= args.max_indicator_degree):
            continue
        for d1, d2 in combinations(sorted(doms), 2):
            pair[(d1, d2)][rel].append(k[1])
    def _clean(v):
        # strip the "kind:" prefix so the actual value reads cleanly (e.g. "G-PN…")
        s = str(v)
        return s.split(":", 1)[1] if ":" in s and not s.startswith("http") else s

    for (d1, d2), rels in pair.items():
        strong = sum(1 for r in rels if r in STRONG)   # distinct attribution-grade classes shared
        n_shared = sum(len(v) for v in rels.values())
        lc = "operator" if strong >= 2 else "kit" if strong >= 1 else "link"
        g.node(d1, "domain")
        g.node(d2, "domain")
        label = "+".join(RELNAME.get(r, r) for r in sorted(rels))
        # evidence lists the ACTUAL shared values, not just a count
        detail = "  ·  ".join(
            f"{RELNAME.get(r, r)}: " + ", ".join(_clean(x) for x in vals)
            for r, vals in sorted(rels.items()))
        key = g.edge(d1, d2, label, confidence="confirmed" if strong >= 2 else "inferred",
                     evidence=detail)
        g.edges[key]["link_class"] = lc
        g.edges[key]["shared"] = {RELNAME.get(r, r): [_clean(x) for x in vals]
                                  for r, vals in rels.items()}

    # 2) operator anchors: person / email nodes with registered_by edges
    for k, doms in ind_domains.items():
        dt, dv = k
        if dt in ("person", "email") and ind_rel[k] == "registered_by":
            if len(doms) > args.max_indicator_degree:
                continue  # bulk-registrant / reseller — skip (tradecraft guard)
            nid = f"{dt}:{dv}"
            g.node(nid, dt if dt in gb.TYPE_META else "email", label=dv)
            for d in doms:
                g.node(d, "domain")
                key = g.edge(d, nid, "registered_by", confidence="confirmed", evidence="registrant")
                g.edges[key]["link_class"] = "operator"

    graph = gb.assemble(g)

    # Recolor by OPERATOR attribution (clearer than raw Louvain): 0 = Nguyen Duc Tai
    # (ductaibc1@gmail.com), 1 = Lê Nhất Duy, 2 = unattributed. Layout already
    # separates them via the anchors; this makes the sub-clusters read at a glance.
    reg = defaultdict(set)
    for e in kb.edges():
        if e["rel"] == "registered_by" and e["src_type"] == "domain":
            reg[e["src"]].add(e["dst"].lower())

    def op_by_registrant(dom):
        tags = reg.get(dom, set())
        if "ductaibc1@gmail.com" in tags or "nguyen duc tai" in tags:
            return 0
        if any("duy" in t for t in tags):
            return 1
        return None

    # Propagate the operator label across each artifact community by majority vote,
    # so privacy-registered domains inherit the operator they're artifact-linked to.
    from collections import Counter
    comm_votes = defaultdict(Counter)
    for n in graph["nodes"]:
        if n["type"] == "domain":
            grp = op_by_registrant(n["label"])
            if grp is not None:
                comm_votes[n.get("community")][grp] += 1
    comm_op = {c: v.most_common(1)[0][0] for c, v in comm_votes.items() if v}

    for n in graph["nodes"]:
        if n["type"] == "domain":
            direct = op_by_registrant(n["label"])
            n["community_rank"] = direct if direct is not None else comm_op.get(n.get("community"), 2)
        elif n["type"] in ("email", "person"):
            lab = n["label"].lower()
            n["community_rank"] = 0 if ("ductaibc1" in lab or lab == "nguyen duc tai") \
                else 1 if "duy" in lab else 2
    graph["meta"]["coloring"] = "operator (0=Nguyen Duc Tai, 1=Lê Nhất Duy, 2=unattributed)"

    json.dump(graph, open(args.out, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    m = graph["meta"]
    print(f"wrote {args.out}: {m['nodes']} nodes, {m['edges']} edges, "
          f"{m['communities']} communities, {m['components']} components", file=sys.stderr)


if __name__ == "__main__":
    main()
