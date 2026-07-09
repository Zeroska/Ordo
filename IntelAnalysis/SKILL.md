---
name: IntelAnalysis
description: The analyst / judgment layer for OSINT — correlation, attribution, confidence calibration, and next-pivot decisions over the knowledge base. Does NOT collect; it reasons over facts that collectors (WebPivot, etc.) already gathered. USE WHEN correlate findings, attribute infrastructure, who is behind this, same operator, same actor, build the case, assess confidence, weigh evidence, cluster analysis, what should I pivot on next, is this the same owner, investigation judgment, connect the dots, threat attribution.
---

# IntelAnalysis — the analyst's brain

This is the **reasoning layer**, not a collector. Collectors (WebPivot, future
`osint-ip`/`osint-ioc`) gather attributed facts into `knowledge/`. IntelAnalysis reads
that store and applies **investigative judgment**: which facts matter, what they prove,
how confident to be, and what to chase next. It writes assessments; it does not fetch.

**Deterministic-first still holds.** Correlation math (dedup, shared-indicator detection,
clustering) is code — call `tools/kb/query.py` and `WebPivot/tools/graph_build.py`. Use
model reasoning only for the parts code can't do: weighing evidence, resolving conflicts,
forming and falsifying hypotheses, and deciding the next move. Run this skill on the
strongest model (Opus / Fable); the collectors run cheap.

## Running the tools — paths & working directory (read first)

Run every command below from the `intelligence_assist` **project root** (where `knowledge/`,
`cases/`, and `tools/` live). `tools/kb/query.py` and the KB store are project-root-relative —
they are not inside this skill folder, so `cd` to the project root first (`cd "$ROOT"`).

## Inputs / outputs

- **Reads:** the knowledge base.
  ```bash
  python3 tools/kb/query.py --kb knowledge --stats
  python3 tools/kb/query.py --kb knowledge --shared --min 2      # cluster seeds (start here)
  python3 tools/kb/query.py --kb knowledge --cluster <domain>    # peers of a domain
  python3 tools/kb/query.py --kb knowledge --entity <value>      # one entity, facts + edges + provenance
  ```
- **Writes (output contract — every assessment is persisted, not just spoken):**
  1. A cited assessment file at a **fixed path**: `knowledge/reports/<case>/assessment.md`,
     following the §7 schema exactly (BLUF → Cluster table → Attribution → Gaps & alternatives →
     Next steps). Writing the assessment only into the chat is not "done" — save the file, then
     summarize it in the reply. Re-running an assessment overwrites the same path.
  2. When your judgment changes a rating, the **updated confidence back into the store** (so the
     next run inherits it), keeping provenance.
  3. Optional but recommended: hand the `case_graph.json` to `IntelGraph` and drop the rendered
     `network.html` beside the report in `knowledge/reports/<case>/`.

## Method

```
Triage facts → Correlate into clusters → Attribute (same-kit vs same-operator vs same-actor)
   → Calibrate confidence → Form & falsify hypotheses → Prioritise next pivots → Write the assessment
```

---

## 0. Opening a case — first moves  ▢ TUNE  (in-case notes)

**Collect broad BEFORE you theorize.** The opening pass is deliberately maximal — get the
widest concrete footprint first, because the domain that looks central often isn't.

1. **Bulk-collect the whole set; don't narrow early.** Run WebPivot artifact extraction +
   WHOIS (current **and** history) + a page capture across *every* seed domain at once.
   Gather more than you think you need — correlation comes after collection, not during.
2. **Start from the seed / initial domain** — the one closest to the case origin (the tip
   that opened the case). Read it first, but do **not** assume it's the hub; the real broker
   is often a sibling (betweenness centrality tells you which, later).
3. **Read the naming pattern by eye** before tooling — brand families, TLD rotation,
   transliteration tells — to pre-guess sub-groups.
4. **Anchor on the registrant email / identity.** The email that registered the domains is
   the most concrete glue — build the spine from WHOIS (recover it from *history* when the
   current record is privacy-masked), then hang artifacts off that spine.
5. **Prioritise artifacts that are UNIQUE to the site or its paid services**, most-concrete first:
   registrant email/name → owner-account tokens (GA4/GTM, SEO/ads UUIDs, ahrefs/GSC/Bing) →
   **origin IP** (true backend, *not* the shared CDN/hosting edge — see §1) → on-page DOM
   artifacts the operator uses to get paid/contacted (phone, Zalo/Messenger, email, distinctive
   page schema/template), any comments that are unique to the build, and finally the favicon hash (stronger if it's a niche/custom kit). also check for a reused crypto wallet address (e.g. BTC, ETH, USDT) — if it's reused across sites, it's a strong same-operator artifact. Some typo of the website name in the domain name is also a medium signal of same-operator.
6. **Acquire by hostility.** Passive-first (Wayback / urlscan / crt.sh) for clearly adversarial
   targets; live fetch from a safe egress for low-risk ones. Judge per target, not one rule.

Executable recipe: `Workflows/OpenCase.md`.

## 1. Artifact triage ladder  ▢ TUNE WITH YOUR EXPERIENCE

Not all shared artifacts are equal. Rank every shared indicator before you reason about it.
Seeded from cases so far — **edit the tiers as you learn**:

| Tier | Weight | Artifacts | Why |
|---|---|---|---|
| **Attribution-grade** | high | registrant email/name, GA4/GTM property, ahrefs/GSC verification token, favicon hash on a *niche/custom* kit, reused crypto wallet | private, owner-controlled — a stranger can't share these by accident |
| **Corroborating** | medium | Messenger/contact handle, phone, distinctive template/DOM-skeleton hash, self-hosted third-party host | meaningful with ≥1 attribution-grade artifact; weak alone |
| **Noise** | low / drop | Cloudflare name servers, generic registrar (GoDaddy/Porkbun), shared CDN host, common favicon (WordPress default), `googletagmanager.com` | shared by millions; near-zero attribution value — keep for completeness, never assert on |

**Tells learned in-case (keep adding yours):**
- **Sequential GA/UA account numbers** = one operator batch-provisioned them in a sitting.
  A tight block like `UA-163843824` … `UA-164041825` across sibling sites is strong same-operator.
- **Shared WordPress theme** (e.g. `flatsome`) = weak-medium same-kit; **identical inline-CSS
  block or DOM-skeleton hash** across sites = stronger (same build, not just same theme).
- **Reverse-WHOIS count is a filter:** a registrant tied to a handful of thematically-coherent
  domains = attribution-grade; one tied to hundreds/thousands of unrelated domains = a shared
  reseller/agency = NOISE. Enforced by `tools/kb/ingest_reverse_whois.py --max-domains`.
- **Registrar/proxy contacts** (`abuse@`, `admin@onamae.com`, `registrar@inet.vn`, Domains-By-Proxy)
  and placeholder registrants ("domain expired", "Domain Admin C/O ID#…") are never the owner.
- **Origin IP ≠ hosting/CDN IP.** A shared *origin/backend* IP — a real server both
  sites resolve to, or an origin leaked from behind Cloudflare — is **attribution-grade infra**.
  A shared *edge/CDN/shared-host* IP (Cloudflare `104.21.x` / `172.67.x`, shared cPanel host) is
  **NOISE** — millions share it. Always resolve which kind before treating a shared IP as a link.
  *Enforced:* `WebPivot/tools/cdn_ranges.py` fetches published CDN/cloud ranges (Cloudflare,
  Fastly, AWS CloudFront, Google, BunnyCDN) and classifies each IP; `graph_build.py` drops
  CDN IPs and tags the rest `origin_candidate`. Run `cdn_ranges.py --update` to refresh ranges.
  Gap: CDNs with no public list (Akamai, Imperva) need ASN classification — see the tool's
  `NO_PUBLIC_LIST`.

▢ **Your rules:** _how you treat a GA4 ID that appears on 200 domains (link farm vs shared SEO agency); when a favicon is "niche" vs "off-the-shelf"; TLD-rotation patterns you've seen; Vietnamese-market registrar tells (Mat Bao, PA Vietnam, iNET)…_

**Captured (in-case — edit freely):**
- **Sequential handle aliases = one person.** `ductaibc1@ / ductaibc5@ / ductaibc20@gmail.com` is one identity, not three. Normalize `name+<n>@` families to a single actor before counting.
- **A thematically-coherent registrant is attribution-grade even under privacy.** "Nguyen Duc Tai" across the lambang*/baoxinviec* diploma set holds even when *current* WHOIS is a privacy proxy — recover it from WHOIS **history** (pre-privacy record), don't stop at the masked current record.
- **Mis-parsed / ad-network indicators are noise — drop, never assert.** `g-recaptcha` captured as a GA4 `G-` id (parser artifact); an AdSense `pub-…` or GA id shared across 80–100+ thematically-unrelated shops = a shared ad/SEO network, not one owner. (Same class as the reverse-WHOIS >200-domain reseller filter.)
- **Build fingerprints beat theme names.** A shared `wp_theme:flatsome` is weak same-kit; an identical **HTML-comment hash / inline-CSS hash / DOM-skeleton** across sites is strong same-build — and reaches domains outside the seed list (the `comment:e137c25e84d7747b` fingerprint spanned 41 sites incl. `quayvideoquangcao.xyz`).
- **Same WHOIS registration/expiry date = one batch, one actor.** Exact-same creation date (and the matching expiry, since expiry = created + term) across thematically-coherent domains means they were registered in one sitting by the same person — same class as sequential GA/UA numbers. Corroborating→same-operator; strongest with same registrar + a small coherent set, down-weight a huge set or a registrar bulk-promo default. In-case: `khacdaugia.net`+`lamcccdgia.net` both created 2023-07-12 (a 2nd signal for ID-card Cluster B beyond the shared phone); `baoxinviec.shop`+`lambangnhanh.vip` both 2024-07-20 (bridges the two Tai families). *Enforced:* `graph_build.py` models `regdate:<YYYY-MM-DD>` as a hub (day precision).

## 2. Correlation & the same-* distinction  ▢ TUNE

Three claims of increasing strength — never conflate them:

- **Same kit** — reused code/template/favicon. Says nothing about who runs it (kits are sold/shared).
- **Same operator** — shared *private* IDs/infra (GA4 property, verification token, registrant, wallet). One controller.
- **Same actor/person** — a named identity ties them (registrant name, reused email, phone).

**Corroboration rule (seeded):** assert *same-operator* only with **≥2 independent
attribution-grade artifacts**, or 1 attribution-grade + a named identity. One shared
generic artifact is a *lead*, not a finding.

▢ **Your thresholds:** _when you'll assert on a single artifact (which ones earn that trust); how you down-weight artifacts that co-occur because of a shared SEO/agency tool rather than a shared owner._

**Captured (in-case — edit freely):**
- **A shared phone / Zalo / Messenger handle is corroborating, never attribution.** Do NOT merge two clusters on a phone alone. Keep them separate until a registrant, verification token, or GA/GTM property confirms. (This is why the ID-card cluster — bound only by Zalo `0934893825` — was assessed a *separate* operator, not folded into the Tai ring.)
- **Resolve a theme-only cluster with a registrant lookup before asserting same-operator.** When sites bind only by a shared generic theme (`vnnews`), run WHOIS registrant-name before deciding — that's what reclassified `ringting/tingbing/tingzing.net` from "likely unrelated" to Tai's.
- **A named-identity bridge on ONE node can merge two artifact families.** `baoxinviec.org` carrying Tai's email *and* the lambangnhanh ahrefs token on the same page is enough to assert the two families are one operator — a single node that holds two families' private artifacts is attribution-grade glue.

## 3. Confidence calibration  ▢ TUNE

Blend source reliability × corroboration × recency into a 0–1 score. Starting model:

- base by tier (attribution-grade 0.9 / corroborating 0.6 / noise 0.3),
- **+** raise when ≥2 independent artifacts agree, **−** lower for stale data or single-source,
- keep the *provenance* — a claim's score is only as good as its `evidence_ref`.

▢ **Your calibration:** _the priors you actually trust per source (FOFA latest-index blind spots, urlscan freshness, WhoisXML history gaps), and how much a Vietnamese-registrar early record outweighs later privacy._

## 4. Hypothesis loop  ▢ TUNE

For each cluster, state the hypothesis, then **actively try to break it**:

1. **Hypothesis:** "Domains X, Y, Z are one operator."
2. **Disconfirm:** look for the artifact that *shouldn't* be shared if true — a different
   registrant, a conflicting GA property, an IP in a different ASN. Absence of
   disconfirming evidence ≠ proof; note what you couldn't check.
3. **Next pivot:** pick the lead most likely to confirm *or* refute cheaply (see §5).

▢ **Your heuristics:** _the "what would I check next" instincts — the tells that make you
suspicious of a coincidence; when a clean story is too clean._

## 5. Pivot prioritisation  ▢ TUNE

Rank open leads by **expected yield ÷ cost** (cost = API credits, time, attribution risk):

- prefer passive + free (crt.sh, Wayback, existing KB) before paid (FOFA/WhoisXML credits),
- prefer artifacts that *split* the hypothesis (confirm or kill it) over ones that merely add volume,
- a reverse lookup on a *named identity* (e.g. reverse-WHOIS on a leaked registrant) usually
  outranks another favicon sweep.

▢ **Your priorities:** _the order you'd actually run things given a credit budget._

## 6. Conflict handling

The store keeps disagreements (WHOIS vs RDAP, two registrants across history). **Surface
the conflict in the assessment**; don't silently pick one. A conflict is often the signal
(e.g. a pre-privacy record naming the real owner vs the later proxy).

## 7. Assessment write-up standard  ▢ TUNE

- **BLUF** — the finding in one sentence, with a confidence word (assessed / likely / possible).
- **Cluster** — domains + the shared artifacts that bind them (a table, each row cited).
- **Attribution** — same-kit / same-operator / same-actor, and the evidence for the level claimed.
- **Gaps & alternatives** — what you couldn't verify, and the competing explanation you ruled out.
- **Next steps** — the prioritised open pivots.

▢ **Your format:** _house style, client-facing vs internal, how you phrase confidence for a legal/takedown audience._

---

## Worked example (current case — replace as the KB grows)

`--shared` over the store yields: ahrefs token `d85dca…` on 4 domains, GA4 `G-PN3PJL74EJ`
+ GTM + favicon on the lambangnhanh family, Messenger `61591524489399` bridging
`baoxinviec.shop`↔`lambangnhanh.vip`, and a leaked registrant **Ông Lê Nhất Duy** on
`lambangnhanh.online`. Triaged: those are all attribution-grade except the Cloudflare NS
(noise). Corroboration: ≥2 attribution-grade artifacts across the set **and** a named
identity → **assessed same-operator, one named actor.** Next pivot (§5): reverse-WHOIS on
"Lê Nhất Duy" (named identity > another favicon sweep).
