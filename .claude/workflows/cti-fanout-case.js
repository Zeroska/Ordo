export const meta = {
  name: 'cti-fanout-case',
  description: 'Fan-out CTI case: reactive collector per seed, partition into clusters, then adversarially-verified judgement per cluster',
  whenToUse: 'Work a case whose seeds each deserve reactive per-seed collection (hostile/CF/empty handling) but should run concurrently, then be judged CLUSTER BY CLUSTER with every same-operator link adversarially refuted before it is committed — the Claude-Code mirror of orchestrator.collect_fanout (--fanout) + --parallel cluster judgement + the adversarial verify phase. args: { case, seeds:[...], keywords?:[...], expand?:bool, engines?:str, maxClusters?:int=3, maxLinks?:int=6 }.',
  phases: [
    { title: 'Search-expand', detail: 'multi-engine search on seeds/keywords → new candidate hosts (opt-in)' },
    { title: 'Collect', detail: 'one WebPivot collector agent per seed, concurrently' },
    { title: 'Ingest', detail: 'ingest all raw pivot JSON into the KB once' },
    { title: 'Partition', detail: 'split the case into same-operator clusters — the unit of judgement' },
    { title: 'Correlate', detail: 'per cluster: emit its same-operator links as structured pairs' },
    { title: 'Verify', detail: 'per cluster: 3 lens-skeptics refute the links; 2-of-3 kills one' },
    { title: 'Assess', detail: 'per cluster: ICD-203 assessment over the SURVIVING links only' },
  ],
}

// args: { case, seeds:[...], keywords?:[...], expand?:bool, engines?:"google,yandex,duckduckgo" }
const CASE = (args && args.case) || 'CASE-0001'
const SEEDS = (args && args.seeds) || []
const KEYWORDS = (args && args.keywords) || []          // distinctive slogans/IDs/handles to search
const ENGINES = (args && args.engines) || 'google,yandex,duckduckgo'
const EXPAND = !!(args && (args.expand || KEYWORDS.length))
if (!SEEDS.length && !KEYWORDS.length) throw new Error('pass args: { case, seeds:[...] } (or keywords:[...])')

// ── Phase 0: SEARCH-EXPAND (opt-in) — multi-engine search on each seed/keyword, fold NEW hosts in ──
// Uses the intel MCP tool search_pivot to build engine URLs, then fires them with Claude Code's own
// WebSearch (single-engine, free) + WebFetch (the readable duckduckgo html URL). This is the
// keyword→search→infrastructure loop the SDK exposes as the search_pivot tool.
if (EXPAND) {
  phase('Search-expand')
  const HOSTS_SCHEMA = {
    type: 'object',
    properties: {
      hosts: { type: 'array', items: { type: 'string' }, description: 'bare candidate hostnames found in results' },
      notes: { type: 'string' },
    },
    required: ['hosts'],
  }
  const seedHosts = new Set(SEEDS.map((s) => String(s).replace(/^https?:\/\//, '').split('/')[0].toLowerCase()))
  const indicators = [...SEEDS, ...KEYWORDS]
  const found = (await parallel(indicators.map((ind) => () =>
    agent(
      `Case ${CASE}. Multi-engine SEARCH pivot on the indicator: ${JSON.stringify(ind)}.\n` +
      `1. Call the intel MCP tool search_pivot(indicator=${JSON.stringify(ind)}, engines="${ENGINES}") ` +
      `(find it with ToolSearch) to get the dork queries + engine result URLs.\n` +
      `2. FIRE them with Claude Code's built-in tools: run WebSearch on the strongest 2-3 queries ` +
      `(Google/Yandex are single-engine there but free), and WebFetch the duckduckgo html.duckduckgo.com ` +
      `URL for a readable SERP. Google/Yandex bot-wall a plain WebFetch — don't WebFetch those.\n` +
      `3. From the results, extract CANDIDATE hostnames that plausibly belong to the same operator/campaign ` +
      `(lookalikes, mirrors, mentioned infra). Return bare hosts only — no schemes/paths. Skip mainstream ` +
      `sites (google, facebook, twitter/x, github, pastebin, news, the brand's real domain).`,
      { label: `search:${String(ind).slice(0, 40)}`, phase: 'Search-expand', schema: HOSTS_SCHEMA }
    )
  ))).filter(Boolean)
  const newHosts = [...new Set(found.flatMap((f) => f.hosts || [])
    .map((h) => String(h).replace(/^https?:\/\//, '').split('/')[0].toLowerCase())
    .filter((h) => h && h.includes('.') && !seedHosts.has(h)))]
  log(`search-expand: +${newHosts.length} new candidate host(s) from ${indicators.length} indicator(s)`)
  for (const h of newHosts) SEEDS.push(h)
}
if (!SEEDS.length) throw new Error('no seeds to collect (search-expand found nothing and no seeds given)')

// ── Phase 1: COLLECT — one reactive collector per seed, concurrent (semaphore = workflow cap) ──
phase('Collect')
const COLLECT_SCHEMA = {
  type: 'object',
  properties: {
    host: { type: 'string' },
    n_pivots: { type: 'integer' },
    verdict: { type: 'string', description: 'PIVOTABLE / NO-PIVOT-YET / COLLECTED, from fallback_probe when empty' },
    notes: { type: 'string' },
  },
  required: ['host', 'n_pivots', 'verdict'],
}
const collected = (await parallel(SEEDS.map((seed) => () =>
  agent(
    `You are ONE collector agent for case ${CASE}, working the SINGLE seed: ${seed}\n` +
    `Use the intel MCP tools (find them with ToolSearch: pivot_extract, fallback_probe).\n` +
    `1. Call pivot_extract on the seed with case=${CASE} (raw JSON is written under cases/${CASE}/raw/).\n` +
    `2. EMPTY-RESULT RULE: if it returns zero/near-zero pivots or a parked/empty-favicon/NXDOMAIN page ` +
    `(WHOIS+FOFA+urlscan all cold), you MUST call fallback_probe on the host before finishing and report its VERDICT.\n` +
    `Do NOT ingest — the workflow ingests every collector's output once, after all collectors finish.\n` +
    `Return only the structured result for THIS seed.`,
    { label: `collect:${seed}`, phase: 'Collect', schema: COLLECT_SCHEMA }
  )
))).filter(Boolean)
log(`collected ${collected.length}/${SEEDS.length} seed(s)`)

// ── Phase 2: INGEST — once, after the barrier, to avoid a concurrent KB write race ──
phase('Ingest')
await agent(
  `Ingest the raw pivot JSON for case ${CASE} into the KB using the intel MCP tool kb_ingest ` +
  `(find it with ToolSearch). Ingest the whole case once. Return a one-line summary of what was ingested.`,
  { label: 'ingest', phase: 'Ingest' }
)

// ── Phase 3: PARTITION — split the case into same-operator clusters BEFORE judging ──
// The unit of judgment is the CLUSTER, not the case. One correlate agent holding every seed is
// unfocused and blows context once a case passes ~10 domains; it is also N attribution questions
// pretending to be one. case_clusters is a pure KB read (no collection, no credits).
phase('Partition')
const CLUSTER_SCHEMA = {
  type: 'object',
  properties: {
    clusters: {
      type: 'array',
      description: 'Same-operator components, largest first',
      items: {
        type: 'object',
        properties: {
          id: { type: 'integer' },
          domains: { type: 'array', items: { type: 'string' } },
          binding_indicators: {
            type: 'array',
            description: 'Indicators binding the cluster, most distinctive first, with KB-wide prevalence',
            items: { type: 'string' },
          },
        },
        required: ['id', 'domains'],
      },
    },
    n_singletons: { type: 'integer', description: 'components with a single domain (nothing to correlate)' },
  },
  required: ['clusters'],
}
const partition = await agent(
  `Partition case ${CASE} into same-operator clusters. Call the intel MCP tool ` +
  `case_clusters(case="${CASE}") (find it with ToolSearch) and return its components.\n` +
  `Report ONLY multi-domain clusters in \`clusters\` (a singleton has nothing to correlate) and put ` +
  `the singleton count in n_singletons. Preserve each binding indicator's KB-wide prevalence in the ` +
  `string — an indicator binding 3 domains here but sitting on 400 KB-wide is noise, and the ` +
  `verifier needs to see that.`,
  { label: 'partition', phase: 'Partition', schema: CLUSTER_SCHEMA }
)
let clusters = ((partition && partition.clusters) || []).filter((c) => (c.domains || []).length > 1)
clusters.sort((a, b) => (b.domains || []).length - (a.domains || []).length)
const nSingletons = (partition && partition.n_singletons) || 0
// CAPS: bound the fan-out so a 200-domain case cannot spawn hundreds of agents. Both are
// args-overridable, and whatever they drop is logged — a silent cap reads as full coverage.
const MAX_CLUSTERS = (args && args.maxClusters) || 3
const MAX_LINKS = (args && args.maxLinks) || 6
if (clusters.length > MAX_CLUSTERS) {
  const dropped = clusters.slice(MAX_CLUSTERS)
  log(
    `CAP: judging the ${MAX_CLUSTERS} largest of ${clusters.length} multi-domain clusters. ` +
    `NOT judged: ${dropped.map((c) => `c${c.id}(${c.domains.length})`).join(', ')} — ` +
    `re-run with args.maxClusters to cover them.`
  )
  clusters = clusters.slice(0, MAX_CLUSTERS)
}
log(`partition: ${clusters.length} cluster(s) to judge, ${nSingletons} singleton(s) skipped`)
if (!clusters.length) {
  log('no multi-domain cluster — nothing to correlate. Collection is still ingested and on disk.')
  return { case: CASE, seeds: SEEDS, collected, clusters: [], results: [] }
}

// ── Phases 4-6: per-cluster CORRELATE → VERIFY → ASSESS, pipelined ──
// pipeline (not parallel): cluster B starts correlating while cluster A is already being verified.
// No barrier is needed — clusters are independent by construction.
const CORRELATE_SCHEMA = {
  type: 'object',
  properties: {
    links: {
      type: 'array',
      description: 'Every candidate same-operator link INSIDE this cluster: a domain pair + the shared artifact',
      items: {
        type: 'object',
        properties: {
          a: { type: 'string' },
          b: { type: 'string' },
          indicator: { type: 'string', description: 'e.g. favicon:123456789, ga:G-XXXXXXXXXX, cert-SAN' },
          tier: { type: 'string', description: 'owner-set | infra | boilerplate' },
        },
        required: ['a', 'b', 'indicator'],
      },
    },
  },
  required: ['links'],
}
const REFUTE_SCHEMA = {
  type: 'object',
  properties: {
    verdicts: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          a: { type: 'string' },
          b: { type: 'string' },
          indicator: { type: 'string' },
          refuted: { type: 'boolean', description: 'true if this is NOT a genuine same-operator link' },
          reason: { type: 'string', description: 'the benign / prevalence / competing explanation that broke it, or why it survived' },
        },
        required: ['a', 'b', 'indicator', 'refuted', 'reason'],
      },
    },
  },
  required: ['verdicts'],
}
const ASSESS_SCHEMA = {
  type: 'object',
  properties: {
    bluf: { type: 'string' },
    attribution_level: { type: 'string', enum: ['same-kit', 'same-operator', 'same-actor', 'inconclusive'] },
    confidence: { type: 'string', enum: ['low', 'moderate', 'high'] },
    cluster: { type: 'array', items: { type: 'object' } },
    evidence: { type: 'array', items: { type: 'string' } },
    gaps: { type: 'array', items: { type: 'string' } },
    next_pivots: { type: 'array', items: { type: 'string' } },
  },
  required: ['bluf', 'attribution_level', 'confidence', 'evidence', 'gaps', 'next_pivots'],
}
// One skeptic per LENS per cluster (not per link): 3 agents regardless of link count, and each
// sees the whole cluster — which is what prevalence reasoning actually needs. Still a 2-of-3
// panel vote per link, and it matches the SDK harness's single cluster-wide verify phase.
const LENSES = [
  'benign/prevalence — reference_check the indicator, and kb_entity/kb_query_shared it for how many UNRELATED domains carry it',
  'competing-explanation — shared host / CDN / registrar / SaaS platform / brand coincidence; if it explains the overlap as well as "same operator", the link is at best same-kit',
  'TLS/infra — cert_overlap the specific pair; only a SAN cross-cover survives, a shared CA or a managed wildcard cert does not',
]
const key = (l) => `${[l.a, l.b].sort().join('~')}|${l.indicator}`

const results = await pipeline(
  clusters,
  // 4. CORRELATE this cluster only
  (c) =>
    agent(
      `Correlate CLUSTER c${c.id} of case ${CASE} — these domains ONLY: ${c.domains.join(', ')}\n` +
      `Binding indicators from the partition: ${(c.binding_indicators || []).join('; ') || '(none reported)'}\n` +
      `Use the intel MCP tools (kb_cluster, kb_entity, cert_overlap, reference_check, which_cases — ` +
      `find them with ToolSearch). Apply the noise discipline: managed DNS, parking favicons and ` +
      `registrar-privacy emails are NOT operator links.\n` +
      `Emit EVERY candidate same-operator link inside this cluster as {a, b, indicator, tier}. Do NOT ` +
      `pre-filter borderline links — the next phase refutes them.`,
      { label: `correlate:c${c.id}`, phase: 'Correlate', schema: CORRELATE_SCHEMA }
    ),
  // 5. VERIFY — 3 lenses over this cluster's links, 2-of-3 refuted kills a link
  async (corr, c) => {
    let links = (corr && corr.links) || []
    if (links.length > MAX_LINKS) {
      log(`CAP: c${c.id} proposed ${links.length} links; verifying the first ${MAX_LINKS}. ` +
          `The rest are reported unverified and must NOT be treated as established.`)
      links = links.slice(0, MAX_LINKS)
    }
    if (!links.length) return { cluster: c, links: [], surviving: [], refuted: [] }
    const panels = (await parallel(LENSES.map((lens) => () =>
      agent(
        `Case ${CASE}, CLUSTER c${c.id}. Adversarially REFUTE these candidate same-operator links ` +
        `through ONE lens: ${lens}\n` +
        `Links:\n${JSON.stringify(links, null, 2)}\n` +
        `Use the intel MCP tools (reference_check, kb_entity, kb_query_shared, cert_overlap — find ` +
        `them with ToolSearch). Return a verdict for EVERY link above. Default to refuted=true when ` +
        `uncertain — the burden is on the link to survive.`,
        { label: `refute:c${c.id}:${lens.split(' ')[0]}`, phase: 'Verify', schema: REFUTE_SCHEMA }
      )
    ))).filter(Boolean)
    const votes = {}
    for (const p of panels) {
      for (const v of p.verdicts || []) {
        const k = key(v)
        votes[k] = votes[k] || { refuted: 0, total: 0, reasons: [] }
        votes[k].total += 1
        if (v.refuted) votes[k].refuted += 1
        votes[k].reasons.push(v.reason)
      }
    }
    const judged = links.map((l) => {
      const v = votes[key(l)] || { refuted: 0, total: 0, reasons: ['no verdict returned'] }
      // 2-of-3 refuted kills it; a link no panel voted on has not survived anything
      return { ...l, survives: v.total > 0 && v.refuted < 2, nRefuted: v.refuted, nVotes: v.total, reasons: v.reasons }
    })
    return {
      cluster: c,
      links: judged,
      surviving: judged.filter((l) => l.survives),
      refuted: judged.filter((l) => !l.survives),
    }
  },
  // 6. ASSESS this cluster over the SURVIVING links only
  async (v, c) => {
    if (!v.links.length) {
      return { cluster: c, assessment: null, note: 'no candidate links proposed for this cluster' }
    }
    log(`c${c.id}: ${v.surviving.length}/${v.links.length} link(s) survived the 2-of-3 panel`)
    const assessment = await agent(
      `Write the ICD-203 assessment for CLUSTER c${c.id} of case ${CASE} (domains: ${c.domains.join(', ')}).\n` +
      `Use an estimative word in the BLUF (assessed / likely / possible). Base the attribution ONLY on ` +
      `links that SURVIVED refutation; cite the refuted ones in gaps as competing explanations ruled ` +
      `out. If most links were refuted, drop the attribution level and confidence accordingly — ` +
      `"inconclusive" is a valid, honest answer.\n\n` +
      `SURVIVING LINKS:\n${JSON.stringify(v.surviving, null, 2)}\n\n` +
      `REFUTED LINKS:\n${JSON.stringify(v.refuted, null, 2)}`,
      { label: `assess:c${c.id}`, phase: 'Assess', schema: ASSESS_SCHEMA }
    )
    return { cluster: c, assessment, surviving: v.surviving, refuted: v.refuted }
  }
)

const ok = results.filter(Boolean)
log(`done: ${ok.length} cluster assessment(s); ${nSingletons} singleton(s) never judged`)
return {
  case: CASE,
  seeds: SEEDS,
  collected,
  n_clusters_judged: ok.length,
  n_singletons: nSingletons,
  caps: { maxClusters: MAX_CLUSTERS, maxLinks: MAX_LINKS },
  results: ok,
}
