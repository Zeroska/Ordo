export const meta = {
  name: 'cti-fanout-case',
  description: 'Fan-out CTI case: reactive collector per seed, then adversarially-verified correlate + assess',
  whenToUse: 'Work a case whose seeds each deserve reactive per-seed collection (hostile/CF/empty handling) but should run concurrently, with every same-operator link adversarially refuted before it is committed — the Claude-Code mirror of orchestrator.collect_fanout (--fanout) + the adversarial verify phase.',
  phases: [
    { title: 'Search-expand', detail: 'multi-engine search on seeds/keywords → new candidate hosts (opt-in)' },
    { title: 'Collect', detail: 'one WebPivot collector agent per seed, concurrently' },
    { title: 'Ingest', detail: 'ingest all raw pivot JSON into the KB once' },
    { title: 'Correlate', detail: 'cluster + emit the same-operator links as structured pairs' },
    { title: 'Verify', detail: 'panel of skeptics refutes each link; 2-of-3 kills it' },
    { title: 'Assess', detail: 'ICD-203 assessment over the SURVIVING links only' },
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

// ── Phase 3: CORRELATE — cluster + emit every same-operator link as a structured pair ──
phase('Correlate')
const CORRELATE_SCHEMA = {
  type: 'object',
  properties: {
    links: {
      type: 'array',
      description: 'Every candidate same-operator link: a pair of domains + the shared artifact tying them',
      items: {
        type: 'object',
        properties: {
          a: { type: 'string' },
          b: { type: 'string' },
          indicator: { type: 'string', description: 'e.g. favicon:123456789, ga:G-XXXXXXXXXX, cert-SAN, GTM-XXXXXXX' },
          tier: { type: 'string', description: 'owner-set | infra | boilerplate' },
        },
        required: ['a', 'b', 'indicator'],
      },
    },
    clusters: { type: 'array', items: { type: 'array', items: { type: 'string' } } },
  },
  required: ['links', 'clusters'],
}
const correlate = await agent(
  `Correlate case ${CASE} over the ingested KB using the intel MCP tools (kb_cluster with strong=true, ` +
  `kb_entity, cert_overlap, reference_check, which_cases — find them with ToolSearch). Apply the noise ` +
  `discipline (--strong only; treat managed DNS / parking favicons / registrar-privacy emails as NON-links). ` +
  `Seeds: ${SEEDS.join(', ')}\n` +
  `Emit EVERY candidate same-operator link as a {a, b, indicator, tier} pair, and the clusters they form. ` +
  `Do not pre-filter borderline links here — the next phase adversarially refutes them.`,
  { label: 'correlate', phase: 'Correlate', schema: CORRELATE_SCHEMA }
)
const links = (correlate && correlate.links) || []
log(`correlate proposed ${links.length} same-operator link(s)`)

// ── Phase 4: VERIFY — panel of 3 skeptics per link; 2-of-3 REFUTED kills it (default: refute) ──
phase('Verify')
const REFUTE_SCHEMA = {
  type: 'object',
  properties: {
    refuted: { type: 'boolean', description: 'true if this is NOT a genuine same-operator link' },
    reason: { type: 'string', description: 'the benign/prevalence/competing-explanation that broke it, or why it survived' },
  },
  required: ['refuted', 'reason'],
}
const LENSES = ['benign/prevalence', 'competing-explanation', 'TLS/infra']
const verified = await parallel(links.map((lk) => () =>
  parallel(LENSES.map((lens) => () =>
    agent(
      `Case ${CASE}. Adversarially REFUTE this candidate same-operator link via the "${lens}" lens.\n` +
      `Link: ${lk.a} <-> ${lk.b} via ${lk.indicator} (tier: ${lk.tier || 'unknown'}).\n` +
      `Use the intel MCP tools (reference_check the indicator; kb_entity/kb_query_shared for PREVALENCE; ` +
      `cert_overlap for TLS — find them with ToolSearch). A BENIGN verdict, an over-prevalent indicator ` +
      `(managed DNS / parking favicon / registrar-privacy email / platform GA-GTM / default template), or a ` +
      `shared CA-not-SAN cert all REFUTE the link. Default to refuted=true when uncertain — the burden is on ` +
      `the link to survive.`,
      { label: `refute:${lk.a}~${lk.b}:${lens}`, phase: 'Verify', schema: REFUTE_SCHEMA }
    )
  )).then((votes) => {
    const v = votes.filter(Boolean)
    const nRefuted = v.filter((x) => x.refuted).length
    const survives = nRefuted < 2 // 2-of-3 refuted kills the link
    return { ...lk, survives, nRefuted, reasons: v.map((x) => x.reason) }
  })
))
const surviving = verified.filter(Boolean).filter((l) => l.survives)
const refuted = verified.filter(Boolean).filter((l) => !l.survives)
log(`verify: ${surviving.length} link(s) survived, ${refuted.length} refuted (2-of-3 vote)`)

// ── Phase 5: ASSESS — ICD-203 assessment over the SURVIVING links only ──
phase('Assess')
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
const assessment = await agent(
  `Write the ICD-203 assessment for case ${CASE}. Use an estimative word in the BLUF (assessed / likely / ` +
  `possible). Base the attribution ONLY on the links that SURVIVED adversarial refutation; cite the refuted ` +
  `links in gaps as competing explanations ruled in. If most links were refuted, drop the attribution level ` +
  `and confidence accordingly.\n\n` +
  `SURVIVING LINKS:\n${JSON.stringify(surviving, null, 2)}\n\n` +
  `REFUTED LINKS (state these as ruled-out competing explanations in gaps):\n${JSON.stringify(refuted, null, 2)}`,
  { label: 'assess', phase: 'Assess', schema: ASSESS_SCHEMA }
)

return { case: CASE, seeds: SEEDS, collected, links, surviving, refuted, assessment }
