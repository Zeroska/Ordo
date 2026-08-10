# intelligence_assist — contributor rules

This repo ships **portable OSINT skills** (`WebPivot`, `IntelAnalysis`, `IntelGraph`,
`BinaryPivot`) plus shared tooling under `tools/`. The skills are imported onto other
machines and used by other people. Treat everything tracked here as **public-facing**.

## RULE 1 — Never put case / investigation data into a skill (CRITICAL)

Skills are **code + tradecraft only**. An investigation's data NEVER goes into a
`SKILL.md`, a workflow `.md`, a tool docstring/comment, a test fixture, or any tracked
file. This includes — in prose, comments, examples, fixtures, or hardcoded logic:

- **Real people / operators** — names, aliases, emails, phone / Zalo / Telegram / Messenger handles.
- **Real target infrastructure** — case domains, IPs, wallets, ASNs, hostnames.
- **Real owner artifacts** — actual GA4/GTM/UA IDs, ahrefs/GSC tokens, favicon/DOM hashes tied to a case.
- **Case identifiers** — `CASE-YYYY-NN` IDs, case-folder names, per-case hardcoded paths.
- **Operator PII / attribution** of any kind, even as a "worked example".

Investigation data lives ONLY in the git-ignored stores: `cases/`, `knowledge/`,
`MEMORY/`, `.env`, and the operator registry. It is never committed and never referenced
by identifier inside a skill.

## RULE 2 — Register every new tool/skill with the MCP (so Claude Code can use it)

When you add a **tool** or a **skill**, publish it through the one typed surface both front-ends
share (`harness/tools.py` → the SDK `orchestrator.py` **and** the stdio `harness/mcp_server.py`,
which auto-discovers every `@tool`). Do NOT leave a new capability reachable only as a raw
`python3 …` bash line.

- **New CLI tool** (`WebPivot/tools/*.py`, `tools/*.py`): wrap it as an `@tool(name, description,
  {params})` in `harness/tools.py`. `mcp_server.py` discovers it automatically (no second edit) and
  it appears to Claude Code via the repo-root `.mcp.json` server `intel`. Keep the description one
  tight paragraph — it is context cost paid on every SDK phase (see below).
- **New mode of an existing tool** (e.g. IPPivot is just `pivot_extract.py` with a bare-IP source):
  no new `@tool` — extend the existing tool's description so the model knows the new input/flag.
- **New skill** (`WebPivot`, `IntelAnalysis`, …): add its `SKILL.md`, symlink it into
  `~/.claude/skills/`, and if it exposes a scriptable step, surface that step as an `@tool` too.
- **Smoke-check registration:** `WebPivot/.venv/bin/python3 harness/mcp_server.py` then send a
  `tools/list` JSON-RPC — the new tool must be listed. In Claude Code, confirm with `/mcp`.

## RULE 3 — Separate DATA from LOGIC: reference lists live in JSON, never in code

An analyst must be able to tune a denylist, threshold or lookup table **without editing Python
and without a redeploy**. Code holds the *matching logic*; the values it matches against are data.

- **Any list, map or threshold an analyst may reasonably want to extend goes in a JSON file** —
  denylists/allowlists (managed DNS, parking hosts, privacy-proxy contacts, noise phones), scoring
  thresholds, ASN/CIDR tables, brand/keyword sets, provider registries. If you catch yourself
  appending a literal to a Python tuple/set/dict, it belongs in JSON instead.
- **Where it lives:** `<module>/references/<name>.json` — e.g. `WebPivot/references/cdn_ranges.json`,
  `IntelAnalysis/references/risk_indicators.json`, `tools/kb/references/noise_filters.json`.
- **Shape:** a top-level `_comment` explaining the file, then one object per group with its own
  `_comment` and a `values` array (or named scalars for thresholds). The `_comment` keys are the
  analyst's documentation — write them for a human who has never read the code. Keys beginning
  with `_` are ignored by loaders.
- **Loading:** use the shared loader — `wp_refs.py` (WebPivot), `kb_refs.py` (`tools/kb`),
  `bp_refs.py` (BinaryPivot), `ig_refs.py` (IntelGraph):
  `load_ref(ref_path(__file__, "<name>.json"), _FALLBACK)`. It
  **falls back to your minimal embedded default on missing/malformed/incomplete input and warns
  on stderr**. Never fail open silently — a filter that quietly returns `False` everywhere
  manufactures false clusters, which is worse than crashing. Keep the existing module-level
  constant names so importers don't break. The four loaders are **byte-identical copies on
  purpose** (each skill is imported standalone, so it can't depend on a repo-root package) with
  **distinct module names on purpose** (`tools/kb` and `WebPivot/tools` both land on `sys.path`
  in the same process, so a shared `refs.py` would collide); `tests/test_references.py` asserts
  they stay in sync.
- **One group, one owner.** If two modules match the same values, they read the same JSON group —
  never re-paste the list. That duplication is what let the registrant-noise denylists drift
  across six modules before this layer existed.
- **Normalise on load**, so analysts can enter values in any reasonable format (a phone as
  `+354.421 2434` or `3544212434`; a host with or without a trailing dot).
- **Test the data file itself** in `tests/test_references.py`: it asserts every `references/*.json`
  parses and is documented (`_comment` at the top and per group), that each consumer's loaded
  values are the JSON's and **not** the fallback's, and that a broken file degrades loudly. Add
  your new file's consumers to its `consumers` list — a module silently running on its stub still
  imports and still produces output, it just stops filtering. It runs in the eval gate too.
- **RULE 1 still applies.** These JSON files are tracked and public-facing: generic provider/
  infrastructure constants only, never case data. Case-specific tuning belongs in the git-ignored
  `knowledge/` store.

## Cost visibility

- **Anthropic model cost** (the agent's reasoning): the **SDK harness** captures the SDK's own
  `total_cost_usd` per phase and persists a per-run line to `cases/<case>/run_cost.jsonl`
  (`orchestrator._report_cost`) — that is the ledger to sum for "what did this case cost". In
  **interactive Claude Code** the model can't read its own `total_cost_usd`; run `/cost` to see it.
- **Third-party API credits are NOT in `total_cost_usd`.** `pivot_extract.py` and friends spend
  FOFA / WhoisXML / urlscan / IPinfo / Shodan / Censys / IntelX / SerpApi / ANY.RUN credits (and make **zero** Anthropic calls
  themselves). They are logged to `MEMORY/api_usage.jsonl` by `api_usage.record(...)` and reported
  via `WebPivot/tools/api_usage.py report` (or the `api_usage` MCP tool); every run also prints an
  "API usage this run" summary. State the split when reporting cost; don't imply `total_cost_usd`
  covers the API credits. **Any NEW licensed/metered API call MUST call `api_usage.record(...)`.**
- **Censys is the tightest quota — treat it as a budget, not a log.** 100 credits a MONTH on the
  free plan, no rollover, and the quota is **per account**, so overspending in one case removes
  Censys from every later case. A lookup is 1 credit, a search 5 — **and running the emitted CenQL
  in the web UI costs the same 5**, so the UI link is not a free escape hatch. Prefer the keyless
  CenQL builder and the 1-credit `cert` lookup; check `wp_censys.py budget` before a batch. The
  guard in `wp_censys` caps spend per month and per run from the same ledger.
- **A run's COLLECTION capability is also cost-visible.** `wp_capabilities.py` reports which keys
  are absent and what evidence class each absence removes; it is embedded in every result as
  `meta.capability`. Report a keyless/`--free-only` run as such — its zero API cost bought a
  correspondingly smaller search of the internet.

## When a skill genuinely needs an example

Use obvious, non-real placeholders — never a value lifted from a live case:

| Kind | Use |
|---|---|
| domain | `example.com`, `site-a.example`, `site-b.example` |
| email | `registrant@example.com`, `operator@example.com` |
| person / operator | `"Registrant Name"`, `Operator A`, `operator-a` |
| GA4 / GTM / UA | `G-XXXXXXXXXX`, `GTM-XXXXXXX`, `UA-100000001` |
| case ID | `CASE-0001` (or a CLI arg — never hardcode a real one) |
| favicon / hash | a clearly-synthetic value (e.g. `123456789`) |

Generic public constants are fine (registrar/privacy-proxy addresses, CDN ranges, the Wix
/ Sedo default-favicon hashes, real third-party SaaS *provider* hostnames) — they describe
the tooling, not a case.

## Before you commit

- Keep case data in `cases/` / `knowledge/` — never at the repo root. Stray root-level
  case files (`cases_*.txt`, `*_hosts.txt`) are git-ignored precisely because the `cases/`
  rule doesn't match root files; don't defeat that.
- Grep your diff for identifiers before committing a skill change, e.g.:
  ```bash
  git diff --cached | grep -inE 'CASE-20|@gmail|@163|G-[A-Z0-9]{6}|UA-[0-9]{6}' || echo clean
  ```
- If a tool needs case-specific behavior, take it as a **parameter/CLI arg**, don't bake
  the case into the code.

## Where things live (context map)

Jump to the right file instead of re-deriving structure each session. All paths are
tracked code/docs — **case data is never here** (see RULE 1); it lives only in the
git-ignored stores.

| When you need… | Read / edit |
|---|---|
| How a case runs end-to-end (Collect → Correlate → Assess) | `PIPELINE.md`, `harness/README.md` |
| The collector engine (pivot artifacts, WHOIS, JARM, impersonation) | `WebPivot/tools/pivot_extract.py` + the `WebPivot/tools/wp_*.py` modules |
| The CENSYS layer — CenQL query builder (keyless) + the three free-plan lookups (certificate `names`, host, web property). Free Censys = **lookup endpoints only**; search is Starter+ and degrades to a UI link. **100 credits/MONTH, per account, no rollover — and the UI link costs the same 5 credits as an API search**; the spend guard caps it per month + per run | `WebPivot/tools/wp_censys.py` (tool; `budget` subcommand) + `WebPivot/references/censys_queries.json` (fields/prices/tiers + `credit_budget`) + `references/Setup.md` (getting the key) |
| The URL-PATH layer — the path as a CAMPAIGN IDENTIFIER, for the technique where an operator makes the hostname carry no information (disposable numeric labels, fresh cert each, rotated weekly) and selects the branded template by PATH instead: `host-a/<kit>/`, `host-b/<kit>/`. Every host-level pivot (favicon/TLS/registrant/JARM) then sees unrelated sites; the kit directory is the one string that survives, because it is the operator's own routing. Emits `path:kit` + `path:template` with urlscan/`inurl:`/FOFA/Wayback-CDX reverse queries, and `patterns` reports one kit on N DISTINCT hosts + the mirror case `multi_kit_hosts`. BASE-RATE CONTROLLED — `/login`, `/assets`, `/api/v1`, a `.js` file emit NOTHING (`generic_segments`); a shared kit is SAME-KIT (`serves_kit` edge, medium), never same-operator | `WebPivot/tools/wp_paths.py` (`url_paths` tool; auto in `pivot_extract`, read from the FINAL url after redirects) + `WebPivot/references/url_paths.json` + `tools/kb/ingest_webpivot.py::_ingest_paths` + `IntelAnalysis/SKILL.md` §1.65 |
| The RAW-EVIDENCE CAPTURE — the bytes the host actually served: the DOM plus every JS and CSS the page loaded, each with its own sha256, plus a bundle `capture_sha256` over the sorted digests (cite THAT, not a directory path). Everything else the toolkit emits is DERIVED — assertions about a page that is gone in days. **Default ON whenever `--case` is set.** Timestamped and never overwritten: the diff between two captures dates a re-skin. BUDGETED and honest about it — same-site gets the large allowance, third-party a small one, and anything dropped is in `skipped_for_budget` with the manifest stamped INCOMPLETE. `wp_capture.py <dir>` re-hashes and detects tampering | `WebPivot/tools/wp_capture.py` (`capture_evidence` tool; `--capture` / `--no-capture` / `--no-capture-third-party`) + `WebPivot/references/capture.json` (budgets/kinds/layout) + `tests/test_paths_capture.py` (in the eval gate) |
| The ADVERTISING layer — what the operator BOUGHT, not what they provisioned. Two halves. (1) **Ads Transparency Center** via SerpApi: a domain's Google-**VERIFIED, paying** `advertiser_id` + the *funded by* legal name (an identity WHOIS privacy cannot hide and a re-skin cannot change — nobody re-verifies a new ad account per throwaway host), the REVERSE to every other domain that account advertised (**same-PAYER**, high — unless `agency_domain_threshold` says it is a media buyer, then the clients are facts, not edges), and — opening a creative — `ad_funded_by` (the verified LEGAL ENTITY, more precise than the display name) plus the per-region markets with per-market last-shown dates. The creative's destination link (the operator's own utm/gclid, i.e. the cloaking key) comes back only sometimes: text ads are commonly archived as a rendered image, and the live response nests everything under `search_information`, not where SerpApi's schema says. The live SERP `ads` block is BEST-EFFORT — Google serves it inconsistently to automated clients, so an empty one is never 'nobody advertises this keyword'. (2) **The click-keyed CLOAKING probe — FREE, no key**: many fraud pages serve the scam ONLY to arrivals with the right utm/gclid and show everyone else a decoy, so a bare-domain collection describes the decoy and its 'nothing found' is worthless. Plain view · ad-click view · plain CONTROL view; on `divergent` pivot_extract re-points at the click view and collects the real page. The control fetch is the falsification step — an unstable page returns `inconclusive_unstable`, never an evasion finding. A click id is never a pivot; keyless ≈ 55% | `WebPivot/tools/wp_serp.py` (`serp_ads` tool; `pivot_extract --serp` / `--serp-region` / `--ad-params` / `--cloak-probe`; `budget`) + `WebPivot/references/serpapi.json` (`ad_parameters` / `generic_values` / `clustering_policy` / `cloaking_probe` / `search_budget`) + `tools/kb/ingest_webpivot.py::_ingest_ads` + `tests/test_serp.py` (in the eval gate) |
| The INTELX layer — Intelligence X strong-selector search over a corpus outside the live internet (leaks, stealer logs, pastes, darknet, historical WHOIS) + the `phonebook` domain→emails/subdomains inventory. **Keyless ≈ 50%**: selectors classified and UI URLs emitted, nothing executed. **The stealer logs are QUERIED FIRST, in their own bucket-scoped pass** — IntelX returns a bounded page, so recycled public-breach rows would otherwise fill it and truncate the one log record away (a sort cannot recover what never came back); `logs_pass` is what makes an empty result a real negative. **Pivot the DOMAIN then the EMAIL**: a log is indexed by the URL the malware captured, so the case domain returns the machines that held credentials for it — victims, non-public panel URLs, and sometimes the operator's own box. Logs come back as `read_these` to open item by item; breach co-membership is NEVER a same-operator link (`clustering_policy` fails closed) | `WebPivot/tools/wp_intelx.py` (tool; `pivot_extract --intelx`; `search --logs-only`; `budget`) + `WebPivot/references/intelx.json` (`search_plan` = pass order + selector priority; selectors/buckets/policy/`search_budget`) + `references/Setup.md`. Judging an item (victim vs operator machine): `IntelAnalysis/SKILL.md` §1.7 + `Workflows/StealerLog.md` |
| The ANY.RUN layer — the SANDBOX (submit/history/report) plus the separate, limited TI Lookup licence over other people's detonations. **Submitting is gated: `submit()` returns a risk briefing and sends nothing without explicit per-submission confirmation** (outbound + attributable + irreversible; a URL detonation tells the operator they are sandboxed, and a free plan makes the task PUBLIC). Privacy defaults to `owner`, `public` refused, gate lives in the signature so config can only tighten it. Keyless ≈ 50%; shared threat family = same-KIT only | `BinaryPivot/tools/bp_anyrun.py` (tools; `analyze_artifact --anyrun` = lookups only; `keycheck`/`budget`) + `BinaryPivot/references/anyrun.json` (`submission_policy`, `privacy_types`, fields, `request_budget`) |
| The CAPABILITY / keyless-disclosure layer — which keys exist, what each absence removes, and the rule that a keyless run must SAY so before any "nothing found" (a missing reverse index ≠ evidence of absence) | `WebPivot/tools/wp_capabilities.py` (tool + `meta.capability` + the run banner) + `WebPivot/references/api_keys.json` (per-key consequences) + `WebPivot/SKILL.md` § *API keys* |
| The DOCUMENT / IMAGE metadata layer — downloads the PDFs and images a site HOSTS and reads `/Info` + XMP + EXIF (author, XMP DocumentID, copyright, GPS, camera, producer). Survives a re-skin because nobody re-exports the PDF when the brand changes. Generic tool/default-account values (`Microsoft Word`, `Windows User`) are recorded but NEVER clustered on, and the filter is applied on BOTH the pivot and the ingest path. An empty result is NORMAL (pipelines strip EXIF) and is never scored as tradecraft | `WebPivot/tools/wp_docmeta.py` (layer + standalone CLI + `doc_metadata` tool) + `WebPivot/references/docmeta.json` (extensions, generic lists, byte budget) + `tests/test_docmeta.py` |
| The LIVENESS layer — "is this host still serving the operator's content", decided by READING THE PAGE plus DNS, never by the HTTP status code alone. Stops two silent corruptions. **200 is not alive**: a parking page, a `Welcome to nginx` default page, an "Account Suspended" notice and a soft-404 all return 200 with a full document, and collecting off one harvests a template shared by millions of domains — that is how a parking favicon becomes a fifty-domain "cluster". **404/403 is not dead**: the server ANSWERED, so the name is registered, resolving and controlled; only the path is gone, or we specifically are refused (allowlist/geo-fence/cloaking). A CF interstitial is `blocked`, live=null — the page was never seen. Every state but `live`/`unresolved` sets **`reuse_watch`**, because operators park between campaigns and rebuild after takedowns while keeping the domain; only NXDOMAIN may report dead. Self-enforced policy: `require_content_for_live`, `never_dead_from_status`, `never_dead_when_blocked`, `min_signals` | `WebPivot/tools/wp_liveness.py` (`domain_liveness` tool; `classify()` offline, `probe()` live, `from_pivot_result()` for a stored capture — pass `case=` to judge hostile infra without sending a packet) + `WebPivot/references/liveness.json` (markers/parking NS/thresholds/state vocabulary/policy) + `tools/domain_table.py` (the Status column; `⟲` = reuse-watch) + `tests/test_liveness.py` (in the eval gate) |
| The CONTEXT BUDGET — one governor in front of every tool result, and a ceiling on the shim's transcript. `_governed` SWEEPS the module to bind each tool's name around its handler, so a tool added later cannot escape the cap by forgetting to opt in (the four hand-placed `blob[:6000]` slices are gone). Head AND tail are kept — our JSON leads with `meta`, list output summarises at the end — and **a cut is never silent**: the marker states the original size, forbids reading the gap as "nothing found", and names the full copy on disk. Collectors get the large allowance, status tools the default; `HARNESS_RESULT_CHARS` overrides per run. The OpenAI-compat shim trims by WHOLE ROUNDS (an orphaned `tool_calls`/`tool` pair is rejected outright by the provider) and never elides the system prompt or the original task | `harness/tools.py` (`_bounded` / `_governed` / `_budget_for`) + `harness/openai_backend.py` (`_trim_history` / `_cap_tool_output`) + `harness/references/context_budget.json` + `tests/test_context_budget.py` (in the eval gate) |
| The INTAKE layer — scope the run BEFORE the first request, and treat what the requester asserted ("this scam site", "their C2", "the domain impersonating us") as a HYPOTHESIS THE RUN TESTS, never a premise it inherits. Fixes three invisible failures: wrong POSTURE (the default profile is a direct live fetch, which on threat-actor infra is an attributable probe that tells the operator they are being examined), wrong OWNER (on a compromised host the WHOIS/favicon/cert/analytics are the VICTIM's — cluster on them and unrelated victims fuse into one imaginary estate; only the injected kit path is the operator's), and ANCHORING (a stated class makes every ambiguous artifact read as confirming). Six classes, each with its own fetch posture + clustering rule + disconfirming list. **Never blocks** — no context, or a non-interactive caller (`intel.py`/orchestrator/MCP/batch), degrades to `unknown` + passive-first and SAYS SO. The deliverable carries an explicit verdict on the claim (`supported`/`partially`/`not supported`/`contradicted`/`inconclusive`), where `not supported` on a keyless or blocked run is a fact about the COLLECTION, and `contradicted` is the most valuable thing an intake produces | `WebPivot/SKILL.md` §0 + `WebPivot/Workflows/Intake.md` (runbook) + `WebPivot/references/intake.json` (`target_classes` / `intake_questions` / `claim_verification` / `scope_switches` / `policy`) |
| The analyst / judgment layer (correlation, attribution, confidence) | `IntelAnalysis/` |
| The knowledge base (entities, clusters, noise filters, reference) | `tools/kb/` |
| Case state / resumable convergence loop | `tools/case_state.py`, `tools/intel.py` |
| Where a case artifact belongs — `cases/` vs `knowledge/` | `README.md` § *`cases/` vs `knowledge/`*. Short version: **every per-case deliverable lives in `cases/<case>/`**; `knowledge/` is the cross-case KB only. `assessment.md` is the analyst's and is never overwritten; the loop's render goes to `loop_assessment.md` |
| Register a tool or skill for the MCP + SDK (RULE 2) | `harness/tools.py` (auto-discovered by `harness/mcp_server.py`) |
| The TOOL-CALL GATE + LEDGER — one policy point in front of every tool call on all three front-ends (SDK `PreToolUse` hook / OpenAI-shim inline / stdio MCP), and one JSON line per call to `cases/<case>/tool_calls.jsonl`. Denies hostile egress across every outbound tool, an unapproved sandbox submission, and metered calls past the run's credit budget; a denial goes back to the MODEL so it adapts instead of dying. **Not `can_use_tool`** — `bypassPermissions` + whole-tool `allowed_tools` entries shadow it (the SDK warns and says to use the hook). Read it back with the `tool_calls` MCP tool or `harness/audit.py report <case> [--denied\|--tool\|--all]`; an absent ledger is ABSENCE OF RECORD, never "nothing happened" | `harness/audit.py` (gate + reader CLI) + `harness/references/tool_policy.json` + `tests/test_tool_gate.py` (in the eval gate) |
| Why a run STOPPED, and whether to continue — one `cases/<case>/state.json` vocabulary (`converged` / `cold` / `awaiting-analyst` / `error`) shared by the SDK driver and the deterministic loop, so either can resume the other. `cold` is a claim ("the free search is exhausted") and is never asserted from a failed frontier probe | `orchestrator._hand_back` + `tools/case_state.py` + `tools/intel.py loop` |
| Tunable reference DATA — denylists, thresholds, tables (RULE 3) | `<module>/references/*.json` — `tools/kb/` (`noise_filters`, `registrant_noise`), `WebPivot/` (`registrant_noise`, `third_party_noise`, `generic_labels`, `impersonation`, `mail_providers`, `pivot_tables`, `asn_registry`, `cdn_ranges`, `censys_queries`, `intelx`, `serpapi`, `api_keys`, `liveness`), `harness/` (`tool_policy`, `model_pricing`, `context_budget`), `BinaryPivot/` (`binary_indicators`, `anyrun`), `IntelAnalysis/references/risk_indicators.json`, `tools/kb/references/victim_profile.json` (panel signatures, access-vector hypotheses + thresholds), `IntelGraph/references/evidence_sources.json` (evidence permalinks, source grading, staleness) |
| The reference-data loader + its gate | `wp_refs.py` / `kb_refs.py` / `bp_refs.py` / `ig_refs.py` (identical), `tests/test_references.py` |
| The TEMPORAL layer — lifecycle timeline, hosting windows, expiry cohorts, evidence ledger | `IntelGraph/scripts/case_timeline.py` (tool) + `IntelAnalysis/SKILL.md` §1.5 & `Workflows/Timeline.md` (tradecraft) |
| The VICTIM layer — when the operator serves from hostnames they don't own; infers the ACCESS VECTOR (provider breach / panel exploit / CMS exploit / agency / stolen-or-bought credentials) from the victim set's shape | `tools/kb/victim_profile.py` (tool) + `IntelAnalysis/SKILL.md` §1.6 & `Workflows/VictimProfile.md` (tradecraft) |
| The two harness front-ends (SDK vs Claude-Code-native) | `harness/orchestrator.py`, `IntelHarness/` |
| Agent roles & phase prompts | `harness/agents.py`, `harness/prompts/` |
| Alternate model backend (DeepSeek/Kimi/local) | `harness/openai_backend.py` |
| The regression gate before changing `pivot_extract` | `tools/eval/run_eval.py` |
| The README's own diagrams — PlantUML sources are the EDITABLE original, the .svg/.png beside them are build output (never hand-edit those). `_theme.puml` shares the IntelGraph/IntelReport palette so a README figure, a case graph and a report figure look like one system. Two gotchas in this PlantUML build: inline `#fff;line:…` styling does not parse (use the stereotypes in `_theme.puml`) and a formatting tag opened before a `\n` leaks its closing tag (tag each LINE) | `docs/diagrams/*.puml` + `docs/diagrams/render.sh` |
| Report / diagram rendering | `IntelReport/`, `IntelGraph/`, `harness/render.py` |
| A report in VIETNAMESE (or another language) — `--lang vi` swaps only the GENERATED furniture (cover labels, TOC title, `Phụ lục`, figure/table captions, audience stamp) and picks a font that declares Vietnamese coverage. The BODY is never machine-translated: estimative terms are a calibrated ICD-203 scale, so the author writes in the target language using the fixed wording from `--glossary` | `IntelReport/scripts/render_report.py` (`--lang`, `--glossary`; `lang` on the `render_report` tool) + `IntelReport/references/report_i18n.json` (`strings` / `estimative_terms` / `section_names`) + `IntelReport/SKILL.md` § *Vietnamese reports* |
| The MCP surface exposed to Claude Code | `.mcp.json` (server `intel`), `harness/mcp_server.py` |
| Anthropic-model cost ledger vs third-party API credits | `cases/<case>/run_cost.jsonl` vs `MEMORY/api_usage.jsonl` (see **Cost visibility**) |
