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
