---
name: BinaryPivot
description: Static IOC extraction from binaries pulled off fraud/scam sites — the file half of a scam funnel (sideloaded Android APK, desktop "trading terminal" .exe/.dmg/.msi, bundled .jar/.zip). Downloads/opens the artifact, hashes it, and pulls the operator-clustering identifiers that survive re-skinning: APK signing-cert SHA-256, package name + permissions, embedded backend/C2 hosts, Firebase/appspot cloud tenant, S3 buckets, crypto wallets, Telegram/WhatsApp handles. Emits WebPivot-shaped pivot JSON so the SAME KB/case graph clusters the app with the web infrastructure. USE WHEN analyze APK, analyze binary, analyze exe, analyze installer, scam app, trading app, sideloaded APK, extract IOCs from file, malware IOCs, signing certificate, package name, APK backend, C2 endpoint, firebase project, mobile app analysis, reverse the app, what does this app connect to, pivot from a downloaded file, app download funnel, ANY.RUN, anyrun, TI Lookup, sandbox report, has this hash been detonated, what did the sample contact, sandbox-observed C2, threat intelligence lookup for a hash, packed sample real endpoints.
---

> **OPSEC — this skill is portable/shared. Never write case data into it.** No real operator
> names, emails, domains, IPs, wallets, tracking IDs, hashes, or case IDs in this file, its
> workflows, tool code, or test fixtures. Investigation data lives only in the git-ignored
> `cases/` / `knowledge/` / `MEMORY/`. In examples use placeholders (`example.com`,
> `G-XXXXXXXXXX`, `CASE-0001`). See the repo-root `CLAUDE.md` for the full rule.

---

# BinaryPivot Skill

The sibling of **WebPivot**. WebPivot pivots on the *website*; BinaryPivot pivots on the *file the
website serves* — the sideloaded APK or desktop "terminal" that scam trading/investment funnels
push. It performs **static** extraction only (no detonation): download (or open a local file),
hash it, and pull the identifiers that cluster an operator's whole app portfolio even after they
re-skin the front end.

> ⚠️ **Authorization + safety first.** Only pull artifacts from infrastructure you are authorized
> to investigate, from **non-attributable egress** (research VPS/VPN). This tool never executes the
> sample — it is static analysis. For dynamic detonation use an isolated sandbox (MobSF, Triage,
> Any.Run), never your workstation.

## The tool — `tools/analyze_artifact.py`

**Zero required dependencies** (Python 3 stdlib). Optional accelerators used only if present:
`requests` (nicer download), `keytool` (APK signing cert — best pivot), `openssl` (cert fallback),
`file`/`strings`.

```bash
WP=~/.claude/skills/WebPivot ; BP=~/.claude/skills/BinaryPivot ; CASE=cases/<case>

# Pull an APK straight off the scam CDN and get ranked leads
python3 "$BP/tools/analyze_artifact.py" https://cdn.evil.example/app.apk --leads

# Analyze a local file, save the artifact + write case JSON (feeds the KB / graph)
python3 "$BP/tools/analyze_artifact.py" ./TradingPro.apk \
    --keep "$CASE/bin" -o "$CASE/raw/tradingpro.apk.json" --case <case>

# A desktop installer (Windows/macOS)
python3 "$BP/tools/analyze_artifact.py" https://cdn.evil.example/Setup.exe --leads
```

Flags: `--leads` (human-readable ranked pivots), `-o FILE` (full result JSON), `--pretty`
(pretty JSON to stdout), `--keep DIR` (save the downloaded file), `--case NAME` (stamped in meta).

## What it extracts

| Artifact | Why it's a pivot |
|---|---|
| **file sha256 / md5 / sha1** | VirusTotal / MalwareBazaar / Triage — prior sightings + sibling samples |
| **APK signing-cert SHA-256** | **strongest same-operator link** — clusters every app signed by one developer key; survives package/icon changes |
| **package name + version + permissions** | Koodous / APKPure listings; sensitive perms (SMS/CONTACTS/ACCESSIBILITY) flag the app's real intent |
| **embedded backend / C2 hosts + IP:port** | the app's real API — often *not* the download host; feed straight back into WebPivot |
| **Firebase project / appspot / storage bucket / API key** (google-services.json) | the operator's own Google Cloud tenant; RTDB may be world-readable (leaked leads/PII) |
| **S3 buckets, crypto wallets, Telegram/WhatsApp handles** | payout + recruitment infra reused across the portfolio |
| **embedded 2nd-stage payloads** (bundled dex/apk/dll/exe) | dropper behavior — a strong malicious tell |
| **PE compile timestamp / machine** (desktop installers) | build-time + arch fingerprint |
| **packer / protector / obfuscation** (entropy + section/member signatures) | *why* a sample's string sweep is thin — the real IOCs are encrypted inside; routes it to a dynamic sandbox. A **named** protector (UPX, VMProtect, Qihoo Jiagu, Tencent Legu, Ijiami…) is a **weak, kit-level** same-builder hint (`app_protector`) |

Supported containers: **APK/AAB** (manifest via a bundled pure-Python binary-XML parser, signing
cert via `keytool`/`openssl`), **JAR/ZIP**, **PE** (.exe/.dll), **Mach-O**, **ELF**, and a generic
`strings`-based sweep for anything else.

## How it clusters with the web case (the whole point)

The result is **WebPivot-shaped JSON** (`meta.host` + `artifacts.trackers{label:[values]}` +
`pivots[]`). The operator-clustering IOCs (`apk_signing_cert`, `apk_package`, `firebase_project`,
`app_backend_host`, `app_c2_endpoint`, wallets) are placed in `artifacts.trackers` so the **existing**
WebPivot KB ingester turns them into shared indicator nodes with no code changes:

```bash
# from the intelligence_assist project root — same ingest path as WebPivot
python3 tools/kb/ingest_webpivot.py --kb knowledge "$CASE"/raw/*.json
python3 tools/kb/query.py --kb knowledge --shared --min 2
```

A web domain and an APK that share a signing cert / backend host / Firebase project now land in the
**same cluster** in the case graph and the ICD-203 rollup — which is exactly how the app exposes the
operator behind a re-skinned website. Set `meta.host` to the **download host** (default when you pass
a URL) so the artifact anchors onto the site that served it.

## ANY.RUN — what the file DID, not just what it IS (**keyless ≈ 50% of it**)

Everything above is **static**: it reads the file. ANY.RUN's **Threat Intelligence Lookup** reports
what samples carrying these indicators actually **did when detonated** — the domains, IPs, URLs and
ports they contacted, the family label, Suricata alerts, and public sandbox sessions you can open
and watch. Two things follow, and the second is the reason this layer exists:

- **It recovers infrastructure static extraction cannot see.** A backend assembled at runtime, or
  decrypted out of a packed payload, is absent from the strings sweep *by construction*. So a thin
  result **plus** a `binary:protection` finding is the exact cue to call this — the operator's real
  endpoints are in someone's detonation record and nowhere else.
- **A contacted host is an observation, not a reputation score** — far stronger than "this string
  appears in the file", and it feeds straight back into **WebPivot**.

```bash
BP=~/.claude/skills/BinaryPivot
python3 "$BP/tools/bp_anyrun.py" query file:sha256 <sha256>     # OFFLINE: build the query, no key
python3 "$BP/tools/bp_anyrun.py" lookup --sha256 <sha256>       # 1 request
python3 "$BP/tools/bp_anyrun.py" lookup --ip 203.0.113.10:8443  # a C2 endpoint (auto-split)
python3 "$BP/tools/bp_anyrun.py" keycheck                       # TI Lookup is a SEPARATE licence
python3 "$BP/tools/analyze_artifact.py <target> --anyrun        # run it inside an analysis
```

- **Read-only. Nothing is ever submitted.** There is no detonation path here and the submission
  endpoint is deliberately absent from the reference file: submitting a scam-funnel sample spends a
  run, is visible to the operator on a public plan, and is an analyst's explicit decision made in
  the sandbox UI — not a side effect of a collector.
- **Only observation fields map.** Hashes, contacted domains/IPs/URLs, JARM. A **signing cert, an
  APK package name and a firebase project id are identity, not observation** — those get no ANY.RUN
  query (reverse them on VirusTotal / Koodous / Triage, which the pivot already carries).
- 🚫 **A shared threat FAMILY is same-KIT, never same-operator** — the same class of signal as a
  shared packer or a shared white-label CDN. Two crews running one commodity stealer are two crews.
  Policy: `references/anyrun.json → clustering_policy` (`cluster_on` vs `context_only`), enforced by
  `grade_field()`, which **fails closed** on anything unknown.
- **Metered**, capped per run and per month against the shared ledger
  (`references/anyrun.json → request_budget`, or `ANYRUN_MAX_REQUESTS_PER_RUN` /
  `ANYRUN_MONTHLY_REQUESTS`). A TI Lookup trial is tens of requests — spend them on the two or three
  artifacts that decide the case.
- 🔑 **Without `ANYRUN_API_KEY` the layer runs at ~50%** — it still composes the correct TI Lookup
  query for every indexable artifact (right field, `ip:port` split, bounded window) and gives you
  the UI address to paste it into, but **executes nothing**. A missing ANY.RUN section therefore
  does **not** mean the sample is unknown to the sandbox world. Say so before reporting it.

## Workflow — APK/binary in a scam funnel

1. **WebPivot flags the file.** Running `pivot_extract.py` on the scam site emits `app:apk` /
   `app:desktop_installer` pivots whose first query is the exact BinaryPivot command to run.
2. **Acquire + extract.** Run `analyze_artifact.py <url>` from non-attributable egress. Save the
   file (`--keep`) and the JSON (`-o "$CASE/raw/<host>.json"`).
3. **Pivot the identifiers.** Start with the signing cert (Koodous `cert:`), then package name,
   Firebase project, then each embedded backend host — **invoke the `WebPivot` skill** on those
   hosts (`pivot_extract.py https://<backend-host> --leads`) to map their web infrastructure.
4. **Corroborate + cluster.** Ingest into the KB; a shared signing cert **and** a shared backend host
   between two apps (or an app and a website) is high-confidence common ownership.
5. **Report at the cluster level.** Roll the app + its web siblings into one assessment with WebPivot's
   `evidence_report.py` (see WebPivot `Workflows/Reporting.md`) — trigger: *"output full report for
   that cluster"*.

## Trigger patterns

- "analyze this APK / .exe / installer", "what IOCs are in this app"
- "what does this trading app connect to", "find its backend / C2"
- "get the signing cert / package name", "cluster these scam apps"
- "pivot from the downloaded file", "the site pushes an APK — dig into it"
- "has anyone detonated this hash", "what did it contact when it ran", "sandbox report for this
  sample", "ANY.RUN this", "the sample is packed — where are the real endpoints"

## Notes on reliability

- **Signing cert** needs `keytool` (JDK) for v2/v3 schemes; `openssl` reads the v1 `META-INF/*.RSA`
  as a fallback. If both are absent the cert is skipped (everything else still runs).
- The binary `AndroidManifest.xml` is parsed with a **bundled pure-Python AXML decoder** (no aapt).
  On any parse error it degrades gracefully and the `strings`-based IOC sweep still runs.
- Host extraction is **noise-filtered**: reverse-DNS package names (`com.x.y`), class names,
  permission constants, and resource filenames (`config.json`, `libapp.so`) are rejected; hosts
  pulled from a real `http(s)://` URL are trusted.
- **All of those tables are data, in `references/binary_indicators.json` — extend it, not the
  Python.** Protectors and installers ship new signatures far faster than this tool changes, so
  when a sample comes back `protection: none` but is obviously wrapped, add the `.so` name /
  section name / byte signature to the right group and rerun. Groups: `fake_tlds` and
  `package_prefixes` (what is a filename, not a host), `pe_section_packers`,
  `installer_signatures`, `android_protectors`. Each carries a `_comment` with its match
  semantics (exact vs regex, and which order first-hit-wins applies in).
  If the tool prints a `[refs] WARNING` it is running on a stub table — fix the file.
- Static only — dead-code strings and library boilerplate can appear; corroborate a backend host by
  actually resolving/pivoting it before asserting it's live operator infra.
- **Packer / obfuscation triage** is entropy + signature based (`protection` block in the JSON;
  `⚠ PROTECTION:` line in `--leads`; a low-confidence `binary:protection` pivot). It detects UPX,
  the common PE protectors (VMProtect/Themida/ASPack/Enigma/MPRESS/…), Windows self-extractors
  (NSIS/Inno/InstallShield/7z-SFX), and the major Android app-protectors by their `.so`/asset
  signatures (Qihoo 360 Jiagu, Tencent Legu, Bangcle/SecNeo, Ijiami, Baidu, Alibaba, DexProtector,
  Promon, Virbox…), plus generic high-entropy `classes.dex`/asset blobs (encrypted-DEX packing).
  A **packed sample legitimately yields few IOCs** — that is the signal to detonate it in an
  isolated sandbox (MobSF/Triage), not to conclude the app is clean. A shared *named* protector is
  a **weak, kit-level** link (same builder/protection service), **not** proof of a common operator
  on its own — corroborate with a signing cert / backend host before clustering on it.
