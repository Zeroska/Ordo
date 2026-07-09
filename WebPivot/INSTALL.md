# WebPivot — Installation & User Guide

WebPivot is a Claude Code **skill** for authorized OSINT / cybercrime investigation.
It turns a single web page into a set of *pivot points* (favicon hash, analytics IDs,
crypto wallets, infra fingerprints) and ready-to-run queries, and — with API keys —
runs the top pivots live against FOFA and urlscan.

This guide covers installing it on any machine.

---

## 1. Prerequisites

| Requirement | Why | Check |
|---|---|---|
| **Claude Code** | The skill runs inside it | `claude --version` |
| **Python 3.8+** | The tools (`pivot_extract.py`, `wayback_ga.py`) | `python3 --version` |
| *(optional)* `pip install requests` | Faster/robust HTTP fetch | — |
| *(optional)* `pip install playwright && playwright install chromium` | `--render` for JS-heavy sites | — |

The core has **zero required dependencies** — it runs on the Python 3 standard library
alone (the Shodan-style favicon hash uses a bundled pure-Python MurmurHash3). The pip
packages above are only accelerators.

---

## 2. Where skills live

Claude Code discovers skills from these directories at startup:

- `~/.claude/skills/` — **user-global** (available in every project) ← use this
- `<your-project>/.claude/skills/` — project-local (only in that project)

A skill is a folder containing a `SKILL.md` with YAML frontmatter (`name:`, `description:`).
Dropping the folder in one of those paths is the entire "install."

---

## 3. Install (pick one)

### Option A — Simple copy (recommended for sharing with others)

```bash
# from wherever you received the WebPivot folder
cp -R WebPivot ~/.claude/skills/WebPivot
```

That's it. Restart Claude Code (or start a new session) and the skill is available.

### Option B — Symlink from a git repo (for developers / one source of truth)

Keep the skill in your project/repo and point the registry at it, so you edit **one**
place and the live skill updates instantly:

```bash
ln -s /absolute/path/to/your-repo/WebPivot ~/.claude/skills/WebPivot
```

Verify it's a symlink: `ls -ld ~/.claude/skills/WebPivot` should show `... -> /path/to/repo/WebPivot`.

> This is how the author's machine is set up: the repo copy is the source of truth and
> `~/.claude/skills/WebPivot` is a symlink to it.

---

## 4. Verify the install

```bash
# tool runs?
python3 ~/.claude/skills/WebPivot/tools/pivot_extract.py --help

# skill is registered? — in Claude Code, type:  /WebPivot
# or ask: "analyze example.com with WebPivot"
```

A quick offline smoke test (no network needed):

```bash
echo '<html><head><link rel="icon" href="/favicon.ico"></head></html>' \
  | python3 ~/.claude/skills/WebPivot/tools/pivot_extract.py - --leads
```

---

## 5. API keys (optional — unlocks live pivoting)

Without keys, WebPivot still works fully (extraction + query generation + passive
Wayback/urlscan). **With** keys it runs the HIGH-confidence pivots live: FOFA reverses
the favicon `icon_hash` and tracker/verification IDs, authenticated urlscan
content-searches the same values, WhoisXML adds current + historical registrant data and
reverse-WHOIS pivots, and real hits attach to each pivot.

Recognized variables: `URLSCAN_API_KEY`, `FOFA_KEY` (or `FOFA_API_KEY`), `FOFA_EMAIL`,
`WHOISXML_API_KEY`. Keys are read from the **environment first**, then an optional `.env`
file (env wins).

### Recommended — macOS Keychain (encrypted, nothing plaintext on disk)

```bash
security add-generic-password -a "$USER" -s URLSCAN_API_KEY -w   # prompts; not in shell history
security add-generic-password -a "$USER" -s FOFA_KEY -w
security add-generic-password -a "$USER" -s FOFA_EMAIL -w        # only for FOFA's classic API
security add-generic-password -a "$USER" -s WHOISXML_API_KEY -w  # whoisxmlapi.com
```

Then add to `~/.zshrc` (or `~/.bashrc`):

```bash
export URLSCAN_API_KEY="$(security find-generic-password -s URLSCAN_API_KEY -w 2>/dev/null)"
export FOFA_KEY="$(security find-generic-password -s FOFA_KEY -w 2>/dev/null)"
export FOFA_EMAIL="$(security find-generic-password -s FOFA_EMAIL -w 2>/dev/null)"
export WHOISXML_API_KEY="$(security find-generic-password -s WHOISXML_API_KEY -w 2>/dev/null)"
```

**Linux/Windows** equivalents: use `secret-tool` (GNOME Keyring) / `pass` on Linux, or
Windows Credential Manager — or just export the env vars in your shell profile.

### Simpler — a `.env` file (plaintext, lock it down)

The tools also read `~/.claude/PAI/USER/SKILLCUSTOMIZATIONS/WebPivot/.env` if present
(PAI setups). On a plain machine you can instead export the vars, or point your own
`.env` via your shell. Whatever file you use:

```bash
chmod 600 .env          # owner-only
echo ".env" >> .gitignore   # NEVER commit keys
```

**Never commit API keys or `.env` files to git.**

---

## 6. Everyday use

```bash
# ranked pivot leads for a page (markdown)
python3 ~/.claude/skills/WebPivot/tools/pivot_extract.py https://suspicious.example --leads

# full JSON of every artifact + pivot
python3 ~/.claude/skills/WebPivot/tools/pivot_extract.py https://suspicious.example --pretty

# render JS-heavy SPA first (needs playwright)
... --render --leads

# skip live FOFA/urlscan even if keys are set
... --leads --no-enrich

# historical analytics sweep (catches scrubbed IDs, passive)
python3 ~/.claude/skills/WebPivot/tools/wayback_ga.py suspect.example --max 15 --timeline
```

Inside Claude Code, just say *"analyze <site> with WebPivot"* or type `/WebPivot <domain>`.

> ⚠️ **Authorized investigations only.** See `EthicalFramework.md`. Fetching a hostile
> site touches it directly — prefer passive sources (Wayback/urlscan) or a
> non-attributable egress (research VPS/VPN) for adversarial targets.

---

## 7. Update

- **Copy install:** re-copy the new `WebPivot` folder over `~/.claude/skills/WebPivot`.
- **Symlink install:** just `git pull` in your repo — the symlink already points at it.

---

## 8. Uninstall

```bash
rm ~/.claude/skills/WebPivot        # removes the symlink OR the copied folder
```

(For a symlink this only removes the link, not your repo.)

---

## 9. Troubleshooting

| Symptom | Fix |
|---|---|
| `/WebPivot` doesn't appear | Restart Claude Code / new session; confirm the folder is directly under `~/.claude/skills/` and contains `SKILL.md`. |
| Duplicate skill entries | Don't leave backup folders (`WebPivot.bak`, etc.) **inside** `~/.claude/skills/` — each folder with a `SKILL.md` registers. Move backups elsewhere. |
| `total 0` from urlscan searches | Anonymous search doesn't index page content — set `URLSCAN_API_KEY`. |
| FOFA shows `[-700] 账号无效` | Invalid FOFA account/key — check `FOFA_KEY` (and `FOFA_EMAIL` for the classic API). |
| `playwright` errors on `--render` | `pip install playwright && playwright install chromium`, or drop `--render`. |
| Keys ignored | Confirm they're exported in the shell that launches Claude Code: `echo $FOFA_KEY`. Env overrides any `.env`. |
