#!/usr/bin/env python3
"""
pivot_extract.py — WebPivot harness for OSINT / cybercrime investigation.

Extracts *pivot artifacts* from a web page's HTML/DOM — the fingerprints that
link one site to other sites, infrastructure, or actors — and emits ready-to-run
pivot queries (Shodan, PublicWWW, crt.sh, urlscan, etc.).

Design goals:
  * Zero required dependencies. Core runs on the Python 3 stdlib alone.
  * Graceful acceleration: uses `requests` if present, `playwright` for a
    rendered (post-JS) DOM with --render, `bs4` is NOT required.
  * Favicon mmh3 (Shodan-style) hash is computed with a bundled pure-Python
    MurmurHash3, so it works with no pip installs.

Usage:
  python3 pivot_extract.py <url|file> [--render] [--leads] [--pretty] [-o out.json]
  python3 pivot_extract.py https://example.com
  python3 pivot_extract.py page.html --leads          # just pivot suggestions
  cat page.html | python3 pivot_extract.py -           # read HTML from stdin

Output: JSON to stdout (default) with `artifacts`, `pivots`, and `meta`.

FOR AUTHORIZED INVESTIGATIONS ONLY. Fetches the target directly — use a
research VPS / non-attributable egress when investigating hostile infra.
"""

import sys
import os
import re
import json
import base64
import hashlib
import argparse
import concurrent.futures
from urllib.parse import urljoin, urlparse, urlencode, quote

# ------------------------------------------------------------------ optional deps
try:
    import requests  # noqa
    HAVE_REQUESTS = True
except Exception:
    HAVE_REQUESTS = False

import urllib.request
import urllib.error

try:
    import whois_enrich  # WhoisXML registration pivots (optional, same tools/ dir)
    HAVE_WHOIS = True
except Exception:
    HAVE_WHOIS = False

DEFAULT_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/122.0.0.0 Safari/537.36")


# =================================================================== credentials
# API keys are read from the environment FIRST (populate it via a macOS Keychain
# export in your shell profile — most secure, nothing plaintext on disk), then
# from an optional chmod-600 .env in the skill's customization dir. The env always
# wins over the file. With no key present, every network call degrades to the
# previous keyless behavior — nothing breaks.
_CUSTOMIZATION_ENV = os.path.expanduser(
    "~/.claude/PAI/USER/SKILLCUSTOMIZATIONS/WebPivot/.env")


def _load_customization_env(path: str = _CUSTOMIZATION_ENV) -> None:
    """Populate os.environ from a KEY=VALUE .env, never overriding an existing var."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, _, v = line.partition("=")
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
    except FileNotFoundError:
        pass
    except Exception:
        pass


_load_customization_env()


def _secret(*names):
    """Return the first non-empty env var among names, else None."""
    for n in names:
        v = os.environ.get(n)
        if v and v.strip():
            return v.strip()
    return None


def fofa_search(query: str, size: int = 100,
                fields: str = "host,ip,domain,title", timeout: int = 30):
    """Query the FOFA API for a raw query string (e.g. 'icon_hash="123"').

    Returns {'query','total','results':[{host,ip,domain,title}]} or {'error':...},
    or None if no FOFA key is configured. Needs FOFA_KEY (classic API also FOFA_EMAIL).
    """
    key = _secret("FOFA_KEY", "FOFA_API_KEY")
    if not key:
        return None
    params = {"key": key,
              "qbase64": base64.b64encode(query.encode()).decode(),
              "size": str(size), "fields": fields}
    email = _secret("FOFA_EMAIL")
    if email:
        params["email"] = email
    url = "https://fofa.info/api/v1/search/all?" + urlencode(params)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
    except Exception as e:
        return {"query": query, "error": str(e)}
    if data.get("error"):
        return {"query": query, "error": data.get("errmsg", "fofa error")}
    cols = fields.split(",")
    rows = [dict(zip(cols, row)) for row in data.get("results", [])]
    return {"query": query, "total": data.get("size", len(rows)), "results": rows}


def urlscan_search(query: str, limit: int = 100, timeout: int = 30):
    """Authenticated urlscan.io search for an arbitrary query (content/tracker/token).

    Sends the API-Key header when URLSCAN_API_KEY is set — that unlocks the
    content-index searches that anonymous search returns empty. Returns
    {'query','total','domains':[...]} or {'error':...}.
    """
    headers = {"User-Agent": DEFAULT_UA}
    key = _secret("URLSCAN_API_KEY")
    if key:
        headers["API-Key"] = key
    api = f"https://urlscan.io/api/v1/search/?q={quote(query)}&size={limit}"
    try:
        req = urllib.request.Request(api, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
    except Exception as e:
        return {"query": query, "error": str(e)}
    doms = []
    for res in data.get("results", []):
        d = res.get("page", {}).get("domain")
        if d and d not in doms:
            doms.append(d)
    return {"query": query, "total": data.get("total", len(doms)), "domains": doms[:60]}


def crtsh_search(domain: str, timeout: int = 25):
    """Certificate-transparency search via crt.sh for subdomains of `domain`.

    Keyless. Returns {'query','total','subdomains':[...]} or {'error':...}.
    crt.sh is frequently overloaded — errors are returned, never raised.
    """
    query = f"%.{domain}"
    api = "https://crt.sh/?" + urlencode({"q": query, "output": "json"})
    try:
        req = urllib.request.Request(api, headers={"User-Agent": DEFAULT_UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.load(r)
    except Exception as e:
        return {"query": query, "error": str(e)}
    subs = set()
    for row in data if isinstance(data, list) else []:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name and "@" not in name:
                subs.add(name)
    subs.discard(domain.lower())
    ordered = sorted(subs)
    return {"query": query, "total": len(ordered), "subdomains": ordered[:80]}


def passivedns_search(domain: str, timeout: int = 25):
    """Passive-DNS subdomain/IP lookup via HackerTarget (keyless).

    Returns {'query','total','hosts':[{host,ip}],'ips':[...]} or {'error':...}.
    HackerTarget replies in plaintext CSV (`host,ip`) — 'no results'/'API count
    exceeded' come back as prose, so they are treated as errors, not parsed.
    """
    api = "https://api.hackertarget.com/hostsearch/?" + urlencode({"q": domain})
    try:
        req = urllib.request.Request(api, headers={"User-Agent": DEFAULT_UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "ignore").strip()
    except Exception as e:
        return {"query": domain, "error": str(e)}
    if not body or "," not in body or "error" in body.lower() or "no results" in body.lower():
        return {"query": domain, "error": body[:120] or "no results"}
    hosts, ips = [], set()
    for line in body.splitlines():
        parts = line.split(",")
        if len(parts) >= 2:
            host, ip = parts[0].strip().lower(), parts[1].strip()
            hosts.append({"host": host, "ip": ip})
            if ip:
                ips.add(ip)
    return {"query": domain, "total": len(hosts),
            "hosts": hosts[:80], "ips": sorted(ips)[:40]}


# =================================================================== murmurhash3
def mmh3_x86_32(data: bytes, seed: int = 0) -> int:
    """Pure-python MurmurHash3 x86_32, signed — matches mmh3.hash() (Shodan)."""
    c1, c2 = 0xcc9e2d51, 0x1b873593
    length = len(data)
    h1 = seed & 0xffffffff
    rounded_end = length & 0xfffffffc
    for i in range(0, rounded_end, 4):
        k1 = ((data[i] & 0xff) | ((data[i + 1] & 0xff) << 8) |
              ((data[i + 2] & 0xff) << 16) | (data[i + 3] << 24)) & 0xffffffff
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xffffffff
        h1 = (h1 * 5 + 0xe6546b64) & 0xffffffff
    k1 = 0
    tail = length & 0x03
    if tail == 3:
        k1 = (data[rounded_end + 2] & 0xff) << 16
    if tail >= 2:
        k1 |= (data[rounded_end + 1] & 0xff) << 8
    if tail >= 1:
        k1 |= (data[rounded_end] & 0xff)
        k1 = (k1 * c1) & 0xffffffff
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xffffffff
        k1 = (k1 * c2) & 0xffffffff
        h1 ^= k1
    h1 ^= length
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xffffffff
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xffffffff
    h1 ^= (h1 >> 16)
    return h1 - 0x100000000 if h1 & 0x80000000 else h1


def shodan_favicon_hash(raw: bytes) -> int:
    """Shodan/FOFA favicon hash = mmh3 of MIME-base64(favicon bytes)."""
    return mmh3_x86_32(base64.encodebytes(raw))


# =================================================================== fetching
def fetch(url: str, timeout: int = 20, ua: str = DEFAULT_UA):
    """Return (final_url, status, headers_dict, body_bytes). Follows redirects."""
    if HAVE_REQUESTS:
        r = requests.get(url, headers={"User-Agent": ua}, timeout=timeout,
                         allow_redirects=True, verify=True)
        return r.url, r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.content
    req = urllib.request.Request(url, headers={"User-Agent": ua})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            headers = {k.lower(): v for k, v in resp.headers.items()}
            return resp.geturl(), resp.status, headers, resp.read()
    except urllib.error.HTTPError as e:
        return url, e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, e.read()


def render_dom(url: str, timeout: int = 30, ua: str = DEFAULT_UA):
    """Return post-JS rendered HTML using Playwright (chromium). Requires playwright."""
    from playwright.sync_api import sync_playwright  # optional
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(user_agent=ua)
        page = ctx.new_page()
        page.goto(url, timeout=timeout * 1000, wait_until="networkidle")
        html = page.content()
        final_url = page.url
        cookies = ctx.cookies()
        browser.close()
    return final_url, html, cookies


# ---------------------------------------------------------- passive fallback
def wayback_closest(url: str, ua: str = DEFAULT_UA):
    """Nearest available Wayback snapshot for a URL, or (None, None).

    Tries the availability API, then the CDX API as a backup. Prints a distinct
    notice on HTTP 429 so callers don't misread throttling as 'not archived'.
    """
    import urllib.parse
    q = urllib.parse.quote(url, safe="")
    # 1) availability API (lightest)
    api = "http://archive.org/wayback/available?url=" + q
    try:
        req = urllib.request.Request(api, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=25) as r:
            snap = json.load(r).get("archived_snapshots", {}).get("closest", {})
        if snap.get("available") and snap.get("url"):
            return snap["url"], snap.get("timestamp")
    except urllib.error.HTTPError as e:
        if e.code == 429:
            print("[!] archive.org rate-limited (429) — retry later or use a saved snapshot",
                  file=sys.stderr)
    except Exception:
        pass
    # 2) CDX backup — last 200 HTML capture
    host = urlparse(url if url.startswith("http") else "http://" + url).netloc or url
    cdx = (f"http://web.archive.org/cdx/search/cdx?url={host}&output=json"
           f"&filter=statuscode:200&limit=-1")
    try:
        req = urllib.request.Request(cdx, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=30) as r:
            rows = json.load(r)
        if rows and len(rows) > 1:
            ts, orig = rows[-1][1], rows[-1][2]
            return f"https://web.archive.org/web/{ts}id_/{orig}", ts
    except Exception:
        pass
    return None, None


def urlscan_intel(host: str, ua: str = DEFAULT_UA, limit: int = 20):
    """urlscan.io search for prior scans of a host: related domains/IPs/ASNs.

    Sends the API-Key header when URLSCAN_API_KEY is set (higher rate limits and
    access to results anonymous search omits); otherwise runs keyless as before.
    """
    out = {"query": host, "total": 0, "related_domains": [], "ips": [], "asns": [],
           "servers": [], "recent_scans": []}
    try:
        api = f"https://urlscan.io/api/v1/search/?q=domain:{host}&size={limit}"
        req_headers = {"User-Agent": ua}
        _uk = _secret("URLSCAN_API_KEY")
        if _uk:
            req_headers["API-Key"] = _uk
        req = urllib.request.Request(api, headers=req_headers)
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.load(r)
    except Exception as e:
        out["error"] = str(e)
        return out
    out["total"] = data.get("total", 0)
    doms, ips, asns, servers = set(), set(), set(), set()
    for res in data.get("results", []):
        p = res.get("page", {})
        if p.get("domain"):
            doms.add(p["domain"])
        if p.get("ip"):
            ips.add(p["ip"])
        if p.get("asn"):
            asns.add(f"{p.get('asn')} {p.get('asnname', '')}".strip())
        if p.get("server"):
            servers.add(p["server"])
        out["recent_scans"].append({
            "url": p.get("url"), "time": res.get("task", {}).get("time"),
            "result": f"https://urlscan.io/result/{res.get('_id')}/",
        })
    out["related_domains"] = sorted(doms)[:40]
    out["ips"] = sorted(ips)[:40]
    out["asns"] = sorted(asns)[:20]
    out["servers"] = sorted(servers)[:20]
    out["recent_scans"] = out["recent_scans"][:limit]
    return out


def wayback_save(url: str, ua: str = DEFAULT_UA, timeout: int = 40):
    """Submit a URL to the Wayback Machine's Save Page Now. Returns a dict with the
    archived snapshot URL (or an error). Passive-safe: it makes web.archive.org fetch the
    page, so the archive box (not you) touches the target from then on."""
    save_url = "https://web.archive.org/save/" + url
    try:
        # requests follows the redirect to the created snapshot; note Content-Location too
        if HAVE_REQUESTS:
            r = requests.get(save_url, headers={"User-Agent": ua}, timeout=timeout,
                             allow_redirects=True)
            snap = r.headers.get("Content-Location") or ""
            if snap and not snap.startswith("http"):
                snap = "https://web.archive.org" + snap
            return {"snapshot": snap or r.url, "status": r.status_code}
        req = urllib.request.Request(save_url, headers={"User-Agent": ua})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            cl = resp.headers.get("Content-Location") or ""
            snap = ("https://web.archive.org" + cl) if cl else resp.geturl()
            return {"snapshot": snap, "status": resp.status}
    except Exception as e:
        return {"error": str(e)}


def urlscan_submit(url: str, timeout: int = 30, visibility: str = "unlisted"):
    """Submit a URL to urlscan.io for a fresh scan (needs URLSCAN_API_KEY). Returns the
    api/result URLs + scan UUID, or an error/'no key'. This actively enqueues a new scan
    (vs urlscan_search/urlscan_intel which only read existing scans)."""
    key = _secret("URLSCAN_API_KEY")
    if not key:
        return {"skipped": "no URLSCAN_API_KEY"}
    try:
        payload = json.dumps({"url": url, "visibility": visibility}).encode()
        if HAVE_REQUESTS:
            r = requests.post("https://urlscan.io/api/v1/scan/", data=payload, timeout=timeout,
                              headers={"API-Key": key, "Content-Type": "application/json"})
            j = r.json()
        else:
            req = urllib.request.Request("https://urlscan.io/api/v1/scan/", data=payload,
                                         headers={"API-Key": key, "Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                j = json.loads(resp.read().decode("utf-8", "ignore"))
        if j.get("uuid"):
            return {"uuid": j["uuid"], "result": j.get("result"), "api": j.get("api"),
                    "visibility": j.get("visibility", visibility)}
        return {"error": j.get("message") or j.get("description") or str(j)[:200]}
    except Exception as e:
        return {"error": str(e)}


# =================================================================== extractors
# --- tracking / analytics / ad IDs: (label, regex, pivot-hint)
TRACKER_PATTERNS = [
    ("google_analytics_ua", r"\bUA-\d{4,10}-\d{1,4}\b"),
    ("google_analytics_ga4", r"\bG-[A-Z0-9]{8,12}\b"),
    ("google_tag_manager",   r"\bGTM-[A-Z0-9]{4,10}\b"),
    ("google_ads",           r"\bAW-\d{6,12}\b"),
    ("google_adsense",       r"\bca-pub-\d{10,20}\b|\bpub-\d{10,20}\b"),
    ("google_doubleclick",   r"\bDC-\d{6,12}\b"),
    ("facebook_pixel",       r"fbq\(\s*['\"]init['\"]\s*,\s*['\"](\d{10,20})['\"]"),
    ("facebook_appid",       r"fb:app_id['\"]?\s*[:=]\s*['\"]?(\d{10,20})"),
    ("yandex_metrika",       r"ym\(\s*(\d{6,10})\s*,"),
    ("hotjar",               r"hjid\s*[:=]\s*(\d{5,9})"),
    ("matomo_piwik",         r"setSiteId['\"]?\s*,\s*['\"]?(\d{1,6})['\"]?|idsite=(\d{1,6})"),
    ("segment_writekey",     r"analytics\.load\(\s*['\"]([A-Za-z0-9]{20,40})['\"]"),
    ("mixpanel",             r"mixpanel\.init\(\s*['\"]([a-f0-9]{20,40})['\"]"),
    ("sentry_dsn",           r"https://[a-f0-9]{20,64}@[\w.-]+/\d+"),
    ("cloudflare_beacon",    r"beacon\.min\.js['\"].*?token['\"]?\s*:\s*['\"]([a-f0-9]{16,64})['\"]"),
    ("clarity_ms",           r"clarity\(\s*['\"]set['\"]|c\.clarity\.ms/tag/([a-z0-9]{8,12})"),
    ("intercom_appid",       r"app_id\s*[:=]\s*['\"]([a-z0-9]{6,10})['\"]"),
    ("crisp_website",        r"CRISP_WEBSITE_ID\s*=\s*['\"]([a-f0-9-]{30,40})['\"]"),
]

CRYPTO_PATTERNS = [
    ("btc",   r"\b(bc1[a-zA-HJ-NP-Z0-9]{25,90}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
    ("eth",   r"\b0x[a-fA-F0-9]{40}\b"),
    ("xmr",   r"\b[48][0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),
    ("tron",  r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b"),
    ("ltc",   r"\b(ltc1[a-z0-9]{25,90}|[LM3][a-km-zA-HJ-NP-Z1-9]{26,33})\b"),
]

SOCIAL_HOSTS = {
    "twitter.com": "twitter", "x.com": "twitter", "t.me": "telegram",
    "telegram.me": "telegram", "facebook.com": "facebook", "instagram.com": "instagram",
    "linkedin.com": "linkedin", "youtube.com": "youtube", "youtu.be": "youtube",
    "tiktok.com": "tiktok", "github.com": "github", "discord.gg": "discord",
    "discord.com": "discord", "vk.com": "vk", "wa.me": "whatsapp",
    "api.whatsapp.com": "whatsapp", "medium.com": "medium", "reddit.com": "reddit",
    "m.me": "messenger", "zalo.me": "zalo", "zaloapp.com": "zalo",
}

# Site-ownership verification tokens — strongly owner-tied, excellent pivots.
VERIFICATION_META = {
    "google-site-verification": "google_search_console",
    "msvalidate.01": "bing_webmaster",
    "yandex-verification": "yandex_webmaster",
    "facebook-domain-verification": "facebook_domain",
    "p:domain_verify": "pinterest",
    "ahrefs-site-verification": "ahrefs",
    "naver-site-verification": "naver",
}

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
PHONE_RE = re.compile(r"(?<![\w.])(\+?\d[\d\s().\-]{7,16}\d)(?![\w.])")
SCRIPT_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)
INLINE_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.I | re.S)
LINK_HREF_RE = re.compile(r"<(?:a|link)[^>]+href=[\"']([^\"']+)[\"']", re.I)
FORM_RE = re.compile(r"<form[^>]*>", re.I)
FORM_ACTION_RE = re.compile(r"action=[\"']([^\"']+)[\"']", re.I)
INPUT_NAME_RE = re.compile(r"<input[^>]+name=[\"']([^\"']+)[\"']", re.I)
META_RE = re.compile(r"<meta[^>]+>", re.I)
COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
FAVICON_RE = re.compile(r"<link[^>]+rel=[\"'][^\"']*icon[^\"']*[\"'][^>]*>", re.I)
HREF_IN_TAG_RE = re.compile(r"href=[\"']([^\"']+)[\"']", re.I)
TAG_RE = re.compile(r"<([a-zA-Z][a-zA-Z0-9]*)")


def _attr(tag: str, name: str):
    m = re.search(name + r"=[\"']([^\"']*)[\"']", tag, re.I)
    return m.group(1) if m else None


def uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def strip_www(host: str) -> str:
    """Remove a leading 'www.' prefix (lstrip('www.') would eat stray w/./ chars)."""
    host = (host or "").lower()
    return host[4:] if host.startswith("www.") else host


_WAYBACK_RE = re.compile(r"^https?://web\.archive\.org/web/\d+[a-z_]*/(https?://.+)$", re.I)


def unwrap_wayback(url: str) -> str:
    """A Wayback URL (web.archive.org/web/<ts><mod>/<orig>) -> the original URL."""
    if not url:
        return url
    m = _WAYBACK_RE.match(url)
    return m.group(1) if m else url


def extract_trackers(html: str):
    found = {}
    for label, pat in TRACKER_PATTERNS:
        vals = []
        for m in re.finditer(pat, html, re.I):
            v = next((g for g in m.groups() if g), m.group(0)) if m.groups() else m.group(0)
            vals.append(v)
        if vals:
            found[label] = uniq(vals)
    return found


# --- SaaS / no-code funnel tokens: operator-controlled IDs on hosted-builder pages
# (GoHighLevel, Make/Zapier/Apps-Script automations, backend Google Sheets). These are
# attribution-grade — a stranger can't share your GHL sub-account or automation webhook.
# The separator class handles raw "/", escaped "\/", and unicode-escaped "/".
_SEP = r"(?:/|\\/|\\u002[fF])+"
SAAS_PATTERNS = [
    # GoHighLevel sub-account (location) id — in media URLs: storage.googleapis.com/msgsndr/<id>, assets.cdn.filesafe.space/<id>
    ("gohighlevel_location", rf"(?:msgsndr|filesafe\.space){_SEP}([A-Za-z0-9]{{18,24}})"),
    # Backend Google Sheet id — SheetID:"...", spreadsheets/d/<id>, document/d/<id>
    ("google_sheet", r"""(?:SheetID["']?\s*[:=]\s*["']|spreadsheets/d/|document/d/)([A-Za-z0-9_-]{30,60})"""),
    # Make.com / Integromat automation webhook (operator endpoint)
    ("make_webhook", r"(hook\.[a-z0-9-]+\.make\.com/[A-Za-z0-9]{15,})"),
    ("integromat_webhook", r"(hook\.integromat\.com/[A-Za-z0-9]{15,})"),
    # Zapier catch hook
    ("zapier_webhook", r"(hooks\.zapier\.com/hooks/catch/[0-9]+/[A-Za-z0-9]+)"),
    # Google Apps Script web-app deployment
    ("apps_script", r"(script\.google\.com/macros/s/[A-Za-z0-9_-]{20,}(?:/exec)?)"),
    # TrustedForm — TCPA lead-cert; a lead-generation tell (not an operator id)
    ("trustedform", r"((?:api|cdn|cert)\.trustedform\.com)"),
]


def extract_saas(html: str):
    found = {}
    for label, pat in SAAS_PATTERNS:
        vals = []
        for m in re.finditer(pat, html, re.I):
            vals.append(m.group(1) if m.groups() else m.group(0))
        if vals:
            found[label] = uniq(vals)[:20]
    return found


def extract_crypto(text: str):
    found = {}
    for label, pat in CRYPTO_PATTERNS:
        vals = uniq(re.findall(pat, text))
        # eth regex sometimes eats other 0x — keep as-is; analyst validates
        if vals:
            found[label] = vals[:25]
    return found


def extract_socials(hosts_hrefs):
    out = {}
    for href in hosts_hrefs:
        try:
            host = strip_www(urlparse(unwrap_wayback(href)).netloc)
        except Exception:
            continue
        for shost, name in SOCIAL_HOSTS.items():
            if host == shost or host.endswith("." + shost):
                out.setdefault(name, []).append(href)
    return {k: uniq(v)[:20] for k, v in out.items()}


def extract_meta(html: str):
    meta = {}
    for tag in META_RE.findall(html):
        name = _attr(tag, "name") or _attr(tag, "property") or _attr(tag, "http-equiv")
        content = _attr(tag, "content")
        if name and content:
            meta[name.lower()] = content
    t = TITLE_RE.search(html)
    if t:
        meta["_title"] = re.sub(r"\s+", " ", t.group(1)).strip()[:300]
    return meta


def dom_skeleton_hash(html: str):
    """Structure-only fingerprint: hash of the ordered tag skeleton (template reuse)."""
    tags = TAG_RE.findall(html)
    skeleton = ">".join(t.lower() for t in tags)
    return hashlib.sha1(skeleton.encode("utf-8", "ignore")).hexdigest()


def tech_fingerprint(html: str, headers: dict, meta: dict):
    fp = []
    low = html.lower()
    gen = meta.get("generator", "")
    if gen:
        fp.append("generator:" + gen)
    if "wp-content" in low or "wp-includes" in low:
        fp.append("cms:wordpress")
    if "/sites/default/files" in low or "drupal-settings-json" in low:
        fp.append("cms:drupal")
    if "cdn.shopify.com" in low or "shopify" in gen.lower():
        fp.append("platform:shopify")
    if "wixstatic.com" in low or "wix.com" in low:
        fp.append("platform:wix")
    if "__next" in low or "/_next/" in low:
        fp.append("framework:nextjs")
    if "data-reactroot" in low or "react" in low[:20000]:
        fp.append("framework:react")
    for h in ("server", "x-powered-by", "x-generator", "x-aspnet-version", "via", "x-served-by"):
        if h in headers:
            fp.append(f"header:{h}={headers[h]}")
    jq = re.search(r"jquery[.\-/]?(\d+\.\d+\.\d+)", low)
    if jq:
        fp.append("lib:jquery@" + jq.group(1))
    return uniq(fp)


def get_favicon(base_url: str, html: str, ua: str):
    """Locate + fetch favicon, return hash dict or None."""
    href = None
    m = FAVICON_RE.search(html)
    if m:
        h = HREF_IN_TAG_RE.search(m.group(0))
        if h:
            href = h.group(1)
    if base_url:
        fav_url = urljoin(base_url, href) if href else urljoin(base_url, "/favicon.ico")
    elif href:
        fav_url = href
    else:
        return None
    if not fav_url.startswith("http"):
        return None
    try:
        _, status, _, raw = fetch(fav_url, ua=ua)
        if status != 200 or not raw:
            return None
        return {
            "url": fav_url,
            "shodan_mmh3": shodan_favicon_hash(raw),
            "md5": hashlib.md5(raw).hexdigest(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "bytes": len(raw),
        }
    except Exception:
        return None


# label -> (confidence, note, source-code-search services). trustedform has no operator id
# to pivot on, so it's recorded as an artifact but not emitted as a pivot (None).
SAAS_PIVOTS = {
    "gohighlevel_location": ("high", "GoHighLevel sub-account (location) ID. Same GHL tenant = same operator; find its whole portfolio."),
    "google_sheet": ("high", "Backend Google Sheet ID embedded in the page. Same sheet = same operator — and it may be publicly readable (check for exposed leads/PII)."),
    "make_webhook": ("high", "Make.com automation webhook — operator-controlled endpoint. Same token = same operator."),
    "integromat_webhook": ("high", "Integromat/Make automation webhook — operator-controlled. Same token = same operator."),
    "zapier_webhook": ("high", "Zapier catch hook — operator-controlled automation endpoint. Same token = same operator."),
    "apps_script": ("high", "Google Apps Script web-app the form posts to — operator-controlled. Same deployment = same operator."),
    "trustedform": (None, "TrustedForm (TCPA lead certification) — signals a lead-generation funnel; not an operator pivot."),
}


# =================================================================== pivot builder
def build_pivots(art: dict, base_host: str):
    """Turn artifacts into ranked, ready-to-run pivot leads."""
    pivots = []

    def add(kind, value, confidence, queries, note=""):
        pivots.append({"kind": kind, "value": value, "confidence": confidence,
                       "note": note, "queries": queries})

    fav = art.get("favicon")
    if fav:
        # Each engine hashes the favicon differently: Shodan/FOFA/ZoomEye=mmh3,
        # Censys=MD5, Netlas=SHA-256. Emit the right query per engine.
        add("favicon_hash", fav["shodan_mmh3"], "high", [
            {"service": "Shodan", "query": f'http.favicon.hash:{fav["shodan_mmh3"]}'},
            {"service": "FOFA", "query": f'icon_hash="{fav["shodan_mmh3"]}"'},
            {"service": "ZoomEye", "query": f'iconhash:"{fav["shodan_mmh3"]}"'},
            {"service": "Censys", "query": f'services.http.response.favicons.md5_hash={fav["md5"]}'},
            {"service": "Netlas", "query": f'http.favicon.hash_sha256:{fav["sha256"]}'},
        ], "Same favicon across unrelated domains = shared operator/kit.")

    for label, token in art.get("verifications", {}).items():
        add(f"verification:{label}", token, "high", [
            {"service": "PublicWWW", "query": f'"{token}"'},
            {"service": "urlscan.io", "query": f'"{token}"'},
            {"service": "NerdyData", "query": f'"{token}"'},
        ], "Ownership-verification token reused across the owner's other domains.")

    for label, vals in art.get("trackers", {}).items():
        for v in vals:
            add(f"tracker:{label}", v, "high", [
                {"service": "PublicWWW", "query": f'"{v}"'},
                {"service": "SpyOnWeb", "query": v},
                {"service": "DNSlytics reverse-analytics", "query": v},
                {"service": "urlscan.io", "query": f'page.url:* AND "{v}"'},
                {"service": "NerdyData", "query": f'"{v}"'},
            ], "Shared analytics/ad ID = same owner across sites.")

    for label, vals in art.get("saas_ids", {}).items():
        conf_note = SAAS_PIVOTS.get(label)
        if not conf_note or not conf_note[0]:   # unknown or non-pivot (trustedform)
            continue
        conf, note = conf_note
        for v in vals:
            add(f"saas:{label}", v, conf, [
                {"service": "PublicWWW", "query": f'"{v}"'},
                {"service": "urlscan.io", "query": f'"{v}"'},
                {"service": "NerdyData", "query": f'"{v}"'},
                {"service": "Google/Bing", "query": f'"{v}"'},
            ], note)

    for coin, vals in art.get("crypto", {}).items():
        for v in vals:
            add(f"crypto:{coin}", v, "medium", [
                {"service": "blockchain explorer", "query": v},
                {"service": "Chainabuse", "query": v},
                {"service": "search engine / PublicWWW", "query": f'"{v}"'},
            ], "Reused wallet links scam/campaign infrastructure.")

    for e in art.get("emails", []):
        add("email", e, "medium", [
            {"service": "reverse-WHOIS (ViewDNS/WhoisXML)", "query": e},
            {"service": "urlscan.io", "query": f'"{e}"'},
            {"service": "hunter.io / Epieos", "query": e},
        ], "Registrant/contact email pivots to other domains.")

    for net, handles in art.get("socials", {}).items():
        for h in handles:
            add(f"social:{net}", h, "medium", [
                {"service": "platform search", "query": h},
            ])

    for host in art.get("third_party_hosts", [])[:15]:
        add("third_party_host", host, "low", [
            {"service": "crt.sh", "query": f"%.{host}"},
            {"service": "SecurityTrails/DNSlytics", "query": host},
        ], "Non-CDN third-party host may be shared C2/infra.")

    if base_host:
        add("domain", base_host, "high", [
            {"service": "crt.sh", "query": f"%.{base_host}"},
            {"service": "urlscan.io", "query": f"domain:{base_host}"},
            {"service": "Wayback CDX", "query": f"http://web.archive.org/cdx/search/cdx?url={base_host}*&output=json&collapse=urlkey"},
            {"service": "ViewDNS reverse-IP", "query": base_host},
        ], "Certificate transparency + passive DNS for related hosts.")

    order = {"high": 0, "medium": 1, "low": 2}
    pivots.sort(key=lambda p: order.get(p["confidence"], 3))
    return pivots


# =================================================================== main analyze
def analyze(source: str, html: str, base_url: str, headers: dict, ua: str,
            extra_cookies=None):
    # Unwrap Wayback/archive wrappers so the *original* site is treated as the origin.
    effective_url = unwrap_wayback(base_url) if base_url else ""
    is_archived = bool(base_url) and effective_url != base_url
    self_host = strip_www(urlparse(effective_url).netloc) if effective_url else ""

    meta = extract_meta(html)
    verifications = {label: meta[k] for k, label in VERIFICATION_META.items() if k in meta}
    trackers = extract_trackers(html)
    saas_ids = extract_saas(html)
    crypto = extract_crypto(html)

    emails = uniq(EMAIL_RE.findall(html))
    emails = [e for e in emails if not e.lower().endswith((".png", ".jpg", ".gif", ".svg", ".webp"))][:40]

    script_srcs = uniq(SCRIPT_SRC_RE.findall(html))
    all_hrefs = uniq(LINK_HREF_RE.findall(html))
    socials = extract_socials(all_hrefs)

    third_party = []
    for u in script_srcs + all_hrefs:
        try:
            resolved = unwrap_wayback(urljoin(base_url or "", u))
            h = strip_www(urlparse(resolved).netloc)
        except Exception:
            continue
        if h and self_host and h != self_host and not h.endswith("." + self_host):
            third_party.append(h)
    common_cdn = ("googleapis.com", "gstatic.com", "cloudflare.com", "jsdelivr.net",
                  "cdnjs.cloudflare.com", "unpkg.com", "fontawesome.com", "bootstrapcdn.com")
    archive_infra = ("archive.org",)  # Wayback wrapper chrome, not target infra
    third_party_hosts = uniq([h for h in third_party
                              if not any(h.endswith(c) for c in common_cdn)
                              and not (is_archived and h.endswith(archive_infra))])

    inline_scripts = INLINE_SCRIPT_RE.findall(html)
    inline_hashes = [hashlib.sha256(s.encode("utf-8", "ignore")).hexdigest()
                     for s in inline_scripts if s.strip()]

    # --- CSS / stylesheet indicators (a shared theme = same kit) ---
    stylesheet_hrefs = []
    for tag in re.findall(r"<link\b[^>]*>", html, re.I):
        if re.search(r'rel=["\']?stylesheet', tag, re.I) or re.search(r'href=["\'][^"\']+\.css', tag, re.I):
            m = re.search(r'href=["\']([^"\']+)["\']', tag, re.I)
            if m:
                stylesheet_hrefs.append(unwrap_wayback(urljoin(base_url or "", m.group(1))))
    stylesheet_hrefs = uniq(stylesheet_hrefs)
    # WordPress theme / plugin slugs — a strong, human-readable shared-template tell
    wp_themes = uniq(re.findall(r"/wp-content/themes/([a-z0-9_\-]+)", html, re.I))
    wp_plugins = uniq(re.findall(r"/wp-content/plugins/([a-z0-9_\-]+)", html, re.I))
    # inline <style> block hashes — identical inline CSS across sites = template reuse
    inline_styles = re.findall(r"<style[^>]*>(.*?)</style>", html, re.I | re.S)
    inline_style_hashes = [hashlib.sha256(s.encode("utf-8", "ignore")).hexdigest()
                           for s in inline_styles if s.strip()]

    forms = []
    for fm in re.finditer(r"<form[^>]*>(.*?)</form>", html, re.I | re.S):
        block = fm.group(0)
        action = FORM_ACTION_RE.search(block)
        forms.append({
            "action": urljoin(base_url or "", action.group(1)) if action else None,
            "inputs": uniq(INPUT_NAME_RE.findall(block))[:30],
        })

    comments = [re.sub(r"\s+", " ", c).strip()[:200]
                for c in COMMENT_RE.findall(html) if c.strip()][:25]

    favicon = get_favicon(base_url, html, ua) if base_url else None
    if favicon:
        favicon["url"] = unwrap_wayback(favicon["url"])  # report the real favicon URL

    cookie_names = []
    if "set-cookie" in headers:
        cookie_names = uniq([c.split("=")[0].strip()
                             for c in re.split(r",(?=[^ ;]+=)", headers["set-cookie"])])
    if extra_cookies:
        cookie_names = uniq(cookie_names + [c.get("name") for c in extra_cookies if c.get("name")])

    artifacts = {
        "title": meta.get("_title"),
        "meta": {k: v for k, v in meta.items() if k != "_title"},
        "verifications": verifications,
        "favicon": favicon,
        "trackers": trackers,
        "saas_ids": saas_ids,
        "crypto": crypto,
        "emails": emails,
        "socials": socials,
        "script_srcs": script_srcs[:60],
        "third_party_hosts": third_party_hosts,
        "inline_script_sha256": inline_hashes[:40],
        "stylesheets": stylesheet_hrefs[:40],
        "wp_themes": wp_themes,
        "wp_plugins": wp_plugins[:40],
        "inline_style_sha256": inline_style_hashes[:20],
        "forms": forms[:20],
        "html_comments": comments,
        "dom_skeleton_sha1": dom_skeleton_hash(html),
        "tech_fingerprint": tech_fingerprint(html, headers, meta),
        "cookie_names": cookie_names,
        "server_headers": {k: headers[k] for k in
                           ("server", "x-powered-by", "via", "x-served-by",
                            "content-security-policy", "strict-transport-security")
                           if k in headers},
    }

    pivots = build_pivots(artifacts, self_host)

    return {
        "meta": {
            "source": source,
            "final_url": effective_url or base_url,
            "host": self_host,
            "archived_via_wayback": is_archived,
            "fetched_with": "requests" if HAVE_REQUESTS else "urllib",
        },
        "artifacts": artifacts,
        "pivots": pivots,
    }


def render_leads(result: dict) -> str:
    m = result["meta"]
    lines = [f"# Pivot leads — {m.get('host') or m['source']}", ""]
    if m.get("live_error"):
        lines.append(f"> ⚠️ Live target unreachable ({m['live_error']}).")
        lines.append(f"> Recovered via: {m.get('recovered_via') or 'not archived'}.")
        us = result.get("related_urlscan", {})
        lines.append(f"> urlscan: {us.get('total', 0)} prior scans"
                     + (f", IPs {', '.join(us.get('ips', [])[:5])}" if us.get('ips') else "")
                     + (f", ASNs {', '.join(us.get('asns', [])[:3])}" if us.get('asns') else "") + ".")
        lines.append("")
    for p in result["pivots"]:
        lines.append(f"## [{p['confidence'].upper()}] {p['kind']} = {p['value']}")
        if p.get("note"):
            lines.append(f"  _{p['note']}_")
        for q in p["queries"]:
            lines.append(f"  - {q['service']}: `{q['query']}`")
        lr = p.get("live_results")
        if lr:
            c = lr.get("crtsh") or {}
            if c.get("error"):
                lines.append(f"  - 🔴 crt.sh: error — {c['error']}")
            elif "subdomains" in c:
                lines.append(f"  - 🟢 crt.sh: {c.get('total', 0)} subdomains"
                             + (f" → {', '.join(c['subdomains'][:12])}" if c.get("subdomains") else ""))
            pd = lr.get("passivedns") or {}
            if pd.get("error"):
                lines.append(f"  - 🔴 passive DNS: error — {pd['error']}")
            elif "hosts" in pd:
                _h = [h["host"] for h in pd.get("hosts", [])]
                lines.append(f"  - 🟢 passive DNS: {pd.get('total', 0)} hosts"
                             + (f" → {', '.join(_h[:12])}" if _h else "")
                             + (f"  [IPs: {', '.join(pd.get('ips', [])[:6])}]" if pd.get("ips") else ""))
            f = lr.get("fofa") or {}
            if f.get("error"):
                lines.append(f"  - 🔴 FOFA: error — {f['error']}")
            elif "results" in f:
                hosts = sorted({r.get("domain") or r.get("host") for r in f["results"] if r})
                lines.append(f"  - 🟢 FOFA: {f.get('total', 0)} hits"
                             + (f" → {', '.join(h for h in hosts[:12] if h)}" if hosts else ""))
            u = lr.get("urlscan") or {}
            if u.get("error"):
                lines.append(f"  - 🔴 urlscan: error — {u['error']}")
            elif "domains" in u:
                lines.append(f"  - 🟢 urlscan: {u.get('total', 0)} hits"
                             + (f" → {', '.join(u['domains'][:12])}" if u.get("domains") else ""))
            for stk in ("reverse_whois_current", "reverse_whois_historic"):
                rw = lr.get(stk) or {}
                if rw.get("error"):
                    lines.append(f"  - 🔴 {stk}: error — {rw['error']}")
                elif "domains" in rw:
                    lines.append(f"  - 🟢 {stk}: {rw.get('count', 0)} domains"
                                 + (f" → {', '.join(rw['domains'][:12])}" if rw.get("domains") else ""))
        lines.append("")
    return "\n".join(lines)


def enrich_live(result: dict) -> dict:
    """Run live pivots and attach the real hits to each pivot as pivot['live_results'].

    Keyless always-on: the base `domain` pivot is resolved live via crt.sh
    (certificate transparency), HackerTarget passive DNS, and an anonymous urlscan
    domain search — no API key required. Keyed extras when configured: FOFA reverses
    favicon icon_hash and tracker/verification bodies; authenticated urlscan
    content-searches the same tracker/token values.
    """
    have_fofa = bool(_secret("FOFA_KEY", "FOFA_API_KEY"))
    have_urlscan = bool(_secret("URLSCAN_API_KEY"))
    sources = ["crtsh", "passivedns", "urlscan"]  # keyless domain enrichment
    if have_fofa:
        sources.append("fofa")
    result.setdefault("meta", {})["enriched_with"] = sources
    for piv in result.get("pivots", []):
        kind, val = piv.get("kind", ""), piv.get("value")
        lr = {}
        if kind == "domain" and val:
            # keyless certificate-transparency + passive DNS + urlscan on the base host.
            # The three lookups are independent I/O, so run them concurrently — bounds
            # latency to the slowest call instead of the sum (crt.sh is often overloaded).
            jobs = {"crtsh": lambda: crtsh_search(val),
                    "passivedns": lambda: passivedns_search(val),
                    "urlscan": lambda: urlscan_search(f"domain:{val}")}
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
                futures = {k: ex.submit(fn) for k, fn in jobs.items()}
                lr = {k: fu.result() for k, fu in futures.items()}
        else:
            fofa_q = None
            if kind == "favicon_hash":
                fofa_q = f'icon_hash="{val}"'
            elif kind.startswith(("tracker:", "verification:")):
                fofa_q = f'body="{val}"'
            if fofa_q and have_fofa:
                f = fofa_search(fofa_q)
                if f is not None:
                    lr["fofa"] = f
            if have_urlscan and kind.startswith(("tracker:", "verification:")):
                u = urlscan_search(f'"{val}"')
                if u is not None:
                    lr["urlscan"] = u
        if lr:
            piv["live_results"] = lr
    return result


def whois_enrich_result(result: dict, do_reverse: bool = False,
                        history_mode: str = "purchase") -> dict:
    """Attach WhoisXML registration data + registrant pivots to a result.

    Adds result['artifacts']['whois'] (registrant email/name/org, registrar, dates,
    name servers, and every historical registrant email/name), and a HIGH-confidence
    'whois:registrant_email' pivot with reverse-WHOIS queries. With do_reverse, runs
    the reverse-WHOIS live and attaches sibling domains. No WHOISXML key → no-op.
    """
    if not (HAVE_WHOIS and whois_enrich._key()):
        return result
    host = result.get("meta", {}).get("host")
    if not host:
        return result
    w = whois_enrich.whois_summary(host, history_mode=history_mode)
    if not w or w.get("error"):
        result.setdefault("meta", {})["whois_error"] = (w or {}).get("error", "no data")
        return result
    result.setdefault("artifacts", {})["whois"] = w
    result.setdefault("meta", {}).setdefault("enriched_with", []).append("whoisxml")

    # registrant email → same-operator pivot (reverse WHOIS)
    hist = w.get("history") or {}
    emails = []
    if w.get("registrant_email"):
        emails.append(w["registrant_email"])
    for e in hist.get("registrant_emails") or []:
        if e not in emails:
            emails.append(e)
    for em in emails:
        if whois_enrich.is_privacy(em):
            continue  # skip privacy-proxy / registrar-role addresses — not the owner
        piv = {
            "kind": "whois:registrant_email", "value": em, "confidence": "high",
            "note": "Registrant email — reverse WHOIS finds the owner's other domains.",
            "queries": [
                {"service": "WhoisXML reverse-whois", "query": f'registrant email = "{em}"'},
                {"service": "ViewDNS reverse-whois", "query": em},
                {"service": "DomainBigData", "query": em},
            ],
        }
        if do_reverse:
            for st in ("current", "historic"):
                r = whois_enrich.reverse_whois(em, "email", search_type=st)
                if r is not None:
                    piv.setdefault("live_results", {})[f"reverse_whois_{st}"] = r
        result["pivots"].append(piv)

    name = w.get("registrant_name") or w.get("registrant_org")
    if name and not whois_enrich.is_privacy(name):
        result["pivots"].append({
            "kind": "whois:registrant_name", "value": name, "confidence": "medium",
            "note": "Registrant name/org — reverse WHOIS candidate.",
            "queries": [{"service": "WhoisXML reverse-whois", "query": f'registrant name = "{name}"'}],
        })
    return result


def main():
    ap = argparse.ArgumentParser(description="WebPivot — extract OSINT pivot artifacts from a page.")
    ap.add_argument("source", help="URL, local HTML file, or '-' for stdin")
    ap.add_argument("--render", action="store_true", help="render post-JS DOM via Playwright")
    ap.add_argument("--leads", action="store_true", help="print ranked pivot leads (markdown) instead of JSON")
    ap.add_argument("--pretty", action="store_true", help="pretty-print JSON")
    ap.add_argument("--ua", default=DEFAULT_UA, help="User-Agent string")
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--no-fallback", action="store_true",
                    help="do NOT fall back to Wayback + urlscan when the live fetch fails")
    ap.add_argument("--no-enrich", action="store_true",
                    help="do NOT run live enrichment (keyless crt.sh/passive-DNS/urlscan on the "
                         "domain, plus FOFA/urlscan when keys are configured)")
    ap.add_argument("--no-whois", action="store_true",
                    help="do NOT run WhoisXML enrichment even if WHOISXML_API_KEY is set")
    ap.add_argument("--whois-reverse", action="store_true",
                    help="run reverse-WHOIS live on registrant emails (costs WhoisXML credits)")
    ap.add_argument("--whois-history-mode", choices=["preview", "purchase"], default="purchase",
                    help="WHOIS history: preview (count only) or purchase (full records)")
    ap.add_argument("-o", "--out", help="write JSON to file")
    ap.add_argument("--save-dom", nargs="?", const=True, default=None, metavar="PATH",
                    help="store the raw fetched/rendered DOM to disk. Bare flag → alongside "
                         "--out (<out>.html) or <host>.dom.html; or give an explicit PATH.")
    ap.add_argument("--submit", action="store_true",
                    help="actively archive the URL: submit to Wayback Save-Page-Now AND urlscan.io "
                         "(needs URLSCAN_API_KEY for the scan). Archives attached to result.archives.")
    args = ap.parse_args()

    src = args.source
    base_url, headers, cookies = "", {}, None
    html = ""
    live_error = None
    recovered_via = None
    intel = None

    if src == "-":
        html = sys.stdin.read()
    elif os.path.isfile(src):
        with open(src, "r", encoding="utf-8", errors="ignore") as f:
            html = f.read()
    elif src.startswith(("http://", "https://")):
        host_for_intel = strip_www(urlparse(src).netloc)
        # --- try the live target first ---
        try:
            if args.render:
                base_url, html, cookies = render_dom(src, timeout=args.timeout, ua=args.ua)
                try:
                    _, _, headers, _ = fetch(base_url, timeout=args.timeout, ua=args.ua)
                except Exception:
                    headers = {}
            else:
                base_url, status, headers, body = fetch(src, timeout=args.timeout, ua=args.ua)
                html = body.decode("utf-8", "ignore")
                headers["_status"] = str(status)
                if status >= 400 or len(html) < 200:
                    raise RuntimeError(f"HTTP {status}, {len(html)} bytes")
        except Exception as e:
            live_error = str(e)
            html = ""
        # --- if the live target is unreachable/blocked, go passive ---
        if not html and not args.no_fallback:
            print(f"[!] live fetch failed ({live_error}); falling back to Wayback + urlscan",
                  file=sys.stderr)
            snap_url, ts = wayback_closest(src, ua=args.ua)
            if snap_url:
                try:
                    base_url, _, headers, body = fetch(snap_url, timeout=args.timeout, ua=args.ua)
                    html = body.decode("utf-8", "ignore")
                    recovered_via = f"wayback:{ts}"
                    print(f"[+] recovered archived copy: {snap_url}", file=sys.stderr)
                except Exception:
                    pass
            intel = urlscan_intel(host_for_intel, ua=args.ua)
            print(f"[+] urlscan: {intel.get('total', 0)} prior scans, "
                  f"{len(intel.get('related_domains', []))} related domains", file=sys.stderr)
    else:
        ap.error("source must be a URL, an existing file, or '-'")

    result = analyze(src, html, base_url, headers, args.ua, extra_cookies=cookies)
    if live_error:
        result["meta"]["live_error"] = live_error
        result["meta"]["recovered_via"] = recovered_via
    if intel is not None:
        result["related_urlscan"] = intel
        # promote urlscan related-infra to pivots even when the page itself is gone
        for d in intel.get("related_domains", [])[:15]:
            if d and d != result["meta"].get("host"):
                result["pivots"].append({
                    "kind": "urlscan_related_domain", "value": d, "confidence": "medium",
                    "note": "Domain seen in urlscan scans of the same host/target.",
                    "queries": [{"service": "urlscan.io", "query": f"domain:{d}"},
                                {"service": "crt.sh", "query": f"%.{d}"}]})
        for ip in intel.get("ips", [])[:10]:
            result["pivots"].append({
                "kind": "urlscan_ip", "value": ip, "confidence": "medium",
                "note": "IP that served the target in a urlscan scan — reverse it.",
                "queries": [{"service": "urlscan.io", "query": f"ip:{ip}"},
                            {"service": "Validin/DNSlytics reverse-IP", "query": ip}]})

    if not args.no_enrich:
        enrich_live(result)
    if not args.no_whois:
        whois_enrich_result(result, do_reverse=args.whois_reverse,
                            history_mode=args.whois_history_mode)

    # --- store the raw DOM (the collected page) ---
    if args.save_dom and html:
        if isinstance(args.save_dom, str):
            dom_path = args.save_dom
        elif args.out:
            dom_path = re.sub(r"\.json$", "", args.out) + ".html"
        else:
            dom_path = (result["meta"].get("host") or "page") + ".dom.html"
        try:
            with open(dom_path, "w", encoding="utf-8") as f:
                f.write(html)
            result["meta"]["raw_dom_file"] = dom_path
            print(f"[+] saved raw DOM ({len(html)} bytes) -> {dom_path}", file=sys.stderr)
        except Exception as e:
            print(f"[!] could not save DOM: {e}", file=sys.stderr)

    # --- actively archive the URL to Wayback + urlscan (more results later) ---
    if args.submit and src.startswith(("http://", "https://")):
        archives = {}
        print("[+] submitting to Wayback Save-Page-Now …", file=sys.stderr)
        # SPN's synchronous save often takes 60-120s; a read timeout here does NOT mean the
        # capture failed (it usually completes server-side) — give it generous headroom.
        archives["wayback"] = wayback_save(src, ua=args.ua, timeout=max(args.timeout, 90))
        print(f"    wayback: {archives['wayback'].get('snapshot') or archives['wayback'].get('error')}",
              file=sys.stderr)
        print("[+] submitting to urlscan.io …", file=sys.stderr)
        archives["urlscan"] = urlscan_submit(src, timeout=max(args.timeout, 30))
        u = archives["urlscan"]
        print(f"    urlscan: {u.get('result') or u.get('error') or u.get('skipped')}", file=sys.stderr)
        result["archives"] = archives

    if args.leads:
        print(render_leads(result))
        return
    out = json.dumps(result, indent=2 if args.pretty else None, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"wrote {args.out} ({len(result['pivots'])} pivots)", file=sys.stderr)
    else:
        print(out)


if __name__ == "__main__":
    main()
