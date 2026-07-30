"""wp_recon — external recon API clients (FOFA, urlscan, TLS cert, crt.sh/CT, passive DNS)."""
import sys
import os
import re
import json
import base64
import hashlib
import argparse
import collections
import functools
import gzip
import itertools
import zlib
import socket
import ssl
import datetime
import shutil
import subprocess
import concurrent.futures
from urllib.parse import urljoin, urlparse, urlencode, quote, parse_qsl, unquote
# ------------------------------------------------------------------ optional deps
try:
    import requests  # noqa
    HAVE_REQUESTS = True
except Exception:
    HAVE_REQUESTS = False

import urllib.request
import urllib.error
from wp_common import *  # noqa

def fofa_search(query: str, size: int = 100,
                fields: str = "host,ip,domain,title", timeout: int = 30,
                full: bool = False):
    """Query the FOFA API for a raw query string (e.g. 'icon_hash="123"').

    Returns {'query','total','results':[{host,ip,domain,title}]} or {'error':...},
    or None if no FOFA key is configured. Needs FOFA_KEY (classic API also FOFA_EMAIL).

    full=True sets FOFA's `full=true` so the search spans ALL historical data
    instead of the default ~1-year window — catches assets (favicon hash, tracker
    body) that were live in the past and later scrubbed. Requires a FOFA tier that
    permits full/historical search; on lower tiers FOFA ignores or rejects it.
    """
    key = _secret("FOFA_KEY", "FOFA_API_KEY")
    if not key:
        return None
    params = {"key": key,
              "qbase64": base64.b64encode(query.encode()).decode(),
              "size": str(size), "fields": fields}
    if full:
        params["full"] = "true"
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

def urlscan_search(query: str, limit: int = 100, timeout: int = 30, max_results: int = None):
    """Authenticated urlscan.io search for an arbitrary query (content/tracker/token).

    Sends the API-Key header when URLSCAN_API_KEY is set — that unlocks the content-index searches
    anonymous search returns empty, higher rate limits, and (on Pro) the full result window. With a
    key this **paginates via `search_after`** to pull far more than one page — free/keyless returns
    a single page. Returns {'query','total','domains':[...],'pages'} or {'error':...}.

    max_results caps how many domains to accumulate (default 1000 with a key, 100 keyless)."""
    headers = {"User-Agent": DEFAULT_UA}
    key = _secret("URLSCAN_API_KEY")
    if key:
        headers["API-Key"] = key
    if max_results is None:
        max_results = 1000 if key else limit
    doms, seen, total, search_after, pages = [], set(), None, None, 0
    while len(doms) < max_results and pages < 20:
        pages += 1
        size = min(100, max_results - len(doms))
        api = f"https://urlscan.io/api/v1/search/?q={quote(query)}&size={size}"
        if search_after:
            api += f"&search_after={quote(search_after)}"
        try:
            req = urllib.request.Request(api, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = json.load(r)
        except Exception as e:
            if doms:
                break                       # keep the partial page(s) already gathered
            return {"query": query, "error": str(e)}
        results = data.get("results", []) or []
        if not results:
            break
        total = data.get("total", total)
        for res in results:
            d = res.get("page", {}).get("domain")
            if d and d not in seen:
                seen.add(d)
                doms.append(d)
        if not data.get("has_more"):
            break
        sort = results[-1].get("sort")         # cursor for the next page
        if not sort:
            break
        search_after = ",".join(str(x) for x in sort)
    return {"query": query, "total": total if total is not None else len(doms),
            "domains": doms[:max_results], "pages": pages}


def urlscan_similar(host: str, timeout: int = 30, limit: int = 60):
    """urlscan **Pro** 'Similar' — pages structurally like the host's latest scan (DOM structure),
    clustering re-skinned kits even when favicon/analytics/wallet all differ.

    Needs a Pro URLSCAN_API_KEY (the /pro/ endpoint 402/403s on the free tier). Returns
    {'uuid','similar_domains':[...]} or {'skipped':...}/{'error':...} — always safe to call; a
    non-Pro key just degrades to skipped. Two steps: find the host's most recent scan UUID, then
    ask urlscan for structurally-similar results."""
    key = _secret("URLSCAN_API_KEY")
    if not key:
        return {"skipped": "no URLSCAN_API_KEY"}
    headers = {"User-Agent": DEFAULT_UA, "API-Key": key}
    # 1) most-recent scan uuid for the host
    try:
        api = f"https://urlscan.io/api/v1/search/?q=page.domain:{quote(host)}&size=1"
        with urllib.request.urlopen(urllib.request.Request(api, headers=headers), timeout=timeout) as r:
            hits = (json.load(r).get("results") or [])
    except Exception as e:
        return {"error": str(e)}
    uuid = (hits[0].get("_id") if hits else None)
    if not uuid:
        return {"skipped": "no prior urlscan scan for host"}
    # 2) structurally-similar pages (Pro-only endpoint)
    try:
        api = f"https://urlscan.io/api/v1/pro/result/{uuid}/similar/"
        with urllib.request.urlopen(urllib.request.Request(api, headers=headers), timeout=timeout) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        if e.code in (401, 402, 403):
            return {"skipped": "urlscan similarity needs a Pro key", "uuid": uuid}
        return {"error": f"HTTP {e.code}", "uuid": uuid}
    except Exception as e:
        return {"error": str(e), "uuid": uuid}
    doms = []
    for res in (data.get("results") or data.get("similar") or []):
        d = (res.get("page") or {}).get("domain") if isinstance(res, dict) else None
        if d and d != host and d not in doms:
            doms.append(d)
    return {"uuid": uuid, "similar_domains": doms[:limit]}


# --- SAN extension OID (2.5.29.17) as DER: OBJECT IDENTIFIER, len 3, 55 1D 11 ------

_SAN_OID = b"\x06\x03\x55\x1d\x11"

def _der_read_len(der: bytes, i: int):
    """Read an ASN.1/DER length at offset i. Returns (length, next_offset)."""
    n = der[i]
    if n < 0x80:
        return n, i + 1
    cnt = n & 0x7F
    return int.from_bytes(der[i + 1:i + 1 + cnt], "big"), i + 1 + cnt

def _der_sans(der: bytes):
    """Extract dNSName SANs from a DER certificate with a stdlib-only scan.

    Locates the SAN extension (OID 2.5.29.17), unwraps its OCTET STRING → SEQUENCE
    of GeneralName, and collects context-tag [2] (0x82) dNSName entries. Best-effort:
    returns [] if the structure isn't found (never raises). Used only when the
    validating handshake failed and getpeercert() gave us nothing.
    """
    names = []
    try:
        pos = der.find(_SAN_OID)
        if pos < 0:
            return []
        i = pos + len(_SAN_OID)
        n = len(der)
        # the extension value is an OCTET STRING (0x04); a critical flag (BOOLEAN) may precede it
        if i < n and der[i] == 0x01:          # BOOLEAN critical — skip it
            _, i = _der_read_len(der, i + 1)
            i += 1
        if i >= n or der[i] != 0x04:
            return []
        _, i = _der_read_len(der, i + 1)
        if i >= n or der[i] != 0x30:          # SEQUENCE of GeneralName
            return []
        seq_len, i = _der_read_len(der, i + 1)
        end = min(i + seq_len, n)
        while i < end:
            tag = der[i]
            ln, j = _der_read_len(der, i + 1)
            if j + ln > n:                    # truncated/malformed — stop, keep what we have
                break
            val = der[j:j + ln]
            if tag == 0x82:                   # [2] dNSName (IA5String, implicit)
                try:
                    names.append(val.decode("ascii").strip().lstrip("*.").lower())
                except UnicodeDecodeError:
                    pass
            i = j + ln
    except Exception:
        pass                                  # best-effort scanner — never raise
    return uniq([n for n in names if n])

def fetch_tls_cert(host: str, port: int = 443, timeout: int = 15):
    """Read the LIVE TLS certificate served by host:port and pull pivot fields.

    Returns {host, port, fingerprint_sha256, sans:[...], issuer, subject,
    serial, not_before, not_after, validated} — or {host, error} on a socket
    failure. Two passes so hostile certs still yield data:
      1. validating context → rich getpeercert() dict (the common valid-LE case),
      2. on SSLCertVerificationError, an unverified context that still returns the
         DER, so we keep fingerprint_sha256 + DER-scanned SANs even for a
         mismatched / expired / self-signed cert (all interesting signals).
    fingerprint_sha256 is the SHA-256 of the DER — the standard cert fingerprint
    Censys/Validin index on. Pure stdlib (ssl + socket + hashlib).
    """
    def _dict_fields(cert: dict):
        out = {}
        sans = [v for (t, v) in cert.get("subjectAltName", ()) if t.lower() == "dns"]
        out["sans"] = uniq([s.strip().lstrip("*.").lower() for s in sans if s])
        def _flat(seq):  # ((('commonName','x'),),) → {'commonName':'x'}
            d = {}
            for rdn in seq or ():
                for k, v in rdn:
                    d[k] = v
            return d
        iss, subj = _flat(cert.get("issuer")), _flat(cert.get("subject"))
        out["issuer"] = iss.get("organizationName") or iss.get("commonName")
        out["subject"] = subj.get("commonName")
        out["serial"] = cert.get("serialNumber")
        out["not_before"] = cert.get("notBefore")
        out["not_after"] = cert.get("notAfter")
        return out

    # pass 1 — validating: yields the parsed dict when the cert chains + matches
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                der = ss.getpeercert(binary_form=True)
        res = {"host": host, "port": port, "validated": True,
               "fingerprint_sha256": hashlib.sha256(der).hexdigest()}
        res.update(_dict_fields(cert or {}))
        return res
    except ssl.SSLCertVerificationError as e:
        verr = str(e)
    except Exception as e:                    # socket/SSL/parse — never propagate
        return {"host": host, "port": port, "error": str(e)}

    # pass 2 — unverified: cert is present but didn't validate; keep DER-derived facts
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
        return {"host": host, "port": port, "validated": False,
                "validation_error": verr,
                "fingerprint_sha256": hashlib.sha256(der).hexdigest(),
                "sans": _der_sans(der)}
    except Exception as e:                    # never propagate to the caller
        return {"host": host, "port": port, "error": str(e),
                "validated": False, "validation_error": verr}

def _crtsh_fetch(value: str, timeout: int = 25):
    """Fetch crt.sh JSON rows for a search value, resilient to crt.sh flakiness.

    crt.sh's `?q=` endpoint frequently returns an nginx 502 HTML page (not JSON);
    its `?identity=` endpoint is more stable. Try `q` first, then fall back to
    `identity` for the same value. Returns a list of rows (possibly empty) or
    raises the last error so the caller can record it.
    """
    last_err = None
    for param in ("q", "identity"):
        api = "https://crt.sh/?" + urlencode({param: value, "output": "json"})
        try:
            req = urllib.request.Request(api, headers={"User-Agent": DEFAULT_UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read().decode("utf-8", "ignore").strip()
            if not body:
                last_err = "empty response"
                continue
            data = json.loads(body)          # a 502 returns HTML → JSONDecodeError → try next form
            return data if isinstance(data, list) else []
        except Exception as e:
            last_err = str(e)
            continue
    raise RuntimeError(last_err or "crt.sh unavailable")

def crtsh_search(domain: str, timeout: int = 25):
    """Certificate-transparency (SSL) search via crt.sh for `domain`.

    Enumerates every CT-logged certificate covering the registrable domain and
    its subdomains — including **wildcard** certs — via two queries merged:
    `%.<domain>` (subdomains) and the apex `identity`. Each cert's issuer +
    validity window + serial is kept so the CT result carries the SSL detail an
    analyst needs (issuance timeline, wildcard scope) without a second lookup.

    Keyless. Returns {'query','total','subdomains','wildcards','certs',...} or
    {'error':...}. crt.sh is frequently overloaded — errors are returned, never raised.
    """
    query = f"%.{domain}"
    rows = []
    err = None
    for value in (query, domain):            # subdomains, then the apex cert(s)
        try:
            rows.extend(_crtsh_fetch(value, timeout=timeout))
        except Exception as e:
            err = str(e)
    if not rows and err:
        return {"query": query, "error": err}

    subs, wildcards, certs, seen_cert = set(), set(), [], set()
    for row in rows:
        names = []
        for name in str(row.get("name_value", "")).splitlines() + [row.get("common_name", "")]:
            name = name.strip().lower()
            if not name or "@" in name:
                continue
            names.append(name)
            if name.startswith("*."):
                wildcards.add(name)
            bare = name.lstrip("*.")
            if bare and bare != domain.lower():
                subs.add(bare)
        cid = row.get("id")
        if cid and cid not in seen_cert:          # one entry per logged certificate
            seen_cert.add(cid)
            certs.append({
                "id": cid,
                "issuer": row.get("issuer_name"),
                "common_name": row.get("common_name"),
                "names": uniq(names),
                "not_before": row.get("not_before"),
                "not_after": row.get("not_after"),
                "serial": row.get("serial_number"),
            })
    certs.sort(key=lambda c: c.get("not_before") or "", reverse=True)
    ordered = sorted(subs)
    return {
        "query": query,
        "total": len(ordered),
        "subdomains": ordered[:80],
        "wildcards": sorted(wildcards),          # *.domain certs (broad-scope reuse signal)
        "cert_count": len(certs),
        "certs": certs[:40],                     # newest-first, issuer + validity + serial
    }

def shodan_ctl_search(domain: str, timeout: int = 25):
    """Certificate-transparency search via Shodan's keyless CTL mirror of the crt.sh DB.

    crt.sh's own endpoint is frequently overloaded (502s); Shodan's CTL API serves the
    same CT data from a steadier host, so it's our resilient second CT source. Two keyless
    endpoints:
      GET /api/v1/domain/<d>/hostnames -> flat JSON array of every hostname seen for <d>
      GET /api/v1/domain/<d>           -> cert objects {hash, subject_cn, issuer_cn,
                                          not_before/after (unix epoch), san_dns_names}

    Returns the SAME shape as crtsh_search (subdomains/wildcards/certs/cert_count) so it
    drops in as a merge/fallback, or {'error':...}. Never raises.
    """
    import datetime
    base = f"https://ctl.shodan.io/api/v1/domain/{quote(domain)}"

    def _json(url):
        req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_UA})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", "ignore"))

    def _iso(epoch):
        try:
            return datetime.datetime.utcfromtimestamp(int(epoch)).strftime("%Y-%m-%dT%H:%M:%S")
        except Exception:
            return None

    subs, wildcards, certs, err = set(), set(), [], None
    try:
        for name in _json(base + "/hostnames"):
            name = str(name).strip().lower()
            if not name or "@" in name:
                continue
            if name.startswith("*."):
                wildcards.add(name)
            bare = name.lstrip("*.")
            if bare and bare != domain.lower():
                subs.add(bare)
    except Exception as e:
        err = str(e)
    try:
        for row in _json(base):                    # cert objects
            cn = str(row.get("subject_cn", "")).strip().lower()
            if cn.startswith("*."):
                wildcards.add(cn)
            names = [str(n).strip().lower() for n in (row.get("san_dns_names") or []) if n]
            for n in names + ([cn] if cn else []):
                bare = n.lstrip("*.")
                if bare and bare != domain.lower():
                    subs.add(bare)
            certs.append({
                "id": row.get("hash"),
                "issuer": row.get("issuer_cn"),
                "common_name": row.get("subject_cn"),
                "names": uniq(names),
                "not_before": _iso(row.get("not_before")),
                "not_after": _iso(row.get("not_after")),
                "serial": None,
            })
    except Exception as e:
        err = err or str(e)
    if not subs and not certs and err:
        return {"query": domain, "error": err, "source": "shodan-ctl"}
    certs.sort(key=lambda c: c.get("not_before") or "", reverse=True)
    ordered = sorted(subs)
    return {
        "query": domain, "source": "shodan-ctl",
        "total": len(ordered), "subdomains": ordered[:80],
        "wildcards": sorted(wildcards), "cert_count": len(certs), "certs": certs[:40],
    }

def ct_search(domain: str, timeout: int = 25):
    """Merged certificate-transparency view over BOTH CT sources — crt.sh and Shodan's CTL
    mirror — run concurrently and unioned. Two independent CT indexes each miss certs the
    other has, and crt.sh alone 502s often; querying both maximises subdomain enumeration
    and survives either source being down. Same return shape as crtsh_search."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        a = ex.submit(crtsh_search, domain, timeout)
        b = ex.submit(shodan_ctl_search, domain, timeout)
        r1, r2 = a.result(), b.result()
    good = [r for r in (r1, r2) if not r.get("error")]
    if not good:
        return {"query": domain, "error": (r1.get("error") or r2.get("error")),
                "sources_tried": ["crt.sh", "shodan-ctl"]}
    subs, wildcards, certs, seen = set(), set(), [], set()
    for r in good:
        subs.update(r.get("subdomains", []))
        wildcards.update(r.get("wildcards", []))
        for c in r.get("certs", []):
            key = c.get("id") or (c.get("common_name"), c.get("not_before"))
            if key not in seen:
                seen.add(key)
                certs.append(c)
    certs.sort(key=lambda c: c.get("not_before") or "", reverse=True)
    ordered = sorted(subs)
    return {
        "query": domain, "sources": [r.get("source", "crt.sh") for r in good],
        "total": len(ordered), "subdomains": ordered[:80],
        "wildcards": sorted(wildcards), "cert_count": len(certs), "certs": certs[:40],
    }

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

def pdns_search(query: str, timeout: int = 25):
    """Passive-DNS lookup via a CIRCL-style COF endpoint (HTTP Basic auth).

    The `PDNS_USERNAME` + `PDNS_PASSWORD` credential pair is the CIRCL / Passive-DNS
    Common Output Format (COF) convention; CIRCL and most self-hosted / commercial COF
    instances answer at `<base>/<query>` with HTTP Basic auth and reply in newline-
    delimited JSON (one record per line). Base URL comes from `PDNS_URL` (default CIRCL).

    `query` is a domain OR an IP. Returns
      {'query','total','records':[{rrname,rrtype,rdata,time_first,time_last,count}],
       'ips':[...], 'domains':[...]}   (historical IPs a name used + names seen on an IP)
    or {'error':...}, or None if no PDNS credentials are configured.
    """
    user = _secret("PDNS_USERNAME")
    pw = _secret("PDNS_PASSWORD")
    if not (user and pw):
        return None
    base = (_secret("PDNS_URL") or "https://www.circl.lu/pdns/query").rstrip("/")
    url = f"{base}/{quote(query)}"
    auth = base64.b64encode(f"{user}:{pw}".encode()).decode()
    req = urllib.request.Request(url, headers={
        "User-Agent": DEFAULT_UA, "Accept": "application/json",
        "Authorization": "Basic " + auth})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read().decode("utf-8", "ignore").strip()
    except urllib.error.HTTPError as e:
        return {"query": query, "error": f"HTTP {e.code} {e.reason}"}
    except Exception as e:
        return {"query": query, "error": str(e)}
    if not body:
        return {"query": query, "total": 0, "records": [], "ips": [], "domains": []}
    # COF is usually newline-delimited JSON; tolerate a single JSON array too.
    lines = []
    if body[0] == "[":
        try:
            lines = json.loads(body)
        except Exception:
            lines = []
    else:
        for ln in body.splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                lines.append(json.loads(ln))
            except Exception:
                continue
    records, ips, domains = [], set(), set()
    q = query.strip().rstrip(".").lower()

    def _looks_ip(v: str) -> bool:
        return bool(_IPV4_RE.fullmatch(v)) or (":" in v and " " not in v)

    for rec in lines:
        if not isinstance(rec, dict):
            continue
        rrtype = str(rec.get("rrtype", "")).upper()
        rrname = str(rec.get("rrname", "")).rstrip(".").lower()
        rdata = str(rec.get("rdata", "")).rstrip(".").lower()
        records.append({"rrname": rec.get("rrname"), "rrtype": rrtype, "rdata": rec.get("rdata"),
                        "time_first": rec.get("time_first"), "time_last": rec.get("time_last"),
                        "count": rec.get("count")})
        # COF field order varies by instance (CIRCL stores the IP in rrname, the domain in
        # rdata). Route each side by what the VALUE looks like, not which field it sits in,
        # so we harvest historical IPs + co-resolved domains regardless of direction.
        for v in (rrname, rdata):
            if not v or v == q or " " in v:        # skip empty, the query itself, SOA/TXT blobs
                continue
            if _looks_ip(v):
                ips.add(v)
            elif "." in v and not v.replace(".", "").isdigit():
                domains.add(v)
    return {"query": query, "total": len(records), "records": records[:100],
            "ips": sorted(ips)[:60], "domains": sorted(domains)[:80]}

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def resolve_live_dns(host: str, timeout: int = 6) -> dict:
    """Resolve a host's CURRENT authoritative A records, live, right now.

    This is the ground-truth anchor for every IP pivot: passive sources (FOFA,
    HackerTarget, urlscan) report the IP a host was *last seen* on, which lags live
    DNS and misleads badly for infra that IP-hops or migrates hosts. Resolve live
    first, then reverse-search FOFA on the live IP — never the other way round.

    Tries, in order: `nslookup` (real DNS query, as requested), then socket
    (getaddrinfo, uses the OS resolver), then `ping` (last resort — proves nothing
    beyond the A record but works when the others are missing). Returns
    {'host','ips':[...],'method':...} or {'host','ips':[],'error':...}.
    """
    host = strip_www(host or "").strip()
    if not host:
        return {"host": host, "ips": [], "error": "no host"}

    def _via_nslookup():
        exe = shutil.which("nslookup")
        if not exe:
            return None
        try:
            out = subprocess.run([exe, "-type=A", host], capture_output=True,
                                 text=True, timeout=timeout).stdout
        except Exception:
            return None
        # The resolver-server preamble ("Server:/Address:" up to the first "Name:")
        # names the DNS server, not the host — collect those IPs and exclude them so
        # a reply without the blank-line separator can't leak the resolver's own
        # address as a bogus A record (which would then get FOFA-reversed as noise).
        resolver = set()
        for ln in out.splitlines():
            low = ln.lower().lstrip()
            if low.startswith("name:"):
                break
            if low.startswith(("server:", "address:")):
                resolver.update(_IPV4_RE.findall(ln))
        body = out.split("\n\n", 1)[-1]
        ips = [ip for ip in _IPV4_RE.findall(body)
               if not ip.startswith("0.") and ip not in resolver]
        return uniq(ips)

    def _via_socket():
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET)
        except Exception:
            return None
        return uniq([i[4][0] for i in infos])

    def _via_ping():
        exe = shutil.which("ping")
        if not exe:
            return None
        # -c on macOS/Linux; one echo is enough to force resolution.
        try:
            out = subprocess.run([exe, "-c", "1", "-W", str(timeout * 1000), host],
                                 capture_output=True, text=True, timeout=timeout + 2).stdout
        except Exception:
            try:  # some ping builds want -w seconds, not -W ms
                out = subprocess.run([exe, "-c", "1", host], capture_output=True,
                                     text=True, timeout=timeout + 2).stdout
            except Exception:
                return None
        m = re.search(r"\(((?:\d{1,3}\.){3}\d{1,3})\)", out)
        return [m.group(1)] if m else None

    for method, fn in (("nslookup", _via_nslookup),
                       ("socket", _via_socket),
                       ("ping", _via_ping)):
        ips = fn()
        if ips:
            return {"host": host, "ips": ips, "method": method}
    return {"host": host, "ips": [], "error": "unresolved"}


__all__ = [_n for _n in dir() if not _n.startswith("__")]
