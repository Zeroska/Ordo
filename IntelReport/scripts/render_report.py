#!/usr/bin/env python3
"""
render_report.py — turn an assessment MARKDOWN file into a polished PDF and/or
DOCX using pandoc. PDF uses the IntelReport house LaTeX theme (xelatex, muted
editorial palette matching IntelGraph); DOCX uses pandoc with a title block so
a reviewer can redline it.

No new Python deps — shells out to `pandoc` (+ `xelatex` for PDF), both of which
the repo already relies on. Embedded IntelGraph figures (`![](fig_hires.png)`)
render into the PDF automatically. Vietnamese diacritics render via DejaVu.

Metadata: title / case id / classification / subtitle / date come from CLI args,
else a YAML frontmatter block in the markdown, else sensible defaults. Per repo
OPSEC + report convention, NO analyst name is ever stamped and the date defaults
to UTC today.

Usage:
  render_report.py assessment.md out/report --pdf --docx \
      --title "Operator A — infrastructure assessment" \
      --case-id CASE-0001 --classification "TLP:AMBER" \
      --subtitle "Passive OSINT · attribution of N domains to one operator"

  render_report.py assessment.md out/report          # both PDF+DOCX, metadata from frontmatter
  render_report.py assessment.md out/report --pdf     # PDF only
"""
import argparse
import datetime
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TEMPLATES = os.path.join(os.path.dirname(HERE), "templates")
HOUSE_HEADER = os.path.join(TEMPLATES, "house-header.tex")
REFERENCE_DOCX = os.path.join(TEMPLATES, "reference.docx")

TEX_ESCAPE = {"&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#", "_": r"\_",
              "{": r"\{", "}": r"\}", "~": r"\textasciitilde{}",
              "^": r"\textasciicircum{}", "\\": r"\textbackslash{}"}


def tex_escape(s):
    return "".join(TEX_ESCAPE.get(c, c) for c in str(s))


def read_markdown(md_path):
    """Read the markdown ONCE and return (meta, body_title, body_lines):
      - meta: parsed key:value pairs from a leading YAML frontmatter block
      - body_title: first ATX H1, used as a title fallback
      - body_lines: the content with the frontmatter block stripped (so pandoc
        doesn't emit its own \\maketitle title page over our custom cover)."""
    meta, body_title, body_start = {}, None, 0
    with open(md_path, encoding="utf-8") as fh:
        lines = fh.readlines()
    if lines and lines[0].strip() == "---":
        for i in range(1, len(lines)):
            if lines[i].strip() in ("---", "..."):
                body_start = i + 1
                break
            if ":" in lines[i]:
                k, v = lines[i].split(":", 1)
                meta[k.strip().lower()] = v.strip().strip('"').strip("'")
    body_lines = lines[body_start:]
    for ln in body_lines:  # first ATX H1 as a title fallback
        if ln.startswith("# "):
            body_title = ln[2:].strip()
            break
    return meta, body_title, body_lines


def write_body(body_lines, tmpdir):
    """Write the frontmatter-stripped body to a temp .md (images still resolve
    via --resource-path pointed at the original file's directory)."""
    out = os.path.join(tmpdir, "body.md")
    with open(out, "w", encoding="utf-8") as fh:
        fh.writelines(body_lines)
    return out


def utc_today():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")


# Vietnamese-capable families, best first. All cover Latin Extended Additional
# (cà phê, Hà Nội, lừa đảo). We pick the first one actually installed so the
# skill is portable across machines instead of hardcoding one font.
SERIF_PREF = ["Noto Serif", "Source Serif 4", "Source Serif Pro", "Georgia",
              "Palatino", "PT Serif", "Charter", "DejaVu Serif",
              "Times New Roman", "TeX Gyre Termes", "Times"]
SANS_PREF = ["Noto Sans", "Source Sans 3", "Source Sans Pro", "Helvetica Neue",
             "PT Sans", "DejaVu Sans", "Arial", "TeX Gyre Heros", "Helvetica"]


def installed_families(lang=None):
    args = ["fc-list"]
    if lang:
        args.append(":lang=%s" % lang)
    args += ["-f", "%{family}\n"]
    try:
        r = subprocess.run(args, capture_output=True, text=True)
    except FileNotFoundError:
        return set()
    fams = set()
    for line in r.stdout.splitlines():
        for f in line.split(","):
            fams.add(f.strip())
    return fams


def pick_fonts():
    """(serif, sans). Prefer a family that actually DECLARES Vietnamese coverage
    (:lang=vi) — many nice serifs (PT Serif, Charter, DejaVu on macOS) miss the
    stacked-diacritic glyphs (ộ, ừ, ả) and render tofu. Fall back to any installed
    preferred family, then Latin Modern (TeX-bundled — note: Latin Modern does NOT
    cover Vietnamese, so on a box with no fontconfig/fc-list a VN report can still
    tofu; install a Noto/Georgia/Times family there)."""
    vi = installed_families(lang="vi")
    allf = installed_families()

    def first(prefs, default):
        return (next((f for f in prefs if f in vi), None)
                or next((f for f in prefs if f in allf), default))

    return first(SERIF_PREF, "Latin Modern Roman"), first(SANS_PREF, "Latin Modern Sans")


def build_defs_and_cover(m, tmpdir):
    """Write defs.tex (header/footer macros) and cover.tex (title page)."""
    cls = tex_escape(m["classification"])
    caseid = tex_escape(m["case_id"]) if m["case_id"] else ""
    serif, sans = pick_fonts()
    defs = os.path.join(tmpdir, "defs.tex")
    with open(defs, "w", encoding="utf-8") as fh:
        # defs.tex is included before house-header.tex, so load fontspec here
        # (reload in the header is a harmless no-op) so \setmainfont is valid.
        fh.write("\\usepackage{fontspec}\n")
        fh.write("\\newcommand{\\CLSLINE}{%s}\n" % cls)
        fh.write("\\newcommand{\\CASEID}{%s}\n" % caseid)
        fh.write("\\setmainfont{%s}[Scale=0.98]\n" % serif)
        fh.write("\\setsansfont{%s}[Scale=0.98]\n" % sans)
        fh.write("\\newfontfamily\\headingfont{%s}\n" % sans)

    title = tex_escape(m["title"])
    subtitle = tex_escape(m["subtitle"]) if m["subtitle"] else ""
    date = tex_escape(m["date"])
    caserow = (r"\textbf{Case} & %s \\" % caseid) if caseid else ""
    cover = os.path.join(tmpdir, "cover.tex")
    with open(cover, "w", encoding="utf-8") as fh:
        fh.write(r"""\begin{titlepage}
\thispagestyle{empty}
\raggedright
\vspace*{1.5cm}
{\headingfont\small\bfseries\color{brick}\MakeUppercase{%s}}\par
\vspace{0.35cm}{\color{grid}\hrule height 1.2pt}\par
\vspace{1.6cm}
{\headingfont\fontsize{30}{34}\selectfont\bfseries\color{slate} %s\par}
\vspace{0.6cm}
{\headingfont\large\color{muted} %s\par}
\vfill
{\headingfont\color{ink}\begin{tabular}{@{}l l@{}}
%s
\textbf{Date} & %s \\
\textbf{Basis} & Passive OSINT \\
\end{tabular}\par}
\vspace{0.6cm}{\color{grid}\hrule height 0.6pt}\par
\vspace{0.25cm}{\footnotesize\headingfont\color{muted} Handling: %s}\par
\end{titlepage}
\clearpage
""" % (cls, title, subtitle, caserow, date, cls))
    return defs, cover


def run(cmd):
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        sys.stderr.write("\n$ " + " ".join(cmd) + "\n")
        sys.stderr.write((r.stdout or "") + (r.stderr or "") + "\n")
    return r.returncode == 0


def render_pdf(body, stem, m, resource_dir):
    """body = the frontmatter-stripped temp .md; resource_dir = original md's dir
    (so ![](fig.png) still resolves)."""
    tmp = tempfile.mkdtemp(prefix="intelreport_")
    try:
        defs, cover = build_defs_and_cover(m, tmp)
        out = f"{stem}.pdf"
        ok = run(["pandoc", body, "-o", out,
                  "--pdf-engine=xelatex",
                  "--from", "markdown+yaml_metadata_block+pipe_tables+grid_tables",
                  "--number-sections", "--toc", "--toc-depth=3",
                  "-V", "linkcolor=steel",
                  "--include-in-header", defs,
                  "--include-in-header", HOUSE_HEADER,
                  "--include-before-body", cover,
                  "--resource-path", resource_dir])
        return out if ok else None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def render_docx(body, stem, m, resource_dir):
    out = f"{stem}.docx"
    sub = m["subtitle"] or ""
    if m["classification"]:
        sub = (m["classification"] + (" — " + sub if sub else "")).strip()
    cmd = ["pandoc", body, "-o", out,
           "--from", "markdown+yaml_metadata_block+pipe_tables+grid_tables",
           "--number-sections", "--toc", "--toc-depth=3",
           "-M", f"title={m['title']}",
           "-M", f"date={m['date']}",
           "--resource-path", resource_dir]
    if sub:
        cmd += ["-M", f"subtitle={sub}"]
    if os.path.isfile(REFERENCE_DOCX):
        cmd += ["--reference-doc", REFERENCE_DOCX]
    return out if run(cmd) else None


def main():
    ap = argparse.ArgumentParser(description="markdown assessment -> PDF/DOCX")
    ap.add_argument("markdown", help="input assessment .md")
    ap.add_argument("stem", help="output path stem (no extension)")
    ap.add_argument("--title", default=None)
    ap.add_argument("--subtitle", default=None)
    ap.add_argument("--case-id", default=None, help="e.g. CASE-0001 (never hardcode a real one)")
    ap.add_argument("--classification", default=None, help="handling caveat, e.g. TLP:AMBER")
    ap.add_argument("--date", default=None, help="YYYY-MM-DD (default: UTC today)")
    ap.add_argument("--pdf", action="store_true", help="render PDF")
    ap.add_argument("--docx", action="store_true", help="render DOCX")
    args = ap.parse_args()

    if not shutil.which("pandoc"):
        sys.exit("pandoc not found — install pandoc (brew install pandoc).")
    if not os.path.isfile(args.markdown):
        sys.exit(f"no such markdown file: {args.markdown}")

    fm, body_title, body_lines = read_markdown(args.markdown)
    m = {
        "title": args.title or fm.get("title") or body_title or
                 os.path.splitext(os.path.basename(args.markdown))[0],
        "subtitle": args.subtitle or fm.get("subtitle") or "",
        "case_id": args.case_id or fm.get("case_id") or fm.get("case") or "",
        "classification": args.classification or fm.get("classification")
                          or fm.get("tlp") or "UNCLASSIFIED",
        "date": args.date or fm.get("date") or utc_today(),
    }

    # default: produce both when neither flag is given
    neither = not (args.pdf or args.docx)
    want_pdf, want_docx = args.pdf or neither, args.docx or neither

    os.makedirs(os.path.dirname(os.path.abspath(args.stem)) or ".", exist_ok=True)
    resource_dir = os.path.dirname(os.path.abspath(args.markdown)) or "."
    tmp = tempfile.mkdtemp(prefix="intelreport_body_")
    outs = []
    try:
        body = write_body(body_lines, tmp)  # strip frontmatter ONCE, share both renders
        if want_pdf:
            p = render_pdf(body, args.stem, m, resource_dir)
            if p:
                outs.append(p)
            else:
                sys.stderr.write("PDF render FAILED\n")
        if want_docx:
            d = render_docx(body, args.stem, m, resource_dir)
            if d:
                outs.append(d)
            else:
                sys.stderr.write("DOCX render FAILED\n")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if not outs:
        sys.exit("no outputs produced")
    print("wrote:\n  " + "\n  ".join(outs))


if __name__ == "__main__":
    main()
