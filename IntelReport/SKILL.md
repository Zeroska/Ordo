---
name: IntelReport
description: Render a finished assessment MARKDOWN file into a polished, report-ready PDF and/or editable DOCX using pandoc — with a muted editorial house template that matches IntelGraph (cover page, table of contents, running header/footer carrying the classification + case id, embedded figures, and Vietnamese-safe typography). Use this skill WHENEVER the user has a written assessment/report in markdown (e.g. from pivot_extract --report, evidence_report, or an IntelHarness assessment) and asks to "make a PDF", "export to Word/docx", "produce the report", "render the report", "turn this into a document", "beautiful report", or "deliverable". Produces both PDF and DOCX by default. Supports English and Vietnamese.
---

> **OPSEC — this skill is portable/shared. Never write case data into it.** No real operator
> names, emails, domains, IPs, wallets, tracking IDs, hashes, or case IDs in this file, its
> template, tool code, or examples. Investigation data lives only in the git-ignored
> `cases/` / `knowledge/` / `MEMORY/`. Use placeholders (`example.com`, `CASE-0001`,
> `TLP:AMBER`). Reports never stamp an analyst name; the date defaults to UTC today.
> See the repo-root `CLAUDE.md` for the full rule.

# IntelReport — markdown → polished PDF / DOCX

Turn a finished assessment written in Markdown into a credible, print-native document.
The house style is the same understated editorial look as IntelGraph — muted slate/steel
palette, no gradients, generous margins, the kind of report a SOC analyst files, not an
auto-generated dashboard. **PDF** is the shareable deliverable; **DOCX** is the editable
copy a reviewer can redline.

## Zero new dependencies

Everything is already on the machine the harness uses:
- `pandoc` — the converter (markdown → PDF and → DOCX).
- `xelatex` — the PDF engine (Unicode/Vietnamese-safe; picks an installed Vietnamese-capable
  font automatically, see below).

No Python packages are required — `render_report.py` is stdlib-only and shells out to pandoc.

## Running the tool — paths (read first)

Registered as `IntelReport`, symlinked to the repo's `IntelReport/` folder.

```bash
REPORT=~/.claude/skills/IntelReport            # absolute — works from any CWD (preferred)
# or, inside the repo:  REPORT="$ROOT/IntelReport"

python3 "$REPORT/scripts/render_report.py" assessment.md out/report
```

That writes `out/report.pdf` **and** `out/report.docx` (both by default). Pass `--pdf` or
`--docx` to produce just one.

## Core workflow

1. **Have the assessment as Markdown.** Any assessment markdown works — from
   `pivot_extract.py --report`, `evidence_report.py`, an IntelHarness assessment, or written
   by hand. Standard Markdown: `#`/`##` headings, `|` pipe tables, fenced code, `**bold**`,
   `> quotes`, and image embeds.
2. **(Optional) add YAML frontmatter** so the cover/header fill in without CLI flags:
   ```markdown
   ---
   title: "Operator A — infrastructure assessment"
   subtitle: "Passive OSINT · N sites attributed to one operator"
   case_id: CASE-0001
   classification: "TLP:AMBER"
   ---
   ```
   CLI flags (`--title`, `--case-id`, `--classification`, `--subtitle`, `--date`) override
   the frontmatter. Anything missing gets a sensible default (`classification` →
   `UNCLASSIFIED`, `date` → UTC today, `title` → first `#` heading or the filename).
3. **Embed IntelGraph figures** as ordinary Markdown images — the alt text becomes the
   figure caption, styled in the house palette:
   ```markdown
   ![Operator A — two sites, shared GA4 + registrant](case_diagram_hires.png)
   ```
   Image paths are resolved **relative to the markdown file's directory**. Put the assessment
   `.md` in the case folder next to its figures (see the IntelGraph output contract) and they
   embed cleanly. Use the `_hires.png` (300 DPI) figure for print, or the `.svg` for vector.
4. **Render:**
   ```bash
   python3 "$REPORT/scripts/render_report.py" cases/CASE-0001/assessment.md \
       cases/CASE-0001/report --case-id CASE-0001 --classification "TLP:AMBER"
   ```
5. **Present** the PDF (and DOCX if the user wants to edit it).

## The end-to-end pipeline (charts + report)

```bash
# 1) collect + build the clustered case graph (WebPivot)
python3 <WebPivot>/tools/graph_build.py cases/CASE-0001/raw/*.json \
    --operator "Operator A" -o cases/CASE-0001/case_graph.json

# 2) editable diagram -> PNG/SVG (IntelGraph); the .mmd is hand-editable
python3 <IntelGraph>/scripts/graph_to_diagram.py cases/CASE-0001/case_graph.json \
    cases/CASE-0001/case_diagram --title "One operator, N sites" --legend

# 3) reference the figure in the assessment markdown, then render the document
python3 <IntelReport>/scripts/render_report.py cases/CASE-0001/assessment.md \
    cases/CASE-0001/report --case-id CASE-0001 --classification "TLP:AMBER"
```

`<IntelGraph>` = `~/.claude/skills/IntelGraph`, `<WebPivot>` = `~/.claude/skills/WebPivot`.

## Template & house style

- **Cover page** — classification banner (brick), large slate title, grey subtitle, and a
  Case / Date / Basis block. No logo, no analyst name.
- **Body** — numbered sections in slate/steel sans headings with a hairline rule, booktabs
  tables, house-palette figure captions, coloured hyperlinks. Auto table of contents.
- **Header/footer** — classification top-left, case id top-right, classification + page
  number in the footer, hairline rules.
- The LaTeX template is `templates/house-header.tex` (xelatex, palette copied from
  `IntelGraph/scripts/theme.py`). Edit it to adjust the house look; keep it case-data-free.

### Fonts / Vietnamese

`render_report.py` auto-selects an installed serif + sans that actually **declare Vietnamese
coverage** (`fc-list :lang=vi`) — many otherwise-nice serifs (PT Serif, Charter, DejaVu on
macOS) miss the stacked-diacritic glyphs (ộ, ừ, ả) and render tofu, so they are skipped in
favour of e.g. Noto Serif / Georgia / Times. Diacritics render correctly (cà phê, Hà Nội,
lừa đảo). Latin Modern is the last-resort TeX-bundled fallback.

### DOCX styling

DOCX uses pandoc's default reference styling plus a title block (title / subtitle-with-
classification / date). To brand it further, drop a customised `templates/reference.docx`
into the skill — `render_report.py` picks it up automatically if present (else uses the
clean default). Generate a starting point with
`pandoc -o templates/reference.docx --print-default-data-file reference.docx`, restyle it in
Word/LibreOffice, and keep it case-data-free.

## Quality checklist before presenting

- Both requested files exist (PDF and/or DOCX).
- Cover shows the right title, case id, and classification; NO analyst name.
- Vietnamese text renders with correct diacritics (no tofu boxes).
- Embedded figures appear (use the `_hires.png`); tables render with rules.
- Header/footer carry the classification + case id + page numbers on every body page.
- The classification and case id came from an argument or frontmatter — never hardcoded.
