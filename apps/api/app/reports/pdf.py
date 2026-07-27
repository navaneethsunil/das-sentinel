"""PDF report exporter (M6).

Renders a report to PDF by converting the Markdown the technical/executive
renderers already produce — so there is ONE source of report structure, not a
second body-walk per format. `fpdf2` is pure-Python with no native dependencies
(air-gap-friendly, minimal attack surface for a hardened image); it uses the
built-in core fonts, so no font files ship.

ponytail: naive line parser over our OWN generated Markdown (headings, bullets,
inline **bold**), not a general CommonMark engine. It only has to handle what
reports/markdown.py emits; a richer document needs a real markdown→PDF pass.
"""

from fpdf import FPDF
from fpdf.enums import XPos, YPos


# Core fonts are Latin-1 only; scanner/target-derived text can carry other scripts.
# Sanitize lossily so a stray non-Latin char degrades to '?' instead of crashing the
# export. ponytail: bundle a Unicode TTF if reports must render non-Latin scripts.
def _latin1(text: str) -> str:
    return text.encode("latin-1", "replace").decode("latin-1")


def _emit_line(pdf: FPDF, raw: str) -> None:
    line = raw.rstrip()
    if not line.strip():
        pdf.ln(3)
        return
    stripped = line.lstrip()
    indent = len(line) - len(stripped)
    if stripped.startswith("### "):
        pdf.set_font("Helvetica", "B", 12)
        pdf.multi_cell(0, 6, _latin1(stripped[4:]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    elif stripped.startswith("## "):
        pdf.ln(1)
        pdf.set_font("Helvetica", "B", 14)
        pdf.multi_cell(0, 7, _latin1(stripped[3:]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    elif stripped.startswith("# "):
        pdf.set_font("Helvetica", "B", 18)
        pdf.multi_cell(0, 9, _latin1(stripped[2:]), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    elif stripped.startswith("- "):
        pdf.set_font("Helvetica", "", 11)
        pad = " " * (indent // 2)
        pdf.multi_cell(
            0,
            5,
            _latin1(f"{pad}- {stripped[2:]}"),
            markdown=True,
            new_x=XPos.LMARGIN,
            new_y=YPos.NEXT,
        )
    else:
        pdf.set_font("Helvetica", "", 11)
        pdf.multi_cell(0, 5, _latin1(stripped), markdown=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)


def render_pdf(markdown_text: str, *, title: str | None = None) -> bytes:
    """Render report Markdown to a PDF document (bytes). Pure function of the text."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    if title:
        pdf.set_title(_latin1(title))
    pdf.add_page()
    pdf.set_font("Helvetica", "", 11)
    for raw in markdown_text.splitlines():
        _emit_line(pdf, raw)
    return bytes(pdf.output())
