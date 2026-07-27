"""PDF report exporter (M6).

Renders a report to PDF by converting the Markdown the technical/executive
renderers already produce — so there is ONE source of report structure, not a
second body-walk per format. `fpdf2` is pure-Python with no native dependencies
(air-gap-friendly, minimal attack surface for a hardened image); it uses the
built-in core fonts, so no font files ship.

The block structure comes from reports.markdown.iter_report_blocks (shared with
the DOCX exporter); this module only maps each block to fpdf2 calls. Core fonts are
Latin-1, so non-Latin text degrades to '?' rather than crashing the export.
ponytail: bundle a Unicode TTF if reports must render non-Latin scripts.
"""

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from app.reports.markdown import iter_report_blocks

# kind → (font style, size, line height) for headings and body text.
_STYLE = {
    "h1": ("B", 18, 9),
    "h2": ("B", 14, 7),
    "h3": ("B", 12, 6),
    "para": ("", 11, 5),
    "bullet": ("", 11, 5),
}


def _latin1(text: str) -> str:
    return text.encode("latin-1", "replace").decode("latin-1")


def render_pdf(markdown_text: str, *, title: str | None = None) -> bytes:
    """Render report Markdown to a PDF document (bytes). Pure function of the text."""
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    if title:
        pdf.set_title(_latin1(title))
    pdf.add_page()
    for kind, indent, text in iter_report_blocks(markdown_text):
        if kind == "blank":
            pdf.ln(3)
            continue
        style, size, height = _STYLE[kind]
        pdf.set_font("Helvetica", style, size)
        body = f"{' ' * (indent // 2)}- {text}" if kind == "bullet" else text
        pdf.multi_cell(
            0, height, _latin1(body), markdown=(style == ""), new_x=XPos.LMARGIN, new_y=YPos.NEXT
        )
    return bytes(pdf.output())
