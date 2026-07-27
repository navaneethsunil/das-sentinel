"""Report exporters: render an editable report body to a deliverable.

Formats — POA&M CSV (brief §15), a Markdown technical report, a Markdown executive
report (M6), raw JSON (M6), PDF and DOCX (M6, both rendered from the Markdown via
one shared block tokenizer). Each renderer is a pure function of `reports.body`
(services/reports.py) so the export is exactly the edited snapshot.
"""

from app.reports.docx import render_docx
from app.reports.markdown import render_executive_markdown, render_markdown_report
from app.reports.pdf import render_pdf
from app.reports.poam_csv import render_poam_csv

__all__ = [
    "render_docx",
    "render_executive_markdown",
    "render_markdown_report",
    "render_pdf",
    "render_poam_csv",
]
