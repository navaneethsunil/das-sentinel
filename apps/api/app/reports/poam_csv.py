"""POA&M CSV exporter (M3-B5) — brief §15 field set.

Every cell is passed through `csv_safe` first: a spreadsheet treats a cell whose
first character is =, +, -, @, tab, or CR as a formula, so scanner/target-derived
text (attacker-influenced) could execute on open. We neutralize it by prefixing a
single quote (OWASP CSV-injection guidance, TM-6 for the export sink). The csv
module then handles quoting/escaping of delimiters and newlines within cells.
"""

import csv
import io
from typing import Any

# Leading characters a spreadsheet may interpret as the start of a formula.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

# (header, body-field key) in the brief's §15 order. Some cells are derived.
_COLUMNS: list[str] = [
    "Weakness ID",
    "Weakness Description",
    "Affected Asset",
    "Source of Discovery",
    "Severity",
    "CVSS Score",
    "Control Mapping",
    "Recommended Remediation",
    "Responsible Owner",
    "Planned Completion Date",
    "Current Status",
    "Milestones",
    "Risk Acceptance Notes",
]

_CVSS_VERSION_LABELS = {"v4_0": "CVSS v4.0", "v3_1": "CVSS v3.1"}


def csv_safe(value: Any) -> str:
    """Neutralize CSV/spreadsheet formula injection by prefixing a risky leading
    character with a single quote. Non-strings are stringified; None → ''."""
    text = "" if value is None else str(value)
    if text and text[0] in _FORMULA_PREFIXES:
        return "'" + text
    return text


def _weakness_description(entry: dict[str, Any]) -> str:
    title = entry.get("title") or ""
    description = entry.get("description")
    if description:
        return f"{title} — {description}" if title else str(description)
    return title


def _cvss_str(cvss: dict[str, Any] | None) -> str:
    if not cvss:
        return ""
    version = cvss.get("version")
    label = _CVSS_VERSION_LABELS.get(version, version or "")
    return f"{cvss.get('base_score')} ({label})".strip()


def _control_mapping_str(mappings: list[dict[str, Any]]) -> str:
    return "; ".join(f"{m.get('code')} ({m.get('framework_name')})" for m in mappings)


def render_poam_csv(body: dict[str, Any]) -> str:
    """Render a report body as a POA&M CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(_COLUMNS)
    for entry in body.get("findings", []):
        if not isinstance(entry, dict):
            continue
        writer.writerow(
            [
                csv_safe(entry.get("weakness_id")),
                csv_safe(_weakness_description(entry)),
                csv_safe(entry.get("affected_asset")),
                csv_safe(entry.get("source_of_discovery")),
                csv_safe(entry.get("severity")),
                csv_safe(_cvss_str(entry.get("cvss"))),
                csv_safe(_control_mapping_str(entry.get("mappings", []))),
                csv_safe(entry.get("recommended_remediation")),
                csv_safe(entry.get("responsible_owner")),
                csv_safe(entry.get("planned_completion_date")),
                csv_safe(entry.get("current_status")),
                csv_safe(entry.get("milestones")),
                csv_safe(entry.get("risk_acceptance_notes")),
            ]
        )
    return output.getvalue()
