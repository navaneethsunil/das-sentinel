"""Markdown technical-report exporter (M3-B5).

Renders a report body to a Markdown document: engagement header, editable summary,
then one section per finding with severity, CVSS, status, affected asset, source,
OWASP + NIST mappings, and the description/impact/remediation narrative. A pure
function of `reports.body`.
"""

from typing import Any

_CVSS_VERSION_LABELS = {"v4_0": "CVSS v4.0", "v3_1": "CVSS v3.1"}
_POAM_FIELD_LABELS = [
    ("responsible_owner", "Responsible owner"),
    ("planned_completion_date", "Planned completion date"),
    ("milestones", "Milestones"),
    ("risk_acceptance_notes", "Risk acceptance notes"),
]


def _cvss_line(cvss: dict[str, Any] | None) -> str:
    if not cvss:
        return "Not scored"
    version = cvss.get("version")
    label = _CVSS_VERSION_LABELS.get(version, version or "")
    band = cvss.get("severity_band")
    band_str = f" — {band}" if band else ""
    return f"{cvss.get('base_score')} ({label}){band_str} — `{cvss.get('vector')}`"


def _mapping_list(mappings: list[dict[str, Any]], prefix: str) -> str:
    items = [
        f"{m.get('code')} {m.get('title')}"
        for m in mappings
        if str(m.get("framework_key", "")).startswith(prefix)
    ]
    return ", ".join(items) if items else "—"


def _block(text: Any) -> str:
    value = "" if text is None else str(text).strip()
    return value if value else "_None._"


def render_markdown_report(body: dict[str, Any]) -> str:
    engagement = body.get("engagement", {}) if isinstance(body.get("engagement"), dict) else {}
    findings = [f for f in body.get("findings", []) if isinstance(f, dict)]
    title = body.get("title") or f"Technical Report — {engagement.get('name', 'Engagement')}"

    lines: list[str] = [f"# {title}", ""]
    client = engagement.get("client_system_name")
    header = engagement.get("name", "")
    if client:
        header = f"{header} — {client}"
    lines += [f"**Engagement:** {header}"]
    if body.get("generated_at"):
        lines.append(f"**Generated:** {body['generated_at']}")
    if body.get("report_type"):
        lines.append(f"**Report type:** {body['report_type']}")
    lines += ["", "## Summary", "", _block(body.get("summary")), ""]

    lines += [f"## Findings ({len(findings)})", ""]
    for entry in findings:
        wid = entry.get("weakness_id", "")
        lines += [f"### {wid} — {entry.get('title', '')}".rstrip(" —"), ""]
        validation = entry.get("validation_status", "")
        if entry.get("is_false_positive"):
            validation = f"{validation} (false positive)"
        lines += [
            f"- **Severity:** {entry.get('severity', '')}",
            f"- **CVSS:** {_cvss_line(entry.get('cvss'))}",
            f"- **Current status:** {entry.get('current_status', '')}",
            f"- **Validation status:** {validation}",
            f"- **Affected asset:** {entry.get('affected_asset', '') or '—'}",
            f"- **Source of discovery:** {entry.get('source_of_discovery', '') or '—'}",
            f"- **OWASP mapping:** {_mapping_list(entry.get('mappings', []), 'owasp')}",
            f"- **NIST mapping:** {_mapping_list(entry.get('mappings', []), 'nist')}",
            "",
            "**Description**",
            "",
            _block(entry.get("description")),
            "",
            "**Impact**",
            "",
            _block(entry.get("impact")),
            "",
            "**Recommended remediation**",
            "",
            _block(entry.get("recommended_remediation")),
            "",
        ]
        poam = [
            f"- **{label}:** {entry.get(key)}"
            for key, label in _POAM_FIELD_LABELS
            if str(entry.get(key, "")).strip()
        ]
        if poam:
            lines += ["**POA&M tracking**", "", *poam, ""]

    return "\n".join(lines).rstrip() + "\n"
