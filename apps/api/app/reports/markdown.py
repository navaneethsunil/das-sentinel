"""Markdown report exporters.

`render_markdown_report` is the TECHNICAL report (M3-B5): engagement header,
editable summary, then one section per finding with severity, CVSS, status,
affected asset, source, OWASP + NIST mappings, and the description/impact/
remediation narrative.

`render_executive_markdown` is the EXECUTIVE report (M6): a summary view of the
same body — risk posture, severity breakdown, the top risks by severity/CVSS, and
compliance-framework coverage — without the per-finding deep detail. Both are pure
functions of `reports.body`.

`iter_report_blocks` classifies the Markdown these renderers emit into typed
blocks, so the PDF and DOCX exporters render from ONE source of report structure
instead of each re-parsing Markdown.
"""

from collections.abc import Iterator
from typing import Any

_CVSS_VERSION_LABELS = {"v4_0": "CVSS v4.0", "v3_1": "CVSS v3.1"}

# Severity ordering for risk posture / top-risk ranking (worst first). Keyed by the
# lowercased Severity enum value; anything unrecognized sorts last.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")
_TOP_RISK_COUNT = 5
_POAM_FIELD_LABELS = [
    ("responsible_owner", "Responsible owner"),
    ("planned_completion_date", "Planned completion date"),
    ("milestones", "Milestones"),
    ("risk_acceptance_notes", "Risk acceptance notes"),
]


def iter_report_blocks(markdown_text: str) -> Iterator[tuple[str, int, str]]:
    """Classify each line of our OWN generated report Markdown into
    (kind, indent, text) where kind ∈ {h1, h2, h3, bullet, para, blank}. Only
    handles the constructs this module emits — the PDF/DOCX exporters consume it so
    they don't each re-implement the same line parsing (see reports/pdf.py, docx.py)."""
    for raw in markdown_text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            yield ("blank", 0, "")
            continue
        stripped = line.lstrip()
        indent = len(line) - len(stripped)
        if stripped.startswith("### "):
            yield ("h3", 0, stripped[4:])
        elif stripped.startswith("## "):
            yield ("h2", 0, stripped[3:])
        elif stripped.startswith("# "):
            yield ("h1", 0, stripped[2:])
        elif stripped.startswith("- "):
            yield ("bullet", indent, stripped[2:])
        else:
            yield ("para", 0, stripped)


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


def _severity_rank(entry: dict[str, Any]) -> int:
    sev = str(entry.get("severity", "")).lower()
    return _SEVERITY_ORDER.index(sev) if sev in _SEVERITY_ORDER else len(_SEVERITY_ORDER)


def _cvss_score(entry: dict[str, Any]) -> float:
    cvss = entry.get("cvss")
    if isinstance(cvss, dict) and isinstance(cvss.get("base_score"), (int, float)):
        return float(cvss["base_score"])
    return -1.0


def render_executive_markdown(body: dict[str, Any]) -> str:
    """Render the EXECUTIVE report: risk posture, severity breakdown, top risks, and
    compliance-framework coverage. A pure summary of the same body the technical
    report uses — no per-finding deep detail."""
    engagement = body.get("engagement", {}) if isinstance(body.get("engagement"), dict) else {}
    findings = [f for f in body.get("findings", []) if isinstance(f, dict)]
    title = body.get("title") or f"Executive Report — {engagement.get('name', 'Engagement')}"

    lines: list[str] = [f"# {title}", ""]
    client = engagement.get("client_system_name")
    header = engagement.get("name", "")
    if client:
        header = f"{header} — {client}"
    lines += [f"**Engagement:** {header}"]
    if body.get("generated_at"):
        lines.append(f"**Generated:** {body['generated_at']}")
    lines += ["", "## Executive summary", "", _block(body.get("summary")), ""]

    # Risk posture: total + severity breakdown (only non-zero bands, worst first).
    counts = {band: 0 for band in _SEVERITY_ORDER}
    for entry in findings:
        sev = str(entry.get("severity", "")).lower()
        if sev in counts:
            counts[sev] += 1
    lines += ["## Risk posture", "", f"**Total findings:** {len(findings)}", ""]
    breakdown = [
        f"- **{band.capitalize()}:** {counts[band]}" for band in _SEVERITY_ORDER if counts[band]
    ]
    lines += (breakdown or ["- _No findings._"]) + [""]

    # Top risks: worst severity first, then highest CVSS base score.
    ranked = sorted(findings, key=lambda e: (_severity_rank(e), -_cvss_score(e)))
    top = ranked[:_TOP_RISK_COUNT]
    lines += [f"## Top risks (up to {_TOP_RISK_COUNT})", ""]
    if top:
        for entry in top:
            asset = entry.get("affected_asset") or "—"
            lines.append(
                f"- **{entry.get('title', '')}** — {entry.get('severity', '')} · "
                f"CVSS {_cvss_line(entry.get('cvss'))} · {asset}"
            )
    else:
        lines.append("- _No findings._")
    lines.append("")

    # Compliance coverage: distinct control codes touched per framework.
    fw_name: dict[str, str] = {}
    fw_codes: dict[str, set[str]] = {}
    for entry in findings:
        for m in entry.get("mappings", []):
            if not isinstance(m, dict):
                continue
            key = str(m.get("framework_key", ""))
            code = str(m.get("code", ""))
            if key and code:
                fw_name.setdefault(key, str(m.get("framework_name", "") or key))
                fw_codes.setdefault(key, set()).add(code)
    lines += ["## Compliance coverage", ""]
    if fw_codes:
        for key in sorted(fw_codes):
            codes = sorted(fw_codes[key])
            lines.append(f"- **{fw_name[key]}:** {len(codes)} control(s) — {', '.join(codes)}")
    else:
        lines.append("- _No compliance mappings._")

    return "\n".join(lines).rstrip() + "\n"
