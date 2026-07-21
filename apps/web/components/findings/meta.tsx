import { Badge } from "@/components/ui/badge";
import type { FindingProvenance, FindingStatus, OwaspRef, Severity } from "@/lib/api/types";

export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Info",
};

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-red-700 text-white hover:bg-red-700",
  high: "bg-red-600 text-white hover:bg-red-600",
  medium: "bg-amber-500 text-white hover:bg-amber-500",
  low: "bg-sky-600 text-white hover:bg-sky-600",
  informational: "bg-muted text-foreground hover:bg-muted",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge className={SEVERITY_STYLES[severity]} data-testid="finding-severity">
      {SEVERITY_LABELS[severity]}
    </Badge>
  );
}

// Provenance is the truthfulness control (CLAUDE.md §2.9): an automated or
// AI-generated finding must never read as human-verified. Label + color + a
// title tooltip all carry the distinction.
export const PROVENANCE_LABELS: Record<FindingProvenance, string> = {
  automated: "Automated",
  ai_generated: "AI-generated",
  validated: "Validated",
  manually_overridden: "Manually overridden",
};

const PROVENANCE_STYLES: Record<FindingProvenance, string> = {
  automated: "bg-slate-600 text-white hover:bg-slate-600",
  ai_generated: "bg-violet-600 text-white hover:bg-violet-600",
  validated: "bg-emerald-600 text-white hover:bg-emerald-600",
  manually_overridden: "bg-blue-600 text-white hover:bg-blue-600",
};

const PROVENANCE_HINTS: Record<FindingProvenance, string> = {
  automated: "Produced by a deterministic detector — not human-validated.",
  ai_generated: "Draft AI analysis — not human-validated.",
  validated: "Reviewed and confirmed by a human.",
  manually_overridden: "A human changed this finding from its original state.",
};

/** True for provenance that has NOT been through human review — the UI flags
 * these so an automated result is never mistaken for a verified one. */
export function isUnvalidated(provenance: FindingProvenance): boolean {
  return provenance === "automated" || provenance === "ai_generated";
}

export function ProvenanceBadge({ provenance }: { provenance: FindingProvenance }) {
  return (
    <Badge
      className={PROVENANCE_STYLES[provenance]}
      title={PROVENANCE_HINTS[provenance]}
      data-testid="finding-provenance"
    >
      {PROVENANCE_LABELS[provenance]}
    </Badge>
  );
}

export const STATUS_LABELS: Record<FindingStatus, string> = {
  open: "Open",
  in_triage: "In triage",
  confirmed: "Confirmed",
  mitigated: "Mitigated",
  fixed: "Fixed",
  accepted_risk: "Accepted risk",
  false_positive: "False positive",
  out_of_scope: "Out of scope",
};

export function StatusBadge({ status }: { status: FindingStatus }) {
  return (
    <Badge variant="outline" data-testid="finding-status">
      {STATUS_LABELS[status]}
    </Badge>
  );
}

export function OwaspTag({ owasp }: { owasp: OwaspRef | null }) {
  if (owasp === null) {
    return <span className="text-muted-foreground">—</span>;
  }
  return (
    <span
      className="inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-xs"
      title={`${owasp.framework}: ${owasp.title}`}
      data-testid="finding-owasp"
    >
      {owasp.code}
    </span>
  );
}
