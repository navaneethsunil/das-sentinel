import { Badge } from "@/components/ui/badge";
import type { LaunchIntensity, ScannerKind, ScanStatus, TestSuite } from "@/lib/api/types";

export const SUITE_LABELS: Record<TestSuite, string> = {
  prompt_injection: "Prompt injection (LLM01)",
  data_leakage: "Data leakage (LLM02/05/07/08)",
};

export const SCANNER_LABELS: Record<ScannerKind, string> = {
  semgrep: "Semgrep (SAST — source code)",
  zap: "ZAP (DAST — running web/API)",
};

export const LAUNCH_INTENSITY_LABELS: Record<LaunchIntensity, string> = {
  safe_active: "Safe active",
  authenticated_active: "Authenticated active",
};

export const SCAN_STATUS_LABELS: Record<ScanStatus, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};

const STATUS_STYLES: Record<ScanStatus, string> = {
  queued: "bg-muted text-foreground hover:bg-muted",
  running: "bg-sky-600 text-white hover:bg-sky-600",
  completed: "bg-emerald-600 text-white hover:bg-emerald-600",
  failed: "bg-red-600 text-white hover:bg-red-600",
  cancelled: "bg-amber-600 text-white hover:bg-amber-600",
};

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  return (
    <Badge className={STATUS_STYLES[status]} data-testid="scan-status">
      {SCAN_STATUS_LABELS[status]}
    </Badge>
  );
}

// Friendly copy for the scope keystone's machine reasons (ScopeError.reason on
// the API). Anything unmapped falls back to the raw reason.
const BLOCK_REASONS: Record<string, string> = {
  engagement_inactive: "The engagement is not active — activate it before launching a scan.",
  roe_not_accepted: "The Rules of Engagement have not been accepted for this engagement.",
  roe_stale: "The scope changed since the ROE was accepted — re-accept the ROE first.",
  roe_terms_mismatch: "An engagement term changed since the ROE was accepted — re-accept it first.",
  outside_test_window: "The current time is outside the engagement's authorized test window.",
  scope_violation: "The target is not in scope (or matches a deny rule) for this engagement.",
  intensity_not_authorized:
    "The chosen intensity exceeds the engagement's maximum intensity ceiling.",
  high_risk_not_approved: "This operation is high-risk and needs an approved approval gate.",
  ssrf_ip_blocked: "The target resolves to a blocked address (SSRF guard).",
};

export function blockReasonMessage(reason: string | undefined): string {
  if (!reason) {
    return "The scope engine blocked this launch.";
  }
  return BLOCK_REASONS[reason] ?? `The scope engine blocked this launch (${reason}).`;
}
