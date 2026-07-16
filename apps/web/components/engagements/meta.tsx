import { Badge } from "@/components/ui/badge";
import type { EngagementStatus, ScanIntensity } from "@/lib/api/types";

export const STATUS_LABELS: Record<EngagementStatus, string> = {
  draft: "Draft",
  active: "Active",
  paused: "Paused",
  closed: "Closed",
};

export const INTENSITY_LABELS: Record<ScanIntensity, string> = {
  passive: "Passive",
  safe_active: "Safe active",
  authenticated_active: "Authenticated active",
  high_risk: "High risk",
};

// Mirrors services/engagements.ALLOWED_TRANSITIONS — the API enforces (409);
// this only decides which buttons to offer.
export const ALLOWED_TRANSITIONS: Record<EngagementStatus, EngagementStatus[]> = {
  draft: ["active", "closed"],
  active: ["paused", "closed"],
  paused: ["active", "closed"],
  closed: [],
};

const STATUS_STYLES: Record<EngagementStatus, string> = {
  draft: "",
  active: "bg-emerald-600 text-white hover:bg-emerald-600",
  paused: "bg-amber-500 text-white hover:bg-amber-500",
  closed: "bg-muted text-muted-foreground hover:bg-muted",
};

export function StatusBadge({ status }: { status: EngagementStatus }) {
  return (
    <Badge
      variant={status === "draft" ? "outline" : "default"}
      className={STATUS_STYLES[status]}
      data-testid="engagement-status"
    >
      {STATUS_LABELS[status]}
    </Badge>
  );
}
