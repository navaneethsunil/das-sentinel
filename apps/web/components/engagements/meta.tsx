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

// Mirrors core/scope.OPERATION_INTENSITY — the server derives each scan's
// intensity from what it does and refuses anything above this ceiling.
export const INTENSITY_DESCRIPTIONS: Record<ScanIntensity, string> = {
  passive: "Observation only — passive recon. Nothing is sent that could change the target.",
  safe_active:
    "Non-destructive active testing (the default) — unauthenticated scans with safe payloads.",
  authenticated_active:
    "Safe active plus scans that sign in to the target with configured credentials.",
  high_risk:
    "Exploit validation, brute force, large crawls, data-modifying payloads — each run also needs an explicit approval.",
};

/** Hoverable ⓘ explaining the Maximum intensity ceiling. Pure CSS hover/focus
 * popover — keyboard reachable via tabIndex. */
export function IntensityInfo() {
  return (
    <span className="group relative inline-block align-middle" data-testid="intensity-info">
      <span
        tabIndex={0}
        role="img"
        aria-label="What the intensity ceiling means"
        className="inline-flex size-4 cursor-help items-center justify-center rounded-full border border-muted-foreground/50 text-[10px] text-muted-foreground outline-none focus-visible:ring-2 focus-visible:ring-ring/50"
      >
        i
      </span>
      <span className="invisible absolute left-1/2 bottom-full z-50 mb-2 w-80 -translate-x-1/2 rounded-lg border bg-popover p-3 text-left text-xs font-normal normal-case tracking-normal text-popover-foreground shadow-lg group-hover:visible group-focus-within:visible">
        <span className="mb-1.5 block font-medium">
          The ceiling no scan in this engagement may exceed. Intensity is derived server-side from
          what each scan does — a launch above this ceiling is refused.
        </span>
        {(Object.keys(INTENSITY_LABELS) as ScanIntensity[]).map((level) => (
          <span key={level} className="mt-1 block">
            <span className="font-medium">{INTENSITY_LABELS[level]}</span> —{" "}
            <span className="text-muted-foreground">{INTENSITY_DESCRIPTIONS[level]}</span>
          </span>
        ))}
      </span>
    </span>
  );
}

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
