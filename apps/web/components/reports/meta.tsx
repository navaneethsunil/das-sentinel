import { Badge } from "@/components/ui/badge";
import type { ReportStatus, ReportType } from "@/lib/api/types";

export const REPORT_TYPE_LABELS: Record<ReportType, string> = {
  executive: "Executive summary",
  technical: "Technical report",
  poam: "POA&M",
};

const STATUS_STYLES: Record<ReportStatus, string> = {
  draft: "bg-muted text-foreground hover:bg-muted",
  final: "bg-emerald-600 text-white hover:bg-emerald-600",
};

export function ReportStatusBadge({ status }: { status: ReportStatus }) {
  return (
    <Badge className={STATUS_STYLES[status]} data-testid="report-status">
      {status === "final" ? "Final" : "Draft"}
    </Badge>
  );
}
