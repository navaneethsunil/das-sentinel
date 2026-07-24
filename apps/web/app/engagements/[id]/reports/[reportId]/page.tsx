import Link from "next/link";
import { notFound } from "next/navigation";

import { ReportBuilder } from "@/components/reports/report-builder";
import { REPORT_TYPE_LABELS } from "@/components/reports/meta";
import { Card, CardContent } from "@/components/ui/card";
import { serverGet, serverMe } from "@/lib/api/server";
import type { ReportDetail } from "@/lib/api/types";

export const dynamic = "force-dynamic";

const CAN_EXPORT = new Set(["admin", "tester", "reviewer"]);

export default async function ReportBuilderPage({
  params,
}: {
  params: Promise<{ id: string; reportId: string }>;
}) {
  const { id, reportId } = await params;
  const [report, me] = await Promise.all([
    serverGet<ReportDetail>(`/engagements/${id}/reports/${reportId}`),
    serverMe(),
  ]);
  if (report === null) {
    notFound();
  }
  const canExport = me !== null && CAN_EXPORT.has(me.role);

  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <Link
          href={`/engagements/${id}/reports`}
          className="text-sm text-muted-foreground underline-offset-4 hover:underline"
        >
          ← Reports
        </Link>
        <h1 className="mt-1 text-2xl font-semibold tracking-tight">{report.title}</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          {REPORT_TYPE_LABELS[report.report_type]}
        </p>
      </div>
      <Card>
        <CardContent className="pt-6">
          <ReportBuilder engagementId={id} report={report} canEdit={canExport} />
        </CardContent>
      </Card>
    </div>
  );
}
