import Link from "next/link";
import { notFound } from "next/navigation";

import { GenerateReport } from "@/components/reports/generate-report";
import { REPORT_TYPE_LABELS, ReportStatusBadge } from "@/components/reports/meta";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { serverGet, serverMe } from "@/lib/api/server";
import type { Engagement, Report } from "@/lib/api/types";

export const dynamic = "force-dynamic";

// Report authoring/export is EXPORT_REPORTS (Admin/Tester/Reviewer).
const CAN_EXPORT = new Set(["admin", "tester", "reviewer"]);

export default async function EngagementReportsPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const [engagement, reports, me] = await Promise.all([
    serverGet<Engagement>(`/engagements/${id}`),
    serverGet<Report[]>(`/engagements/${id}/reports`),
    serverMe(),
  ]);
  if (engagement === null || reports === null) {
    notFound();
  }
  const canExport = me !== null && CAN_EXPORT.has(me.role);

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <Link
          href={`/engagements/${id}`}
          className="text-sm text-muted-foreground underline-offset-4 hover:underline"
        >
          ← {engagement.name}
        </Link>
        <h1 className="mt-1 text-2xl font-semibold tracking-tight">Reports</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Generate a POA&amp;M or technical report from this engagement&apos;s findings, edit it,
          and export it as CSV or Markdown. A report snapshots findings, CVSS scores, and compliance
          mappings at generation time.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Generate a report</CardTitle>
        </CardHeader>
        <CardContent>
          <GenerateReport engagementId={id} canEdit={canExport} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {reports.length} report{reports.length === 1 ? "" : "s"}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {reports.length === 0 ? (
            <p className="text-sm text-muted-foreground">No reports yet.</p>
          ) : (
            <table className="w-full text-sm" data-testid="reports-table">
              <thead>
                <tr className="border-b text-left text-xs uppercase tracking-wider text-muted-foreground">
                  <th className="py-2 pr-4 font-medium">Title</th>
                  <th className="py-2 pr-4 font-medium">Type</th>
                  <th className="py-2 pr-4 font-medium">Status</th>
                  <th className="py-2 font-medium">Created</th>
                </tr>
              </thead>
              <tbody>
                {reports.map((report) => (
                  <tr
                    key={report.id}
                    className="border-b last:border-0 hover:bg-muted/50"
                    data-testid="report-row"
                  >
                    <td className="py-2.5 pr-4">
                      <Link
                        href={`/engagements/${id}/reports/${report.id}`}
                        className="font-medium underline-offset-4 hover:underline"
                      >
                        {report.title}
                      </Link>
                    </td>
                    <td className="py-2.5 pr-4">{REPORT_TYPE_LABELS[report.report_type]}</td>
                    <td className="py-2.5 pr-4">
                      <ReportStatusBadge status={report.status} />
                    </td>
                    <td className="py-2.5 text-muted-foreground">
                      {new Date(report.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
