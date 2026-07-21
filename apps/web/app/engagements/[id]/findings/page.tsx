import Link from "next/link";
import { notFound } from "next/navigation";

import { FindingsTable } from "@/components/findings/findings-table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { serverGet } from "@/lib/api/server";
import type { Engagement, Finding } from "@/lib/api/types";

export const dynamic = "force-dynamic";

export default async function EngagementFindingsPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const [engagement, findings] = await Promise.all([
    serverGet<Engagement>(`/engagements/${id}`),
    serverGet<Finding[]>(`/engagements/${id}/findings`),
  ]);
  if (engagement === null || findings === null) {
    notFound();
  }

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <Link
          href={`/engagements/${id}`}
          className="text-sm text-muted-foreground underline-offset-4 hover:underline"
        >
          ← {engagement.name}
        </Link>
        <h1 className="mt-1 text-2xl font-semibold tracking-tight">Findings</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Evidence-backed results from this engagement&apos;s test suites, most severe first.
          Automated and AI-generated findings are labeled as such — they are not human-validated.
        </p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            {findings.length} finding{findings.length === 1 ? "" : "s"}
          </CardTitle>
        </CardHeader>
        <CardContent>
          {findings.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No findings yet — run an AI security scan against an in-scope target.
            </p>
          ) : (
            <FindingsTable engagementId={id} findings={findings} />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
