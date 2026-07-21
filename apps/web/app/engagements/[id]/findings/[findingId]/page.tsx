import Link from "next/link";
import { notFound } from "next/navigation";

import {
  isUnvalidated,
  OwaspTag,
  ProvenanceBadge,
  SeverityBadge,
  StatusBadge,
  STATUS_LABELS,
} from "@/components/findings/meta";
import { TranscriptViewer } from "@/components/findings/transcript-viewer";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { serverGet } from "@/lib/api/server";
import type { FindingDetail } from "@/lib/api/types";

export const dynamic = "force-dynamic";

export default async function FindingDetailPage({
  params,
}: {
  params: Promise<{ id: string; findingId: string }>;
}) {
  const { id, findingId } = await params;
  const finding = await serverGet<FindingDetail>(`/engagements/${id}/findings/${findingId}`);
  if (finding === null) {
    notFound();
  }

  const fields: [string, React.ReactNode][] = [
    ["Rule", finding.rule_id ?? "—"],
    ["OWASP LLM", <OwaspTag key="owasp" owasp={finding.owasp} />],
    ["Technique", finding.technique ?? "—"],
    ["Suite", finding.suite ?? "—"],
    ["Created", new Date(finding.created_at).toLocaleString()],
  ];

  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <Link
          href={`/engagements/${id}/findings`}
          className="text-sm text-muted-foreground underline-offset-4 hover:underline"
        >
          ← Findings
        </Link>
        <div className="mt-1 flex items-start justify-between gap-4">
          <h1 className="text-2xl font-semibold tracking-tight">{finding.title}</h1>
          <SeverityBadge severity={finding.severity} />
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <ProvenanceBadge provenance={finding.provenance} />
          <StatusBadge status={finding.status} />
        </div>
        {isUnvalidated(finding.provenance) && (
          <p
            role="note"
            className="mt-3 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm"
            data-testid="unvalidated-notice"
          >
            This finding is <strong>{STATUS_LABELS[finding.status].toLowerCase()}</strong> and has
            not been human-validated. Review the evidence before acting on it.
          </p>
        )}
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Summary</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <p className="text-sm">{finding.message}</p>
          <dl className="divide-y text-sm">
            {fields.map(([label, value]) => (
              <div key={label} className="flex justify-between gap-4 py-2">
                <dt className="text-muted-foreground">{label}</dt>
                <dd className="text-right">{value}</dd>
              </div>
            ))}
          </dl>
          {finding.description && (
            <div>
              <h3 className="mb-1 text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Description
              </h3>
              <p className="whitespace-pre-wrap text-sm">{finding.description}</p>
            </div>
          )}
          {finding.recommendation && (
            <div>
              <h3 className="mb-1 text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Recommendation
              </h3>
              <p className="whitespace-pre-wrap text-sm">{finding.recommendation}</p>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Evidence</CardTitle>
        </CardHeader>
        <CardContent>
          {finding.evidence.length === 0 ? (
            <p className="text-sm text-muted-foreground">No evidence attached.</p>
          ) : (
            <div className="space-y-3">
              {finding.evidence.map((evidence) => (
                <TranscriptViewer
                  key={evidence.evidence_id}
                  engagementId={id}
                  findingId={finding.id}
                  evidence={evidence}
                />
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Status history</CardTitle>
        </CardHeader>
        <CardContent>
          <ol className="space-y-3" data-testid="status-history">
            {finding.status_history.map((entry, i) => (
              <li key={i} className="flex items-start gap-3 text-sm">
                <span className="mt-0.5">
                  <StatusBadge status={entry.to_status} />
                </span>
                <span className="text-muted-foreground">
                  {entry.from_status ? `${STATUS_LABELS[entry.from_status]} → ` : ""}
                  {STATUS_LABELS[entry.to_status]}
                  {entry.reason ? ` · ${entry.reason}` : ""}
                  <span className="block text-xs">
                    {new Date(entry.changed_at).toLocaleString()}
                  </span>
                </span>
              </li>
            ))}
          </ol>
        </CardContent>
      </Card>
    </div>
  );
}
