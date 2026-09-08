"use client";

import Link from "next/link";

import {
  OwaspTag,
  PROVENANCE_LABELS,
  ProvenanceBadge,
  SEVERITY_LABELS,
  SeverityBadge,
  STATUS_LABELS,
  StatusBadge,
} from "@/components/findings/meta";
import { type DataColumn, DataTable, formatDateTime } from "@/components/ui/data-table";
import type { Finding, Severity } from "@/lib/api/types";

const SEVERITY_RANK: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

/** Findings list — sortable/filterable per column; severity-first by default
 * (the API orders it). Each row links to the finding detail. */
export function FindingsTable({
  engagementId,
  findings,
}: {
  engagementId: string;
  findings: Finding[];
}) {
  const columns: DataColumn<Finding>[] = [
    {
      key: "severity",
      label: "Severity",
      value: (f) => SEVERITY_LABELS[f.severity],
      sortValue: (f) => SEVERITY_RANK[f.severity],
      render: (f) => <SeverityBadge severity={f.severity} />,
    },
    {
      key: "title",
      label: "Finding",
      value: (f) => `${f.title} ${f.technique ?? ""}`,
      render: (f) => (
        <>
          <Link
            href={`/engagements/${engagementId}/findings/${f.id}`}
            className="font-medium underline-offset-4 hover:underline"
          >
            {f.title}
          </Link>
          {f.needs_review && (
            <span
              title="AI-proposed — needs human review"
              className="ml-2 rounded border border-amber-500/50 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-amber-600 align-middle"
            >
              review
            </span>
          )}
          {f.technique && (
            <span className="block text-xs text-muted-foreground">{f.technique}</span>
          )}
        </>
      ),
    },
    {
      key: "source",
      label: "Source",
      value: (f) => f.source ?? "—",
      className: "py-2.5 pr-4 font-mono text-xs text-muted-foreground",
    },
    {
      key: "owasp",
      label: "OWASP",
      value: (f) => (f.owasp ? `${f.owasp.code} ${f.owasp.title}` : "—"),
      render: (f) => <OwaspTag owasp={f.owasp} />,
    },
    {
      key: "provenance",
      label: "Provenance",
      value: (f) => PROVENANCE_LABELS[f.provenance],
      render: (f) => <ProvenanceBadge provenance={f.provenance} />,
    },
    {
      key: "status",
      label: "Status",
      value: (f) => STATUS_LABELS[f.status],
      render: (f) => <StatusBadge status={f.status} />,
    },
    {
      key: "created",
      label: "Created",
      value: (f) => formatDateTime(f.created_at),
      sortValue: (f) => Date.parse(f.created_at),
      className: "whitespace-nowrap py-2.5 pr-4 text-xs text-muted-foreground",
    },
    {
      key: "updated",
      label: "Updated",
      value: (f) => formatDateTime(f.updated_at),
      sortValue: (f) => Date.parse(f.updated_at),
      className: "whitespace-nowrap py-2.5 text-xs text-muted-foreground",
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={findings}
      rowKey={(f) => f.id}
      testId="findings-table"
      rowTestId="finding-row"
    />
  );
}
