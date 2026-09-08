"use client";

import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { type DataColumn, DataTable, formatDateTime } from "@/components/ui/data-table";
import type { AuditEvent, AuditOutcome } from "@/lib/api/types";

const OUTCOME_STYLES: Record<AuditOutcome, string> = {
  success: "",
  blocked: "bg-red-600 text-white hover:bg-red-600",
  failure: "bg-amber-500 text-white hover:bg-amber-500",
};

function OutcomeBadge({ outcome }: { outcome: AuditOutcome }) {
  return (
    <Badge
      variant={outcome === "success" ? "outline" : "default"}
      className={OUTCOME_STYLES[outcome]}
    >
      {outcome}
    </Badge>
  );
}

export function AuditTable({ events }: { events: AuditEvent[] }) {
  const columns: DataColumn<AuditEvent>[] = [
    {
      key: "time",
      label: "Time",
      value: (e) => formatDateTime(e.created_at),
      sortValue: (e) => Date.parse(e.created_at),
      className: "whitespace-nowrap py-2.5 pr-4 text-xs text-muted-foreground",
    },
    {
      key: "actor",
      label: "Actor",
      value: (e) => e.actor_email ?? "system",
      className: "max-w-48 truncate py-2.5 pr-4",
    },
    {
      key: "action",
      label: "Action",
      value: (e) => `${e.action} ${e.object_type}`,
      render: (e) => (
        <>
          <span
            className="font-mono text-xs"
            title={e.detail ? JSON.stringify(e.detail, null, 2) : undefined}
          >
            {e.action}
          </span>
          <span className="block text-xs text-muted-foreground">{e.object_type}</span>
        </>
      ),
    },
    {
      key: "engagement",
      label: "Engagement",
      value: (e) => e.engagement_name ?? e.engagement_id ?? "—",
      className: "max-w-48 py-2.5 pr-4",
      render: (e) =>
        e.engagement_id ? (
          <Link
            href={`/audit?engagement=${e.engagement_id}`}
            className="block truncate underline-offset-4 hover:underline"
          >
            {e.engagement_name ?? e.engagement_id}
          </Link>
        ) : (
          "—"
        ),
    },
    {
      key: "outcome",
      label: "Outcome",
      value: (e) => e.outcome,
      render: (e) => <OutcomeBadge outcome={e.outcome} />,
    },
    {
      key: "ip",
      label: "IP",
      value: (e) => e.ip_address ?? "—",
      className: "py-2.5 font-mono text-xs text-muted-foreground",
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={events}
      rowKey={(e) => e.id}
      testId="audit-table"
      rowTestId="audit-row"
    />
  );
}
