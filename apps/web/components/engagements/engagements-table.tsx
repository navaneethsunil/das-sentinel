"use client";

import Link from "next/link";

import { INTENSITY_LABELS, STATUS_LABELS, StatusBadge } from "@/components/engagements/meta";
import { type DataColumn, DataTable, formatDateTime } from "@/components/ui/data-table";
import type { Engagement } from "@/lib/api/types";

const dateSort = (iso: string | null) => (iso ? Date.parse(iso) : 0);

const COLUMNS: DataColumn<Engagement>[] = [
  {
    key: "name",
    label: "Name",
    value: (e) => e.name,
    render: (e) => (
      <Link
        href={`/engagements/${e.id}`}
        className="font-medium underline-offset-4 hover:underline"
      >
        {e.name}
      </Link>
    ),
  },
  { key: "client", label: "Client / system", value: (e) => e.client_system_name },
  {
    key: "status",
    label: "Status",
    value: (e) => STATUS_LABELS[e.status],
    render: (e) => <StatusBadge status={e.status} />,
  },
  { key: "intensity", label: "Max intensity", value: (e) => INTENSITY_LABELS[e.max_intensity] },
  {
    key: "rate",
    label: "Rate limit",
    value: (e) => `${e.rate_limit_rps} rps`,
    sortValue: (e) => e.rate_limit_rps,
  },
  {
    key: "created",
    label: "Created",
    value: (e) => formatDateTime(e.created_at),
    sortValue: (e) => dateSort(e.created_at),
    className: "whitespace-nowrap py-2.5 pr-4 text-xs text-muted-foreground",
  },
  {
    key: "updated",
    label: "Updated",
    value: (e) => formatDateTime(e.updated_at),
    sortValue: (e) => dateSort(e.updated_at),
    className: "whitespace-nowrap py-2.5 pr-4 text-xs text-muted-foreground",
  },
  {
    key: "closed",
    label: "Closed",
    value: (e) => formatDateTime(e.closed_at),
    sortValue: (e) => dateSort(e.closed_at),
    className: "whitespace-nowrap py-2.5 text-xs text-muted-foreground",
  },
];

export function EngagementsTable({ engagements }: { engagements: Engagement[] }) {
  return (
    <DataTable
      columns={COLUMNS}
      rows={engagements}
      rowKey={(e) => e.id}
      testId="engagements-table"
      rowTestId="engagement-row"
    />
  );
}
