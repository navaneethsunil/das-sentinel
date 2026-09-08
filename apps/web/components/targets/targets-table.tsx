"use client";

import Link from "next/link";

import {
  AUTH_STATUS_LABELS,
  ENVIRONMENT_LABELS,
  EnvironmentBadge,
  TARGET_TYPE_LABELS,
} from "@/components/targets/meta";
import { type DataColumn, DataTable, formatDateTime } from "@/components/ui/data-table";
import type { Target } from "@/lib/api/types";

export function TargetsTable({
  engagementId,
  targets,
}: {
  engagementId: string;
  targets: Target[];
}) {
  const columns: DataColumn<Target>[] = [
    {
      key: "name",
      label: "Name",
      value: (t) => `${t.name} ${t.primary_value}`,
      render: (t) => (
        <>
          <Link
            href={`/engagements/${engagementId}/targets/${t.id}/edit`}
            className="font-medium underline-offset-4 hover:underline"
          >
            {t.name}
          </Link>
          <span className="block max-w-64 truncate font-mono text-xs text-muted-foreground">
            {t.primary_value}
          </span>
        </>
      ),
    },
    { key: "type", label: "Type", value: (t) => TARGET_TYPE_LABELS[t.target_type] },
    {
      key: "environment",
      label: "Environment",
      value: (t) => ENVIRONMENT_LABELS[t.environment],
      render: (t) => <EnvironmentBadge environment={t.environment} />,
    },
    { key: "auth", label: "Auth", value: (t) => AUTH_STATUS_LABELS[t.auth_status] },
    {
      key: "created",
      label: "Created",
      value: (t) => formatDateTime(t.created_at),
      sortValue: (t) => Date.parse(t.created_at),
      className: "whitespace-nowrap py-2.5 pr-4 text-xs text-muted-foreground",
    },
    {
      key: "updated",
      label: "Updated",
      value: (t) => formatDateTime(t.updated_at),
      sortValue: (t) => Date.parse(t.updated_at),
      className: "whitespace-nowrap py-2.5 text-xs text-muted-foreground",
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={targets}
      rowKey={(t) => t.id}
      testId="targets-table"
      rowTestId="target-row"
    />
  );
}
