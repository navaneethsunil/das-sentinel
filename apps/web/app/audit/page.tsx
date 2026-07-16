import Link from "next/link";

import { Badge } from "@/components/ui/badge";
import { ApiError } from "@/lib/api/client";
import { serverGet } from "@/lib/api/server";
import type { AuditEvent, AuditOutcome } from "@/lib/api/types";

export const dynamic = "force-dynamic";

export const metadata = { title: "Audit log — DAS Sentinel" };

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

export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<{ engagement?: string }>;
}) {
  const { engagement } = await searchParams;
  const query = engagement ? `?engagement_id=${encodeURIComponent(engagement)}` : "";

  let events: AuditEvent[];
  try {
    events = (await serverGet<AuditEvent[]>(`/audit-events${query}`)) ?? [];
  } catch (caught) {
    if (caught instanceof ApiError && caught.status === 403) {
      return (
        <div className="max-w-2xl space-y-2">
          <h1 className="text-2xl font-semibold tracking-tight">Audit log</h1>
          <p role="alert" className="text-sm text-muted-foreground">
            The audit log is an oversight view available to Admin and Reviewer roles only.
          </p>
        </div>
      );
    }
    throw caught;
  }

  return (
    <div className="max-w-5xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Audit log</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Append-only record of every state change and blocked attempt — read-only, latest first.
        </p>
        {engagement && (
          <p className="mt-2 text-sm">
            Filtered to engagement{" "}
            <span className="font-mono text-xs">{events[0]?.engagement_name ?? engagement}</span> —{" "}
            <Link href="/audit" className="underline underline-offset-4">
              show all
            </Link>
          </p>
        )}
      </div>
      {events.length === 0 ? (
        <p className="rounded-lg border border-dashed px-4 py-8 text-center text-sm text-muted-foreground">
          No audit events{engagement ? " for this engagement" : ""} yet.
        </p>
      ) : (
        <table className="w-full text-sm" data-testid="audit-table">
          <thead>
            <tr className="border-b text-left text-xs uppercase tracking-wider text-muted-foreground">
              <th className="py-2 pr-4 font-medium">Time</th>
              <th className="py-2 pr-4 font-medium">Actor</th>
              <th className="py-2 pr-4 font-medium">Action</th>
              <th className="py-2 pr-4 font-medium">Engagement</th>
              <th className="py-2 pr-4 font-medium">Outcome</th>
              <th className="py-2 font-medium">IP</th>
            </tr>
          </thead>
          <tbody>
            {events.map((event) => (
              <tr key={event.id} className="border-b align-top last:border-0 hover:bg-muted/50">
                <td className="whitespace-nowrap py-2.5 pr-4 text-xs text-muted-foreground">
                  {new Date(event.created_at).toLocaleString()}
                </td>
                <td className="max-w-48 truncate py-2.5 pr-4">{event.actor_email ?? "system"}</td>
                <td className="py-2.5 pr-4">
                  <span
                    className="font-mono text-xs"
                    title={event.detail ? JSON.stringify(event.detail, null, 2) : undefined}
                  >
                    {event.action}
                  </span>
                  <span className="block text-xs text-muted-foreground">{event.object_type}</span>
                </td>
                <td className="max-w-48 py-2.5 pr-4">
                  {event.engagement_id ? (
                    <Link
                      href={`/audit?engagement=${event.engagement_id}`}
                      className="block truncate underline-offset-4 hover:underline"
                    >
                      {event.engagement_name ?? event.engagement_id}
                    </Link>
                  ) : (
                    "—"
                  )}
                </td>
                <td className="py-2.5 pr-4">
                  <OutcomeBadge outcome={event.outcome} />
                </td>
                <td className="py-2.5 font-mono text-xs text-muted-foreground">
                  {event.ip_address ?? "—"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
