import Link from "next/link";

import { AccessDenied } from "@/components/access-denied";
import { AuditTable } from "@/components/audit/audit-table";
import { FORBIDDEN, serverGetOrForbidden } from "@/lib/api/server";
import type { AuditEvent } from "@/lib/api/types";

export const dynamic = "force-dynamic";

export const metadata = { title: "Audit log — DAS Sentinel" };

export default async function AuditPage({
  searchParams,
}: {
  searchParams: Promise<{ engagement?: string }>;
}) {
  const { engagement } = await searchParams;
  const query = engagement ? `?engagement_id=${encodeURIComponent(engagement)}` : "";

  const result = await serverGetOrForbidden<AuditEvent[]>(`/audit-events${query}`);
  if (result === FORBIDDEN) {
    return (
      <AccessDenied
        title="Audit log"
        message="The audit log is an oversight view available to Admin and Reviewer roles only."
      />
    );
  }
  const events = result ?? [];

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
        <AuditTable events={events} />
      )}
    </div>
  );
}
