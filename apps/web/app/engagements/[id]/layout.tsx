import Link from "next/link";
import { notFound } from "next/navigation";

import { StatusBadge } from "@/components/engagements/meta";
import { serverGet, serverMe } from "@/lib/api/server";
import type { Engagement } from "@/lib/api/types";

// Current-engagement context bar (M1-F5): every page under an engagement
// (detail, edit, targets) shows which engagement it belongs to and its
// status. The audit link is role-gated for nav hygiene only — the API's
// VIEW_AUDIT guard is the enforcement.
export default async function EngagementLayout({
  children,
  params,
}: {
  children: React.ReactNode;
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const [engagement, me] = await Promise.all([
    serverGet<Engagement>(`/engagements/${id}`),
    serverMe(),
  ]);
  if (engagement === null) {
    notFound();
  }
  const canViewAudit = me !== null && (me.role === "admin" || me.role === "reviewer");

  return (
    <div className="space-y-6">
      <div
        className="flex items-center justify-between gap-4 border-b pb-3 text-sm"
        data-testid="engagement-context"
      >
        <div className="flex min-w-0 items-center gap-3">
          <p className="truncate text-muted-foreground">
            <Link href="/engagements" className="underline-offset-4 hover:underline">
              Engagements
            </Link>
            {" / "}
            <Link
              href={`/engagements/${engagement.id}`}
              className="font-medium text-foreground underline-offset-4 hover:underline"
            >
              {engagement.name}
            </Link>
          </p>
          <StatusBadge status={engagement.status} />
        </div>
        {canViewAudit && (
          <Link
            href={`/audit?engagement=${engagement.id}`}
            className="shrink-0 text-muted-foreground underline-offset-4 hover:underline"
          >
            View audit log
          </Link>
        )}
      </div>
      {children}
    </div>
  );
}
