import Link from "next/link";

import { EngagementsTable } from "@/components/engagements/engagements-table";
import { buttonVariants } from "@/components/ui/button";
import { serverGet, serverMe } from "@/lib/api/server";
import type { Engagement } from "@/lib/api/types";

export const dynamic = "force-dynamic";

export const metadata = { title: "Engagements — DAS Sentinel" };

export default async function EngagementsPage() {
  const [engagements, me] = await Promise.all([
    serverGet<Engagement[]>("/engagements").then((list) => list ?? []),
    serverMe(),
  ]);
  // Creating an engagement is a MANAGE_ENGAGEMENTS action (Admin/Tester) — mirrors
  // the API guard, so Reviewer / Read only aren't offered a form they can't submit.
  const canManage = me !== null && (me.role === "admin" || me.role === "tester");

  return (
    <div className="max-w-6xl space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Engagements</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Every scan runs inside an engagement with a defined scope and an accepted ROE.
          </p>
        </div>
        {canManage && (
          <Link href="/engagements/new" className={buttonVariants()}>
            New engagement
          </Link>
        )}
      </div>
      {engagements.length === 0 ? (
        <p className="rounded-lg border border-dashed px-4 py-8 text-center text-sm text-muted-foreground">
          No engagements yet — create the first one to define scope and ROE.
        </p>
      ) : (
        <EngagementsTable engagements={engagements} />
      )}
    </div>
  );
}
