import Link from "next/link";

import { INTENSITY_LABELS, StatusBadge } from "@/components/engagements/meta";
import { buttonVariants } from "@/components/ui/button";
import { serverGet } from "@/lib/api/server";
import type { Engagement } from "@/lib/api/types";

export const dynamic = "force-dynamic";

export const metadata = { title: "Engagements — DAS Sentinel" };

export default async function EngagementsPage() {
  const engagements = (await serverGet<Engagement[]>("/engagements")) ?? [];

  return (
    <div className="max-w-4xl space-y-6">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Engagements</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Every scan runs inside an engagement with a defined scope and an accepted ROE.
          </p>
        </div>
        <Link href="/engagements/new" className={buttonVariants()}>
          New engagement
        </Link>
      </div>
      {engagements.length === 0 ? (
        <p className="rounded-lg border border-dashed px-4 py-8 text-center text-sm text-muted-foreground">
          No engagements yet — create the first one to define scope and ROE.
        </p>
      ) : (
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-xs uppercase tracking-wider text-muted-foreground">
              <th className="py-2 pr-4 font-medium">Name</th>
              <th className="py-2 pr-4 font-medium">Client / system</th>
              <th className="py-2 pr-4 font-medium">Status</th>
              <th className="py-2 pr-4 font-medium">Max intensity</th>
              <th className="py-2 font-medium">Rate limit</th>
            </tr>
          </thead>
          <tbody>
            {engagements.map((engagement) => (
              <tr key={engagement.id} className="border-b last:border-0 hover:bg-muted/50">
                <td className="py-2.5 pr-4">
                  <Link
                    href={`/engagements/${engagement.id}`}
                    className="font-medium underline-offset-4 hover:underline"
                  >
                    {engagement.name}
                  </Link>
                </td>
                <td className="py-2.5 pr-4">{engagement.client_system_name}</td>
                <td className="py-2.5 pr-4">
                  <StatusBadge status={engagement.status} />
                </td>
                <td className="py-2.5 pr-4">{INTENSITY_LABELS[engagement.max_intensity]}</td>
                <td className="py-2.5">{engagement.rate_limit_rps} rps</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
