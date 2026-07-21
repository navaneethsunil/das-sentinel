import Link from "next/link";

import { FindingsTable } from "@/components/findings/findings-table";
import { buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { serverGet } from "@/lib/api/server";
import type { Finding } from "@/lib/api/types";

const PREVIEW = 5;

/** The engagement detail page's Findings card. Fetches its own findings so it
 * can stream inside a Suspense boundary — the scope/ROE editors on the page stay
 * interactive without waiting on this read. */
export async function FindingsCard({ engagementId }: { engagementId: string }) {
  const findings = (await serverGet<Finding[]>(`/engagements/${engagementId}/findings`)) ?? [];
  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="text-base">Findings</CardTitle>
        {findings.length > 0 && (
          <Link
            href={`/engagements/${engagementId}/findings`}
            className={buttonVariants({ variant: "outline", size: "sm" })}
          >
            View all {findings.length}
          </Link>
        )}
      </CardHeader>
      <CardContent>
        {findings.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            No findings yet — run an AI security scan against an in-scope target. Automated and
            AI-generated findings appear here labeled as such (not human-validated).
          </p>
        ) : (
          <FindingsTable engagementId={engagementId} findings={findings.slice(0, PREVIEW)} />
        )}
      </CardContent>
    </Card>
  );
}

/** Streaming fallback shown while the findings read is in flight. */
export function FindingsCardFallback() {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Findings</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground">Loading findings…</p>
      </CardContent>
    </Card>
  );
}
