import Link from "next/link";

import { buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/** The engagement detail page's Findings entry point. Deliberately fetches
 * nothing: the detail page is already router.refresh-heavy (scope/ROE edits), so
 * the findings list lives on its own page and this is just the link to it —
 * keeping the shared detail render fast and stable. */
export function FindingsCard({ engagementId }: { engagementId: string }) {
  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="text-base">Findings</CardTitle>
        <Link
          href={`/engagements/${engagementId}/findings`}
          className={buttonVariants({ variant: "outline", size: "sm" })}
          data-testid="view-findings"
        >
          View findings
        </Link>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground">
          Evidence-backed results from this engagement&apos;s test suites — severity, OWASP LLM
          mapping, and provenance. Automated and AI-generated findings are labeled as such (not
          human-validated).
        </p>
      </CardContent>
    </Card>
  );
}
