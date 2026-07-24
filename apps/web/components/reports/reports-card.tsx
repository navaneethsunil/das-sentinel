import Link from "next/link";

import { buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

/** The engagement detail page's Reports entry point. Fetches nothing (the detail
 * page's render is kept fast/stable — M2-F3 lesson); the reports surface lives on
 * its own route. */
export function ReportsCard({ engagementId }: { engagementId: string }) {
  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="text-base">Reports</CardTitle>
        <Link
          href={`/engagements/${engagementId}/reports`}
          className={buttonVariants({ variant: "outline", size: "sm" })}
          data-testid="view-reports"
        >
          View reports
        </Link>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground">
          Generate a POA&amp;M or technical report from this engagement&apos;s findings — editable
          before export to CSV or Markdown.
        </p>
      </CardContent>
    </Card>
  );
}
