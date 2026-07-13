import Link from "next/link";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

export default function DashboardPage() {
  return (
    <div className="max-w-3xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Dashboard</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Evidence-backed, compliance-mapped findings from authorized security testing.
        </p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">M0 — foundation</CardTitle>
          <CardDescription>
            Engagements, scope, and rules-of-engagement come first (M1): no scan runs without a
            saved engagement, a defined scope, and an accepted ROE.
          </CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          The stack is coming up piece by piece — check{" "}
          <Link href="/health" className="font-medium text-foreground underline underline-offset-4">
            system health
          </Link>{" "}
          for live service status.
        </CardContent>
      </Card>
    </div>
  );
}
