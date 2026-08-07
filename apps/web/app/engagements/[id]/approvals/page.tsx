import { notFound } from "next/navigation";

import { ApprovalsManager } from "@/components/approvals/approvals-manager";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { serverGet, serverMe } from "@/lib/api/server";
import type { ApprovalGate, Engagement, Target } from "@/lib/api/types";

export const dynamic = "force-dynamic";

export const metadata = { title: "Approvals — DAS Sentinel" };

export default async function ApprovalsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const [engagement, gates, targets, me] = await Promise.all([
    serverGet<Engagement>(`/engagements/${id}`),
    serverGet<ApprovalGate[]>(`/engagements/${id}/approvals`),
    serverGet<Target[]>(`/engagements/${id}/targets`),
    serverMe(),
  ]);
  if (engagement === null) {
    notFound();
  }

  // Mirrors the API guards: requesting is LAUNCH_SCANS (Admin/Tester), deciding and
  // revoking are APPROVE_HIGH_RISK (Admin/Reviewer). Reading is VIEW — every role.
  const canRequest = me !== null && (me.role === "admin" || me.role === "tester");
  const canDecide = me !== null && (me.role === "admin" || me.role === "reviewer");
  const targetList = targets ?? [];

  return (
    <div className="max-w-4xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Approvals</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          High-risk actions — exploit validation, brute force, large-scale crawling and
          data-modifying payloads — need an approval gate bound to one exact operation, target and
          Rules-of-Engagement acknowledgement. A gate is single-use and expires; the approver must
          be someone other than the requester.
        </p>
        <p className="mt-1 text-sm text-muted-foreground">{engagement.name}</p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Gates</CardTitle>
        </CardHeader>
        <CardContent>
          {targetList.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              Add a target to this engagement before requesting an approval.
            </p>
          ) : (
            <ApprovalsManager
              engagementId={id}
              targets={targetList}
              initialGates={gates ?? []}
              targetNames={Object.fromEntries(targetList.map((t) => [t.id, t.name]))}
              canRequest={canRequest}
              canDecide={canDecide}
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
