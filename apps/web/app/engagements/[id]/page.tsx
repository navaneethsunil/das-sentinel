import Link from "next/link";
import { notFound } from "next/navigation";

import { DeleteEngagementButton } from "@/components/engagements/delete-engagement-button";
import { INTENSITY_LABELS } from "@/components/engagements/meta";
import { RoePanel } from "@/components/engagements/roe-panel";
import { ScopeEditor } from "@/components/engagements/scope-editor";
import { StatusControl } from "@/components/engagements/status-control";
import { FindingsCard } from "@/components/findings/findings-card";
import { ReportsCard } from "@/components/reports/reports-card";
import { ScansPanel } from "@/components/scans/scans-panel";
import {
  AUTH_STATUS_LABELS,
  EnvironmentBadge,
  TARGET_TYPE_LABELS,
} from "@/components/targets/meta";
import { buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { serverGet, serverMe } from "@/lib/api/server";
import {
  CODE_TARGET_TYPES,
  type Engagement,
  LLM_TARGET_TYPES,
  type ROEView,
  type Scan,
  type ScopeItem,
  type Target,
  WEB_TARGET_TYPES,
} from "@/lib/api/types";

export const dynamic = "force-dynamic";

function formatWindow(iso: string | null): string {
  return iso ? new Date(iso).toLocaleString() : "—";
}

export default async function EngagementDetailPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const [engagement, scopeItems, roe, targets, scans, me] = await Promise.all([
    serverGet<Engagement>(`/engagements/${id}`),
    serverGet<ScopeItem[]>(`/engagements/${id}/scope-items`),
    serverGet<ROEView>(`/engagements/${id}/roe`),
    serverGet<Target[]>(`/engagements/${id}/targets`),
    serverGet<Scan[]>(`/engagements/${id}/scans`),
    serverMe(),
  ]);
  if (
    engagement === null ||
    scopeItems === null ||
    roe === null ||
    targets === null ||
    scans === null
  ) {
    notFound();
  }

  const llmTargets = targets.filter((t) => LLM_TARGET_TYPES.includes(t.target_type));
  const scannerTargets = targets.filter(
    (t) => CODE_TARGET_TYPES.includes(t.target_type) || WEB_TARGET_TYPES.includes(t.target_type),
  );
  const targetNames = Object.fromEntries(targets.map((t) => [t.id, t.name]));
  // Emergency stop is a LAUNCH_SCANS action (Admin/Tester) — mirrors the API guard.
  const canCancel = me !== null && (me.role === "admin" || me.role === "tester");

  const fields: [string, React.ReactNode][] = [
    ["Client / system", engagement.client_system_name],
    ["Test window start", formatWindow(engagement.test_window_start)],
    ["Test window end", formatWindow(engagement.test_window_end)],
    ["Rate limit", `${engagement.rate_limit_rps} rps`],
    ["Maximum intensity", INTENSITY_LABELS[engagement.max_intensity]],
    ["Hosted LLMs", engagement.hosted_models_allowed ? "Allowed" : "Local models only"],
    ["Coordination contact", engagement.coordination_contact ?? "—"],
    ["Emergency-stop contact", engagement.emergency_stop_contact ?? "—"],
    ["Created", new Date(engagement.created_at).toLocaleString()],
    ["Updated", new Date(engagement.updated_at).toLocaleString()],
  ];

  return (
    <div className="max-w-3xl space-y-6">
      <div className="flex items-start justify-between gap-4">
        <h1 className="text-2xl font-semibold tracking-tight">{engagement.name}</h1>
        <Link
          href={`/engagements/${engagement.id}/edit`}
          className={buttonVariants({ variant: "outline", size: "sm" })}
        >
          Edit
        </Link>
      </div>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Details</CardTitle>
        </CardHeader>
        <CardContent>
          <dl className="divide-y text-sm">
            {fields.map(([label, value]) => (
              <div key={label} className="flex justify-between gap-4 py-2">
                <dt className="text-muted-foreground">{label}</dt>
                <dd className="text-right">{value}</dd>
              </div>
            ))}
          </dl>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Scope</CardTitle>
        </CardHeader>
        <CardContent>
          <ScopeEditor engagementId={engagement.id} items={scopeItems} />
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Rules of Engagement</CardTitle>
        </CardHeader>
        <CardContent>
          <RoePanel engagementId={engagement.id} roe={roe} />
        </CardContent>
      </Card>
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <CardTitle className="text-base">Targets</CardTitle>
          <Link
            href={`/engagements/${engagement.id}/targets/new`}
            className={buttonVariants({ variant: "outline", size: "sm" })}
          >
            Add target
          </Link>
        </CardHeader>
        <CardContent>
          {targets.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No targets yet — add the systems this engagement is authorized to test.
            </p>
          ) : (
            <table className="w-full text-sm" data-testid="targets-table">
              <thead>
                <tr className="border-b text-left text-xs uppercase tracking-wider text-muted-foreground">
                  <th className="py-2 pr-4 font-medium">Name</th>
                  <th className="py-2 pr-4 font-medium">Type</th>
                  <th className="py-2 pr-4 font-medium">Environment</th>
                  <th className="py-2 font-medium">Auth</th>
                </tr>
              </thead>
              <tbody>
                {targets.map((target) => (
                  <tr key={target.id} className="border-b last:border-0 hover:bg-muted/50">
                    <td className="py-2.5 pr-4">
                      <Link
                        href={`/engagements/${engagement.id}/targets/${target.id}/edit`}
                        className="font-medium underline-offset-4 hover:underline"
                      >
                        {target.name}
                      </Link>
                      <span className="block max-w-64 truncate font-mono text-xs text-muted-foreground">
                        {target.primary_value}
                      </span>
                    </td>
                    <td className="py-2.5 pr-4">{TARGET_TYPE_LABELS[target.target_type]}</td>
                    <td className="py-2.5 pr-4">
                      <EnvironmentBadge environment={target.environment} />
                    </td>
                    <td className="py-2.5">{AUTH_STATUS_LABELS[target.auth_status]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Scans</CardTitle>
        </CardHeader>
        <CardContent>
          <ScansPanel
            engagementId={engagement.id}
            targets={llmTargets}
            scannerTargets={scannerTargets}
            initialScans={scans}
            targetNames={targetNames}
            canCancel={canCancel}
          />
        </CardContent>
      </Card>
      <FindingsCard engagementId={engagement.id} />
      <ReportsCard engagementId={engagement.id} />
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Status</CardTitle>
        </CardHeader>
        <CardContent>
          <StatusControl engagementId={engagement.id} status={engagement.status} />
        </CardContent>
      </Card>
      <DeleteEngagementButton engagementId={engagement.id} />
    </div>
  );
}
