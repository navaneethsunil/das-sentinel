import Link from "next/link";
import { notFound } from "next/navigation";

import { DeleteEngagementButton } from "@/components/engagements/delete-engagement-button";
import { INTENSITY_LABELS, StatusBadge } from "@/components/engagements/meta";
import { RoePanel } from "@/components/engagements/roe-panel";
import { ScopeEditor } from "@/components/engagements/scope-editor";
import { StatusControl } from "@/components/engagements/status-control";
import { buttonVariants } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { serverGet } from "@/lib/api/server";
import type { Engagement, ROEView, ScopeItem } from "@/lib/api/types";

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
  const [engagement, scopeItems, roe] = await Promise.all([
    serverGet<Engagement>(`/engagements/${id}`),
    serverGet<ScopeItem[]>(`/engagements/${id}/scope-items`),
    serverGet<ROEView>(`/engagements/${id}/roe`),
  ]);
  if (engagement === null || scopeItems === null || roe === null) {
    notFound();
  }

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
        <div>
          <p className="text-sm text-muted-foreground">
            <Link href="/engagements" className="underline-offset-4 hover:underline">
              Engagements
            </Link>{" "}
            /
          </p>
          <h1 className="mt-1 flex items-center gap-3 text-2xl font-semibold tracking-tight">
            {engagement.name}
            <StatusBadge status={engagement.status} />
          </h1>
        </div>
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
