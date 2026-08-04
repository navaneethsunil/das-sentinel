import { notFound } from "next/navigation";

import { TargetForm } from "@/components/targets/target-form";
import { serverGet, serverGetOptional } from "@/lib/api/server";
import type { Credential, Engagement } from "@/lib/api/types";

export const dynamic = "force-dynamic";

export const metadata = { title: "Add target — DAS Sentinel" };

export default async function NewTargetPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const engagement = await serverGet<Engagement>(`/engagements/${id}`);
  if (engagement === null) {
    notFound();
  }
  // A viewer without MANAGE_CREDENTIALS gets 403 → null → an empty picker;
  // the form itself still renders (the API is the enforcement on submit).
  const credentials = (await serverGetOptional<Credential[]>("/credentials")) ?? [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Add target</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Inventory entry for {engagement.name} — being listed here does not authorize testing;
          scope and ROE still gate every run.
        </p>
      </div>
      <TargetForm engagementId={engagement.id} credentials={credentials} />
    </div>
  );
}
