import { notFound } from "next/navigation";

import { DeleteTargetButton } from "@/components/targets/delete-target-button";
import { TargetForm } from "@/components/targets/target-form";
import { serverGet } from "@/lib/api/server";
import type { Target } from "@/lib/api/types";

export const dynamic = "force-dynamic";

export const metadata = { title: "Edit target — DAS Sentinel" };

export default async function EditTargetPage({
  params,
}: {
  params: Promise<{ id: string; targetId: string }>;
}) {
  const { id, targetId } = await params;
  const target = await serverGet<Target>(`/engagements/${id}/targets/${targetId}`);
  if (target === null) {
    notFound();
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Edit target</h1>
        <p className="mt-1 text-sm text-muted-foreground">{target.name}</p>
      </div>
      <TargetForm engagementId={id} target={target} />
      <DeleteTargetButton engagementId={id} targetId={target.id} />
    </div>
  );
}
