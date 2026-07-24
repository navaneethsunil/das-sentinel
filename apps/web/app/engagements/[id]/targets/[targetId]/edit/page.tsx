import { notFound } from "next/navigation";

import { DeleteTargetButton } from "@/components/targets/delete-target-button";
import { SourceArchiveUpload } from "@/components/targets/source-archive-upload";
import { TargetForm } from "@/components/targets/target-form";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
      {target.target_type === "source_archive" && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Source archive</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <p className="text-sm text-muted-foreground">
              Upload the code archive (.zip or .tar) to scan. It is stored as content-addressed
              evidence; the Semgrep SAST scanner materializes it at scan time.
            </p>
            <SourceArchiveUpload engagementId={id} targetId={target.id} />
          </CardContent>
        </Card>
      )}
      <DeleteTargetButton engagementId={id} targetId={target.id} />
    </div>
  );
}
