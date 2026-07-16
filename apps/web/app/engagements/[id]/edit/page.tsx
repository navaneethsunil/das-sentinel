import { notFound } from "next/navigation";

import { EngagementForm } from "@/components/engagements/engagement-form";
import { serverGet } from "@/lib/api/server";
import type { Engagement } from "@/lib/api/types";

export const dynamic = "force-dynamic";

export const metadata = { title: "Edit engagement — DAS Sentinel" };

export default async function EditEngagementPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const engagement = await serverGet<Engagement>(`/engagements/${id}`);
  if (engagement === null) {
    notFound();
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Edit engagement</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Status is not edited here — use the transitions on the detail page.
        </p>
      </div>
      <EngagementForm engagement={engagement} />
    </div>
  );
}
