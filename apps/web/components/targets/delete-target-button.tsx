"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { ApiError, deleteTarget } from "@/lib/api/client";

export function DeleteTargetButton({
  engagementId,
  targetId,
}: {
  engagementId: string;
  targetId: string;
}) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onDelete() {
    if (!window.confirm("Remove this target from the engagement's inventory?")) {
      return;
    }
    setBusy(true);
    try {
      await deleteTarget(engagementId, targetId);
      router.push(`/engagements/${engagementId}`);
      router.refresh();
    } catch (caught) {
      setBusy(false);
      setError(
        caught instanceof ApiError && caught.status === 403
          ? "Your role can view targets but not delete them."
          : "Delete failed — try again.",
      );
    }
  }

  return (
    <div className="space-y-2">
      <Button size="sm" variant="destructive" disabled={busy} onClick={onDelete}>
        Delete target
      </Button>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}
