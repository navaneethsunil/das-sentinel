"use client";

import { useState } from "react";

import { Button } from "@/components/ui/button";
import { ApiError, deleteEngagement } from "@/lib/api/client";

export function DeleteEngagementButton({ engagementId }: { engagementId: string }) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onDelete() {
    if (!window.confirm("Delete this engagement? It disappears from every list.")) {
      return;
    }
    setBusy(true);
    try {
      await deleteEngagement(engagementId);
      window.location.assign("/engagements");
    } catch (caught) {
      setBusy(false);
      setError(
        caught instanceof ApiError && caught.status === 403
          ? "Your role can view engagements but not delete them."
          : "Delete failed — try again.",
      );
    }
  }

  return (
    <div className="space-y-2">
      <Button size="sm" variant="destructive" disabled={busy} onClick={onDelete}>
        Delete engagement
      </Button>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}
