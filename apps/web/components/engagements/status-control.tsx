"use client";

import { useState } from "react";

import { ALLOWED_TRANSITIONS, STATUS_LABELS } from "@/components/engagements/meta";
import { Button } from "@/components/ui/button";
import { ApiError, changeEngagementStatus } from "@/lib/api/client";
import type { EngagementStatus } from "@/lib/api/types";

const ACTION_LABELS: Record<EngagementStatus, string> = {
  draft: "Back to draft", // never offered — draft is not a transition target
  active: "Activate",
  paused: "Pause",
  closed: "Close",
};

/** Offers only the transitions the state machine allows from the current
 * status; the API still enforces (409) — this is convenience, not the gate. */
export function StatusControl({
  engagementId,
  status,
}: {
  engagementId: string;
  status: EngagementStatus;
}) {
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const targets = ALLOWED_TRANSITIONS[status];

  if (targets.length === 0) {
    return (
      <p className="text-sm text-muted-foreground">
        {STATUS_LABELS[status]} is terminal — no further transitions.
      </p>
    );
  }

  async function transition(target: EngagementStatus) {
    if (target === "closed" && !window.confirm("Close this engagement? Closed is terminal.")) {
      return;
    }
    setError(null);
    setBusy(true);
    try {
      await changeEngagementStatus(engagementId, target);
      window.location.reload();
    } catch (caught) {
      setBusy(false);
      if (caught instanceof ApiError && caught.status === 403) {
        setError("Your role can view engagements but not change their status.");
      } else if (caught instanceof ApiError && caught.status === 409) {
        setError("The engagement changed state elsewhere — reload and retry.");
      } else {
        setError("Status change failed — try again.");
      }
    }
  }

  return (
    <div className="space-y-2">
      <div className="flex gap-2">
        {targets.map((target) => (
          <Button
            key={target}
            size="sm"
            variant={target === "closed" ? "destructive" : "outline"}
            disabled={busy}
            onClick={() => transition(target)}
          >
            {ACTION_LABELS[target]}
          </Button>
        ))}
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}
