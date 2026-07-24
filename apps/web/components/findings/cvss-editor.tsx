"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { SeverityBadge } from "@/components/findings/meta";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { ApiError, setFindingCvss } from "@/lib/api/client";
import type { CvssScore, CvssVersion } from "@/lib/api/types";

const fieldClass =
  "border-input w-full rounded-lg border bg-transparent px-2.5 py-1.5 text-sm outline-none " +
  "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50";

const VERSION_LABELS: Record<CvssVersion, string> = {
  v4_0: "CVSS v4.0",
  v3_1: "CVSS v3.1",
};

/** CVSS scoring for a finding (M3-B3): shows the current score + insert-only
 * history and, for validators, a form to (re)score from a v4.0/v3.1 vector. The
 * base score + band are derived server-side from the vector; a manual override
 * requires a justification. */
export function CvssEditor({
  engagementId,
  findingId,
  current,
  history,
  canEdit,
}: {
  engagementId: string;
  findingId: string;
  current: CvssScore | null;
  history: CvssScore[];
  canEdit: boolean;
}) {
  const router = useRouter();
  const [vector, setVector] = useState("");
  const [override, setOverride] = useState(false);
  const [justification, setJustification] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    if (!vector.trim()) {
      setError("Enter a CVSS vector string.");
      return;
    }
    if (override && !justification.trim()) {
      setError("A manual override needs a justification.");
      return;
    }
    setSaving(true);
    try {
      await setFindingCvss(engagementId, findingId, {
        vector_string: vector.trim(),
        is_manual_override: override,
        override_justification: override ? justification.trim() : undefined,
      });
      setVector("");
      setOverride(false);
      setJustification("");
      router.refresh();
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 422) {
        setError(caught.detail ?? "That is not a valid CVSS vector.");
      } else {
        setError("Could not save the score — try again.");
      }
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="space-y-4" data-testid="cvss-editor">
      {current ? (
        <div className="space-y-1.5">
          <div className="flex items-center gap-3">
            <span className="text-2xl font-semibold tabular-nums" data-testid="cvss-score">
              {current.base_score.toFixed(1)}
            </span>
            <SeverityBadge severity={current.severity_band} />
            <span className="text-xs text-muted-foreground">
              {VERSION_LABELS[current.version]}
              {current.is_manual_override ? " · manual override" : ""}
            </span>
          </div>
          <p className="font-mono text-xs break-all text-muted-foreground">
            {current.vector_string}
          </p>
          {current.is_manual_override && current.override_justification && (
            <p className="text-xs">
              <span className="text-muted-foreground">Override justification: </span>
              {current.override_justification}
            </p>
          )}
        </div>
      ) : (
        <p className="text-sm text-muted-foreground">Not scored yet.</p>
      )}

      {history.length > 1 && (
        <details className="text-xs">
          <summary className="cursor-pointer text-muted-foreground">
            Score history ({history.length})
          </summary>
          <ul className="mt-2 space-y-1">
            {history.map((entry) => (
              <li key={entry.id} className="flex justify-between gap-3">
                <span>
                  {entry.base_score.toFixed(1)} {VERSION_LABELS[entry.version]}
                  {entry.is_manual_override ? " (override)" : ""}
                </span>
                <span className="text-muted-foreground">
                  {new Date(entry.created_at).toLocaleString()}
                </span>
              </li>
            ))}
          </ul>
        </details>
      )}

      {canEdit && (
        <form onSubmit={onSubmit} className="space-y-3 border-t pt-4" noValidate>
          <div className="space-y-1.5">
            <Label htmlFor="cvss_vector">
              {current ? "Re-score with a new vector" : "Score with a vector"}
            </Label>
            <input
              id="cvss_vector"
              className={fieldClass}
              placeholder="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
              value={vector}
              onChange={(e) => setVector(e.target.value)}
            />
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="size-4"
              checked={override}
              onChange={(e) => setOverride(e.target.checked)}
            />
            Manual override (requires a justification)
          </label>
          {override && (
            <textarea
              className={fieldClass}
              rows={2}
              placeholder="Why this score is being set manually…"
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
            />
          )}
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
          <Button type="submit" disabled={saving}>
            {saving ? "Saving…" : "Save score"}
          </Button>
        </form>
      )}
    </div>
  );
}
