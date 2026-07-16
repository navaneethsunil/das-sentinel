"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { acceptRoe, ApiError } from "@/lib/api/client";
import type { ROEView } from "@/lib/api/types";

/** Renders the current ROE and the signed-acknowledgement acceptance flow.
 * Acceptance sends the content hash of exactly what was rendered here — the
 * server refuses (409) if the ROE changed since, so a stale page can never
 * accept terms its user did not see. Any scope or frozen-term change flips
 * the panel back to "Acceptance required". */
export function RoePanel({ engagementId, roe }: { engagementId: string; roe: ROEView }) {
  const router = useRouter();
  const [acknowledged, setAcknowledged] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onAccept() {
    setError(null);
    setBusy(true);
    try {
      await acceptRoe(engagementId, roe.content_hash);
      setAcknowledged(false);
      router.refresh();
      setBusy(false);
    } catch (caught) {
      setBusy(false);
      // Content changed since render: force a re-read — refresh brings in the
      // current ROE and the acknowledgement checkbox resets with it.
      if (caught instanceof ApiError && caught.status === 409) {
        setAcknowledged(false);
        setError(
          "The ROE changed since this page was rendered — review the current version below and accept again.",
        );
        router.refresh();
      } else if (caught instanceof ApiError && caught.status === 403) {
        setError("Your role can view the ROE but not accept it.");
      } else {
        setError("Accepting the ROE failed — try again.");
      }
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        {roe.is_accepted ? (
          <Badge
            className="bg-emerald-600 text-white hover:bg-emerald-600"
            data-testid="roe-status"
          >
            Accepted
          </Badge>
        ) : (
          <Badge className="bg-amber-500 text-white hover:bg-amber-500" data-testid="roe-status">
            Acceptance required
          </Badge>
        )}
        {roe.is_accepted && roe.accepted_at && (
          <span className="text-sm text-muted-foreground">
            Accepted {new Date(roe.accepted_at).toLocaleString()}
          </span>
        )}
      </div>
      <pre
        data-testid="roe-text"
        className="max-h-80 overflow-y-auto rounded-lg border bg-muted/50 p-4 text-xs whitespace-pre-wrap"
      >
        {roe.roe_text}
      </pre>
      <p className="text-xs text-muted-foreground">
        Content hash:{" "}
        <span className="font-mono break-all" title="SHA-256 over the ROE text, scope, and terms">
          {roe.content_hash}
        </span>
      </p>
      {roe.requires_reacceptance && (
        <div className="space-y-3 border-t pt-4">
          <div className="flex items-start gap-2">
            <input
              id="roe_acknowledged"
              type="checkbox"
              className="mt-0.5 size-4 accent-primary"
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
            />
            <Label htmlFor="roe_acknowledged" className="leading-snug">
              I have read the Rules of Engagement above and confirm I am authorized to accept them
              for this engagement.
            </Label>
          </div>
          <Button size="sm" disabled={!acknowledged || busy} onClick={onAccept}>
            Accept Rules of Engagement
          </Button>
        </div>
      )}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}
