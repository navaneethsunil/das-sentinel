"use client";

import { useCallback, useEffect, useState } from "react";

import { ScanStatusBadge } from "@/components/scans/meta";
import { SuiteLauncher } from "@/components/scans/suite-launcher";
import { Button } from "@/components/ui/button";
import { cancelScan, listScans } from "@/lib/api/client";
import type { Scan, ScanStatus, Target } from "@/lib/api/types";

const ACTIVE_STATUSES: ReadonlySet<ScanStatus> = new Set(["queued", "running"]);
const POLL_MS = 2500;

function isActive(scan: Scan): boolean {
  return ACTIVE_STATUSES.has(scan.status);
}

/** The engagement's AI-security-scans surface: the launcher plus a live-status
 * table. Owns the scan list so a launch (or a cancel) updates it directly, and
 * polls while any scan is still active so running/queued → terminal transitions
 * appear without a manual reload. `canCancel` gates the emergency-stop button to
 * roles that may launch scans. */
export function ScansPanel({
  engagementId,
  targets,
  initialScans,
  targetNames,
  canCancel,
}: {
  engagementId: string;
  targets: Target[];
  initialScans: Scan[];
  targetNames: Record<string, string>;
  canCancel: boolean;
}) {
  const [scans, setScans] = useState<Scan[]>(initialScans);
  const [cancelling, setCancelling] = useState<string | null>(null);
  // Stable across renders (engagementId is fixed for this page), so the polling
  // effect subscribes once per active/idle transition, not on every poll.
  const refresh = useCallback(async () => {
    try {
      setScans(await listScans(engagementId));
    } catch {
      // Transient poll failure — keep the last known list; the next tick retries.
    }
  }, [engagementId]);

  const hasActive = scans.some(isActive);
  useEffect(() => {
    if (!hasActive) {
      return;
    }
    const id = setInterval(() => void refresh(), POLL_MS);
    return () => clearInterval(id);
  }, [hasActive, refresh]);

  async function onCancel(scanId: string) {
    setCancelling(scanId);
    try {
      await cancelScan(engagementId, scanId);
    } catch {
      // 409 (already finished) or transient — reconcile from the refresh below.
    } finally {
      await refresh();
      setCancelling(null);
    }
  }

  return (
    <div className="space-y-6">
      <SuiteLauncher engagementId={engagementId} targets={targets} onLaunched={refresh} />
      {scans.length > 0 && (
        <div>
          <h3 className="mb-2 text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Recent scans
          </h3>
          <table className="w-full text-sm" data-testid="scans-table">
            <thead>
              <tr className="border-b text-left text-xs uppercase tracking-wider text-muted-foreground">
                <th className="py-2 pr-4 font-medium">Target</th>
                <th className="py-2 pr-4 font-medium">Intensity</th>
                <th className="py-2 pr-4 font-medium">Status</th>
                <th className="py-2 pr-4 font-medium">Queued</th>
                <th className="py-2 font-medium" />
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => {
                const stopping = scan.cancel_requested && isActive(scan);
                return (
                  <tr key={scan.id} className="border-b last:border-0" data-testid="scan-row">
                    <td className="py-2.5 pr-4">{targetNames[scan.target_id] ?? scan.target_id}</td>
                    <td className="py-2.5 pr-4">{scan.intensity}</td>
                    <td className="py-2.5 pr-4">
                      <span className="inline-flex items-center gap-2">
                        <ScanStatusBadge status={scan.status} />
                        {stopping && (
                          <span
                            className="text-xs text-muted-foreground"
                            data-testid="scan-stopping"
                          >
                            Stopping…
                          </span>
                        )}
                      </span>
                    </td>
                    <td className="py-2.5 pr-4 text-muted-foreground">
                      {new Date(scan.queued_at).toLocaleString()}
                    </td>
                    <td className="py-2.5 text-right">
                      {canCancel && isActive(scan) && (
                        <Button
                          type="button"
                          variant="outline"
                          size="sm"
                          disabled={cancelling === scan.id || stopping}
                          onClick={() => onCancel(scan.id)}
                        >
                          {cancelling === scan.id ? "Stopping…" : "Cancel"}
                        </Button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {hasActive && (
            <p className="mt-2 text-xs text-muted-foreground" data-testid="scans-live">
              Live — updating while scans are active.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
