"use client";

import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  ApiError,
  decideApproval,
  launchScan,
  listApprovals,
  requestApproval,
  revokeApproval,
} from "@/lib/api/client";
import {
  type ApprovalGate,
  type ApprovalStatus,
  HIGH_RISK_OPERATION_KINDS,
  type HighRiskOperationKind,
  type Target,
} from "@/lib/api/types";

const selectClassName =
  "border-input h-8 w-full rounded-lg border bg-transparent px-2.5 text-sm outline-none " +
  "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 " +
  "disabled:cursor-not-allowed disabled:opacity-50";

const STATUS_STYLES: Record<ApprovalStatus, string> = {
  pending: "bg-muted text-foreground hover:bg-muted",
  approved: "bg-emerald-600 text-white hover:bg-emerald-600",
  denied: "bg-red-600 text-white hover:bg-red-600",
  expired: "bg-amber-600 text-white hover:bg-amber-600",
  revoked: "bg-amber-600 text-white hover:bg-amber-600",
  consumed: "bg-sky-600 text-white hover:bg-sky-600",
};

const KIND_LABELS: Record<HighRiskOperationKind, string> = {
  exploit_validation: "Exploit validation",
  brute_force: "Brute force / password spraying",
  large_crawl: "Large-scale crawl",
  data_modifying: "Data-modifying payloads",
};

/** The high-risk approval surface (M1-B11): request a gate, decide it, revoke it,
 * and spend an approved one. Controls are gated by capability exactly as the API
 * is — `canRequest` is LAUNCH_SCANS (Admin/Tester), `canDecide` is
 * APPROVE_HIGH_RISK (Admin/Reviewer) — so no role is offered a button it cannot
 * use; the API remains the enforcement either way. */
export function ApprovalsManager({
  engagementId,
  targets,
  initialGates,
  targetNames,
  canRequest,
  canDecide,
}: {
  engagementId: string;
  targets: Target[];
  initialGates: ApprovalGate[];
  targetNames: Record<string, string>;
  canRequest: boolean;
  canDecide: boolean;
}) {
  const [gates, setGates] = useState<ApprovalGate[]>(initialGates);
  const [targetId, setTargetId] = useState(targets[0]?.id ?? "");
  const [kind, setKind] = useState<HighRiskOperationKind>("exploit_validation");
  const [justification, setJustification] = useState("");
  const [hours, setHours] = useState("24");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  async function refresh() {
    try {
      setGates(await listApprovals(engagementId));
    } catch {
      // keep the last known list; the next action refreshes again
    }
  }

  function surface(caught: unknown, fallback: string) {
    setNotice(null);
    if (caught instanceof ApiError && caught.detail) {
      setError(caught.detail);
      return;
    }
    setError(fallback);
  }

  async function onRequest(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setNotice(null);
    if (!justification.trim()) {
      setError("Give a justification — it is recorded on the gate and in the audit log.");
      return;
    }
    setBusy("request");
    try {
      await requestApproval(engagementId, {
        target_id: targetId,
        operation_kind: kind,
        justification,
        expires_in_hours: Number(hours),
      });
      setJustification("");
      setNotice("Requested. A second person (Admin or Reviewer) must decide it.");
      await refresh();
    } catch (caught) {
      surface(caught, "Could not request the gate — try again.");
    } finally {
      setBusy(null);
    }
  }

  async function onDecide(gate: ApprovalGate, approve: boolean) {
    setError(null);
    setNotice(null);
    setBusy(gate.id);
    try {
      await decideApproval(engagementId, gate.id, approve, reason);
      setNotice(approve ? "Approved." : "Denied.");
      await refresh();
    } catch (caught) {
      surface(caught, "Could not record the decision.");
    } finally {
      setBusy(null);
    }
  }

  async function onRevoke(gate: ApprovalGate) {
    setError(null);
    setNotice(null);
    setBusy(gate.id);
    try {
      await revokeApproval(engagementId, gate.id, reason);
      setNotice("Revoked.");
      await refresh();
    } catch (caught) {
      surface(caught, "Could not revoke the gate.");
    } finally {
      setBusy(null);
    }
  }

  // Spending the gate: the API derives the high-risk operation kind from the gate
  // itself, so the launch carries only the target and the approval id.
  async function onLaunch(gate: ApprovalGate) {
    setError(null);
    setNotice(null);
    setBusy(gate.id);
    try {
      const scan = await launchScan(engagementId, {
        target_id: gate.target_id,
        scanners: ["zap"],
        intensity: "safe_active",
        approval_id: gate.id,
      });
      setNotice(
        `Launched the approved action — scan ${scan.id.slice(0, 8)}… at ${scan.intensity}.`,
      );
      await refresh();
    } catch (caught) {
      surface(caught, "Could not launch the approved action.");
    } finally {
      setBusy(null);
    }
  }

  return (
    <div className="space-y-6" data-testid="approvals-manager">
      {canRequest ? (
        <form
          onSubmit={onRequest}
          className="max-w-xl space-y-3"
          data-testid="approval-request-form"
        >
          <div className="space-y-1.5">
            <Label htmlFor="approval_target">Target</Label>
            <select
              id="approval_target"
              className={selectClassName}
              value={targetId}
              onChange={(e) => setTargetId(e.target.value)}
            >
              {targets.map((target) => (
                <option key={target.id} value={target.id}>
                  {target.name} ({target.primary_value})
                </option>
              ))}
            </select>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-1.5">
              <Label htmlFor="approval_kind">High-risk action</Label>
              <select
                id="approval_kind"
                className={selectClassName}
                value={kind}
                onChange={(e) => setKind(e.target.value as HighRiskOperationKind)}
              >
                {HIGH_RISK_OPERATION_KINDS.map((value) => (
                  <option key={value} value={value}>
                    {KIND_LABELS[value]}
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="approval_hours">Expires in (hours)</Label>
              <Input
                id="approval_hours"
                type="number"
                min={1}
                max={168}
                value={hours}
                onChange={(e) => setHours(e.target.value)}
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="approval_justification">Justification</Label>
            <Input
              id="approval_justification"
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              placeholder="Why this action is needed, and the client's authorization for it"
            />
          </div>
          <Button type="submit" disabled={busy === "request" || !targetId}>
            {busy === "request" ? "Requesting…" : "Request approval"}
          </Button>
        </form>
      ) : (
        <p className="text-sm text-muted-foreground" data-testid="approvals-cannot-request">
          Your role can review approvals but not request them.
        </p>
      )}

      {canDecide && (
        <div className="max-w-xl space-y-1.5">
          <Label htmlFor="approval_reason">Decision / revocation reason</Label>
          <Input
            id="approval_reason"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Recorded on the gate and in the audit log"
          />
        </div>
      )}

      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      {notice && (
        <p className="text-sm text-emerald-600" data-testid="approval-notice">
          {notice}
        </p>
      )}

      {gates.length === 0 ? (
        <p className="rounded-lg border border-dashed px-4 py-8 text-center text-sm text-muted-foreground">
          No approval gates for this engagement yet.
        </p>
      ) : (
        <table className="w-full text-sm" data-testid="approvals-table">
          <thead>
            <tr className="border-b text-left text-xs uppercase tracking-wider text-muted-foreground">
              <th className="py-2 pr-4 font-medium">Action</th>
              <th className="py-2 pr-4 font-medium">Target</th>
              <th className="py-2 pr-4 font-medium">Status</th>
              <th className="py-2 pr-4 font-medium">Expires</th>
              <th className="py-2 font-medium" />
            </tr>
          </thead>
          <tbody>
            {gates.map((gate) => (
              <tr
                key={gate.id}
                className="border-b align-top last:border-0"
                data-testid="approval-row"
              >
                <td className="py-2.5 pr-4">
                  <span className="font-medium">
                    {KIND_LABELS[gate.action_type as HighRiskOperationKind] ?? gate.action_type}
                  </span>
                  <span className="block max-w-72 truncate text-xs text-muted-foreground">
                    {gate.justification}
                  </span>
                </td>
                <td className="py-2.5 pr-4">{targetNames[gate.target_id] ?? gate.target_id}</td>
                <td className="py-2.5 pr-4">
                  <Badge className={STATUS_STYLES[gate.status]} data-testid="approval-status">
                    {gate.status}
                  </Badge>
                </td>
                <td className="whitespace-nowrap py-2.5 pr-4 text-xs text-muted-foreground">
                  {new Date(gate.expires_at).toLocaleString()}
                </td>
                <td className="py-2.5 text-right">
                  <span className="inline-flex gap-2">
                    {canDecide && gate.status === "pending" && (
                      <>
                        <Button
                          type="button"
                          size="sm"
                          disabled={busy === gate.id}
                          onClick={() => onDecide(gate, true)}
                        >
                          Approve
                        </Button>
                        <Button
                          type="button"
                          size="sm"
                          variant="outline"
                          disabled={busy === gate.id}
                          onClick={() => onDecide(gate, false)}
                        >
                          Deny
                        </Button>
                      </>
                    )}
                    {gate.status === "approved" && (
                      <>
                        {canRequest && (
                          <Button
                            type="button"
                            size="sm"
                            disabled={busy === gate.id}
                            onClick={() => onLaunch(gate)}
                          >
                            Launch approved action
                          </Button>
                        )}
                        {canDecide && (
                          <Button
                            type="button"
                            size="sm"
                            variant="outline"
                            disabled={busy === gate.id}
                            onClick={() => onRevoke(gate)}
                          >
                            Revoke
                          </Button>
                        )}
                      </>
                    )}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
