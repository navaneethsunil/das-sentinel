"use client";

import Link from "next/link";
import { useState } from "react";

import {
  blockReasonMessage,
  LAUNCH_INTENSITY_LABELS,
  SCANNER_LABELS,
} from "@/components/scans/meta";
import { Button, buttonVariants } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { ApiError, launchScan } from "@/lib/api/client";
import {
  type LaunchIntensity,
  type ScannerKind,
  SCANNER_TARGET_TYPES,
  type Target,
} from "@/lib/api/types";

const selectClassName =
  "border-input h-8 w-full rounded-lg border bg-transparent px-2.5 text-sm outline-none " +
  "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 " +
  "disabled:cursor-not-allowed disabled:opacity-50";

const ALL_SCANNERS: ScannerKind[] = ["semgrep", "zap"];
const INTENSITIES: LaunchIntensity[] = ["safe_active", "authenticated_active"];

/** The external scanners that can run against a target of this type (a code
 * target → Semgrep; a web/API target → ZAP). */
function scannersForTarget(target: Target | undefined): ScannerKind[] {
  if (!target) {
    return [];
  }
  return ALL_SCANNERS.filter((s) => SCANNER_TARGET_TYPES[s].includes(target.target_type));
}

/** Configure and launch a SAST/DAST scanner scan. `targets` is pre-filtered to
 * the engagement's code + web/API targets; the applicable scanner is derived from
 * the chosen target's type. Scope/ROE/intensity are enforced server-side. */
export function ScannerLauncher({
  engagementId,
  targets,
  onLaunched,
}: {
  engagementId: string;
  targets: Target[];
  onLaunched: () => void;
}) {
  const [targetId, setTargetId] = useState(targets[0]?.id ?? "");
  // Track explicit deselections so every scanner applicable to the chosen target
  // is checked by default (no effect needed to sync state to the target).
  const [deselected, setDeselected] = useState<Set<ScannerKind>>(new Set());
  const [intensity, setIntensity] = useState<LaunchIntensity>("safe_active");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const selectedTarget = targets.find((t) => t.id === targetId);
  const applicable = scannersForTarget(selectedTarget);
  const isChecked = (scanner: ScannerKind) => !deselected.has(scanner);

  if (targets.length === 0) {
    return (
      <div className="space-y-3 text-sm text-muted-foreground">
        <p>
          No code or web/API targets yet. Add a target of type <em>source archive</em>,{" "}
          <em>source repo</em>, or <em>web app</em> to run SAST/DAST scanners against it.
        </p>
        <Link
          href={`/engagements/${engagementId}/targets/new`}
          className={buttonVariants({ variant: "outline", size: "sm" })}
        >
          Add code or web target
        </Link>
      </div>
    );
  }

  function toggle(scanner: ScannerKind) {
    setDeselected((prev) => {
      const next = new Set(prev);
      if (next.has(scanner)) {
        next.delete(scanner);
      } else {
        next.add(scanner);
      }
      return next;
    });
  }

  async function onLaunch(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    const scanners = applicable.filter(isChecked);
    if (scanners.length === 0) {
      setError("Choose at least one scanner to run.");
      return;
    }
    setSubmitting(true);
    try {
      await launchScan(engagementId, { target_id: targetId, scanners, intensity });
      onLaunched();
    } catch (caught) {
      setSubmitting(false);
      if (caught instanceof ApiError && caught.status === 403) {
        setError(blockReasonMessage(caught.detail));
      } else if (caught instanceof ApiError && caught.status === 422) {
        setError(caught.detail ?? "That scanner cannot run against this target type.");
      } else if (caught instanceof ApiError && caught.status === 404) {
        setError("That target no longer exists — refresh and try again.");
      } else {
        setError("Launch failed — try again.");
      }
      return;
    }
    setSubmitting(false);
  }

  return (
    <form onSubmit={onLaunch} className="space-y-4" noValidate data-testid="scanner-launcher">
      <div className="space-y-1.5">
        <Label htmlFor="scanner_target">Target</Label>
        <select
          id="scanner_target"
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

      <fieldset className="space-y-2">
        <legend className="text-sm font-medium">Scanners</legend>
        {applicable.map((scanner) => (
          <label key={scanner} className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="size-4"
              checked={isChecked(scanner)}
              onChange={() => toggle(scanner)}
            />
            {SCANNER_LABELS[scanner]}
          </label>
        ))}
      </fieldset>

      <div className="space-y-1.5">
        <Label htmlFor="scanner_intensity">Intensity</Label>
        <select
          id="scanner_intensity"
          className={selectClassName}
          value={intensity}
          onChange={(e) => setIntensity(e.target.value as LaunchIntensity)}
        >
          {INTENSITIES.map((value) => (
            <option key={value} value={value}>
              {LAUNCH_INTENSITY_LABELS[value]}
            </option>
          ))}
        </select>
      </div>

      <p
        className="rounded-lg bg-muted/50 p-2.5 text-xs text-muted-foreground"
        data-testid="high-risk-note"
      >
        High-risk actions (exploit validation, brute-force, and destructive checks) require an{" "}
        <strong>approved high-risk gate</strong> and cannot be launched from here. Request one under{" "}
        <Link href={`/engagements/${engagementId}`} className="underline">
          Approvals
        </Link>
        .
      </p>

      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <Button type="submit" disabled={submitting || !targetId}>
        {submitting ? "Launching…" : "Launch scanner"}
      </Button>
    </form>
  );
}
