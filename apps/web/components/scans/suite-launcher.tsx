"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useState } from "react";

import { blockReasonMessage, LAUNCH_INTENSITY_LABELS, SUITE_LABELS } from "@/components/scans/meta";
import { Button, buttonVariants } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { ApiError, launchScan } from "@/lib/api/client";
import type { LaunchIntensity, Target, TestSuite } from "@/lib/api/types";

const selectClassName =
  "border-input h-8 w-full rounded-lg border bg-transparent px-2.5 text-sm outline-none " +
  "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 " +
  "disabled:cursor-not-allowed disabled:opacity-50";

const ALL_SUITES: TestSuite[] = ["prompt_injection", "data_leakage"];
const INTENSITIES: LaunchIntensity[] = ["safe_active", "authenticated_active"];

/** Configure and launch an LLM test-suite scan. `targets` is pre-filtered to
 * the engagement's LLM connector targets; scope/ROE/intensity are all enforced
 * server-side, so this surfaces the scope keystone's reason on a block. */
export function SuiteLauncher({
  engagementId,
  targets,
}: {
  engagementId: string;
  targets: Target[];
}) {
  const router = useRouter();
  const [targetId, setTargetId] = useState(targets[0]?.id ?? "");
  const [suites, setSuites] = useState<Set<TestSuite>>(new Set(["prompt_injection"]));
  const [intensity, setIntensity] = useState<LaunchIntensity>("safe_active");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (targets.length === 0) {
    return (
      <div className="space-y-3 text-sm text-muted-foreground">
        <p>
          No LLM targets yet. Add a target of type <em>AI chatbot</em> or <em>LLM API wrapper</em>{" "}
          (with its connector config) to run AI security suites against it.
        </p>
        <Link
          href={`/engagements/${engagementId}/targets/new`}
          className={buttonVariants({ variant: "outline", size: "sm" })}
        >
          Add LLM target
        </Link>
      </div>
    );
  }

  function toggleSuite(suite: TestSuite) {
    setSuites((prev) => {
      const next = new Set(prev);
      if (next.has(suite)) {
        next.delete(suite);
      } else {
        next.add(suite);
      }
      return next;
    });
  }

  async function onLaunch(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    if (suites.size === 0) {
      setError("Choose at least one suite to run.");
      return;
    }
    setSubmitting(true);
    try {
      await launchScan(engagementId, {
        target_id: targetId,
        // Preserve a stable suite order regardless of click order.
        suites: ALL_SUITES.filter((s) => suites.has(s)),
        intensity,
      });
      router.refresh();
    } catch (caught) {
      setSubmitting(false);
      if (caught instanceof ApiError && caught.status === 403) {
        setError(blockReasonMessage(caught.detail));
      } else if (caught instanceof ApiError && caught.status === 422) {
        setError(caught.detail ?? "The target is not a launchable LLM connector.");
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
    <form onSubmit={onLaunch} className="space-y-4" noValidate>
      <div className="space-y-1.5">
        <Label htmlFor="scan_target">Target</Label>
        <select
          id="scan_target"
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
        <legend className="text-sm font-medium">Suites</legend>
        {ALL_SUITES.map((suite) => (
          <label key={suite} className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              className="size-4"
              checked={suites.has(suite)}
              onChange={() => toggleSuite(suite)}
            />
            {SUITE_LABELS[suite]}
          </label>
        ))}
      </fieldset>

      <div className="space-y-1.5">
        <Label htmlFor="scan_intensity">Intensity</Label>
        <select
          id="scan_intensity"
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
        <p className="text-xs text-muted-foreground">
          The effective intensity is derived and checked against the engagement ceiling — a scan
          over that ceiling is blocked.
        </p>
      </div>

      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <Button type="submit" disabled={submitting || !targetId}>
        {submitting ? "Launching…" : "Launch scan"}
      </Button>
    </form>
  );
}
