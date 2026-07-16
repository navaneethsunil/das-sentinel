"use client";

import { useState } from "react";

import { INTENSITY_LABELS } from "@/components/engagements/meta";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError, createEngagement, updateEngagement } from "@/lib/api/client";
import type { Engagement, EngagementInput, ScanIntensity } from "@/lib/api/types";

function isoToLocalInput(iso: string | null): string {
  if (!iso) {
    return "";
  }
  const date = new Date(iso);
  const pad = (part: number) => String(part).padStart(2, "0");
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}` +
    `T${pad(date.getHours())}:${pad(date.getMinutes())}`
  );
}

function localInputToIso(value: string): string | null {
  return value ? new Date(value).toISOString() : null;
}

const selectClassName =
  "border-input h-8 w-full rounded-lg border bg-transparent px-2.5 text-sm outline-none " +
  "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50";

/** Create (no `engagement`) or edit (prefilled) — one form for both, all the
 * brief's fields. Status is deliberately absent: transitions go through the
 * state-machine endpoint (StatusControl), never a form write. */
export function EngagementForm({ engagement }: { engagement?: Engagement }) {
  const [name, setName] = useState(engagement?.name ?? "");
  const [clientSystemName, setClientSystemName] = useState(engagement?.client_system_name ?? "");
  const [windowStart, setWindowStart] = useState(
    isoToLocalInput(engagement?.test_window_start ?? null),
  );
  const [windowEnd, setWindowEnd] = useState(isoToLocalInput(engagement?.test_window_end ?? null));
  const [rateLimitRps, setRateLimitRps] = useState(String(engagement?.rate_limit_rps ?? 5));
  const [maxIntensity, setMaxIntensity] = useState<ScanIntensity>(
    engagement?.max_intensity ?? "safe_active",
  );
  const [hostedModelsAllowed, setHostedModelsAllowed] = useState(
    engagement?.hosted_models_allowed ?? false,
  );
  const [coordinationContact, setCoordinationContact] = useState(
    engagement?.coordination_contact ?? "",
  );
  const [emergencyStopContact, setEmergencyStopContact] = useState(
    engagement?.emergency_stop_contact ?? "",
  );
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    const input: EngagementInput = {
      name,
      client_system_name: clientSystemName,
      test_window_start: localInputToIso(windowStart),
      test_window_end: localInputToIso(windowEnd),
      rate_limit_rps: Number(rateLimitRps),
      max_intensity: maxIntensity,
      hosted_models_allowed: hostedModelsAllowed,
      coordination_contact: coordinationContact || null,
      emergency_stop_contact: emergencyStopContact || null,
    };
    try {
      const saved = engagement
        ? await updateEngagement(engagement.id, input)
        : await createEngagement(input);
      window.location.assign(`/engagements/${saved.id}`);
    } catch (caught) {
      setSubmitting(false);
      if (caught instanceof ApiError && caught.status === 403) {
        setError("Your role can view engagements but not change them.");
      } else if (caught instanceof ApiError && caught.status === 422) {
        setError("Some fields are invalid — check the test window and rate limit.");
      } else {
        setError("Saving failed — try again.");
      }
    }
  }

  return (
    <form onSubmit={onSubmit} className="max-w-xl space-y-4" noValidate>
      <div className="space-y-1.5">
        <Label htmlFor="name">Name</Label>
        <Input id="name" required value={name} onChange={(e) => setName(e.target.value)} />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="client_system_name">Client / system under test</Label>
        <Input
          id="client_system_name"
          required
          value={clientSystemName}
          onChange={(e) => setClientSystemName(e.target.value)}
        />
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-1.5">
          <Label htmlFor="test_window_start">Test window start</Label>
          <Input
            id="test_window_start"
            type="datetime-local"
            value={windowStart}
            onChange={(e) => setWindowStart(e.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="test_window_end">Test window end</Label>
          <Input
            id="test_window_end"
            type="datetime-local"
            value={windowEnd}
            onChange={(e) => setWindowEnd(e.target.value)}
          />
        </div>
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-1.5">
          <Label htmlFor="rate_limit_rps">Rate limit (requests/s)</Label>
          <Input
            id="rate_limit_rps"
            type="number"
            min={1}
            max={1000}
            required
            value={rateLimitRps}
            onChange={(e) => setRateLimitRps(e.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="max_intensity">Maximum intensity</Label>
          <select
            id="max_intensity"
            className={selectClassName}
            value={maxIntensity}
            onChange={(e) => setMaxIntensity(e.target.value as ScanIntensity)}
          >
            {Object.entries(INTENSITY_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <input
          id="hosted_models_allowed"
          type="checkbox"
          className="size-4 accent-primary"
          checked={hostedModelsAllowed}
          onChange={(e) => setHostedModelsAllowed(e.target.checked)}
        />
        <Label htmlFor="hosted_models_allowed">
          Hosted LLMs allowed (otherwise local models only)
        </Label>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="coordination_contact">Coordination contact</Label>
        <Input
          id="coordination_contact"
          value={coordinationContact}
          onChange={(e) => setCoordinationContact(e.target.value)}
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="emergency_stop_contact">Emergency-stop contact</Label>
        <Input
          id="emergency_stop_contact"
          value={emergencyStopContact}
          onChange={(e) => setEmergencyStopContact(e.target.value)}
        />
      </div>
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <Button type="submit" disabled={submitting}>
        {submitting ? "Saving…" : engagement ? "Save changes" : "Create engagement"}
      </Button>
    </form>
  );
}
