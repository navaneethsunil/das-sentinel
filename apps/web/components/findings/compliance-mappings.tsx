"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import {
  addFindingMapping,
  ApiError,
  autoMapFinding,
  removeFindingMapping,
} from "@/lib/api/client";
import type { ComplianceFramework, ComplianceMapping } from "@/lib/api/types";

const selectClass =
  "border-input h-8 rounded-lg border bg-transparent px-2.5 text-sm outline-none " +
  "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50";

/** OWASP/NIST control mappings for a finding (M3-B4). Shows the mapped controls
 * as tags (with the framework + an "auto" marker for AUTOMATED mappings) and, for
 * validators, an auto-map action plus a framework→control add picker and per-tag
 * removal. Mappings are re-read from the server after every change. */
export function ComplianceMappings({
  engagementId,
  findingId,
  mappings,
  frameworks,
  canEdit,
}: {
  engagementId: string;
  findingId: string;
  mappings: ComplianceMapping[];
  frameworks: ComplianceFramework[];
  canEdit: boolean;
}) {
  const router = useRouter();
  const [frameworkKey, setFrameworkKey] = useState(frameworks[0]?.key ?? "");
  const [controlId, setControlId] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const selectedFramework = frameworks.find((f) => f.key === frameworkKey);
  const mappedControlIds = new Set(mappings.map((m) => m.control_id));

  async function run(action: () => Promise<unknown>) {
    setError(null);
    setBusy(true);
    try {
      await action();
      router.refresh();
    } catch (caught) {
      setError(
        caught instanceof ApiError && caught.detail ? caught.detail : "Action failed — try again.",
      );
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4" data-testid="compliance-mappings">
      {mappings.length === 0 ? (
        <p className="text-sm text-muted-foreground">No control mappings yet.</p>
      ) : (
        <ul className="flex flex-wrap gap-2">
          {mappings.map((m) => (
            <li key={m.control_id}>
              <span
                className="inline-flex items-center gap-1.5 rounded border px-2 py-1 text-xs"
                title={`${m.framework_name}: ${m.title}`}
                data-testid="mapping-tag"
              >
                <span className="font-mono font-medium">{m.code}</span>
                <span className="text-muted-foreground">{m.framework_key}</span>
                {m.mapped_by === "automated" && (
                  <span className="text-[10px] uppercase tracking-wide text-muted-foreground">
                    auto
                  </span>
                )}
                {canEdit && (
                  <button
                    type="button"
                    aria-label={`Remove ${m.code}`}
                    className="ml-0.5 text-muted-foreground hover:text-destructive disabled:opacity-50"
                    disabled={busy}
                    onClick={() =>
                      run(() => removeFindingMapping(engagementId, findingId, m.control_id))
                    }
                  >
                    ×
                  </button>
                )}
              </span>
            </li>
          ))}
        </ul>
      )}

      {canEdit && (
        <div className="space-y-3 border-t pt-4">
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={busy}
            onClick={() => run(() => autoMapFinding(engagementId, findingId))}
            data-testid="auto-map"
          >
            Auto-map from finding
          </Button>
          <div className="flex flex-wrap items-end gap-2">
            <select
              aria-label="Framework"
              className={selectClass}
              value={frameworkKey}
              onChange={(e) => {
                setFrameworkKey(e.target.value);
                setControlId("");
              }}
            >
              {frameworks.map((f) => (
                <option key={f.key} value={f.key}>
                  {f.name}
                </option>
              ))}
            </select>
            <select
              aria-label="Control"
              className={selectClass}
              value={controlId}
              onChange={(e) => setControlId(e.target.value)}
            >
              <option value="">Select a control…</option>
              {selectedFramework?.controls.map((c) => (
                <option key={c.id} value={c.id} disabled={mappedControlIds.has(c.id)}>
                  {c.code} — {c.title}
                </option>
              ))}
            </select>
            <Button
              type="button"
              size="sm"
              disabled={busy || !controlId}
              onClick={() => run(() => addFindingMapping(engagementId, findingId, controlId))}
            >
              Add mapping
            </Button>
          </div>
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
        </div>
      )}
    </div>
  );
}
