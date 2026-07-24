"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { SeverityBadge } from "@/components/findings/meta";
import { ReportStatusBadge } from "@/components/reports/meta";
import { Button } from "@/components/ui/button";
import {
  ApiError,
  deleteReport,
  exportReport,
  finalizeReport,
  updateReport,
} from "@/lib/api/client";
import type { ExportFormat, ReportDetail, ReportFindingEntry } from "@/lib/api/types";

const fieldClass =
  "border-input w-full rounded-lg border bg-transparent px-2.5 py-1.5 text-sm outline-none " +
  "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 " +
  "disabled:cursor-not-allowed disabled:opacity-60";

const POAM_FIELDS: { key: keyof ReportFindingEntry; label: string; type?: "date" }[] = [
  { key: "responsible_owner", label: "Responsible owner" },
  { key: "planned_completion_date", label: "Planned completion date", type: "date" },
  { key: "milestones", label: "Milestones" },
  { key: "risk_acceptance_notes", label: "Risk acceptance notes" },
];

/** The report builder (M3-F3): edit the snapshot's summary + per-finding POA&M
 * fields while draft, finalize to lock it, and download POA&M CSV / Markdown. A
 * finalized report is read-only (server enforces it too — a save then 409s). */
export function ReportBuilder({
  engagementId,
  report,
  canEdit,
}: {
  engagementId: string;
  report: ReportDetail;
  canEdit: boolean;
}) {
  const router = useRouter();
  const [summary, setSummary] = useState(report.body.summary ?? "");
  const [findings, setFindings] = useState<ReportFindingEntry[]>(report.body.findings ?? []);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const isFinal = report.status === "final";
  const editable = canEdit && !isFinal;

  function updateFinding(index: number, key: keyof ReportFindingEntry, value: string) {
    setFindings((prev) => prev.map((f, i) => (i === index ? { ...f, [key]: value } : f)));
    setNotice(null);
  }

  async function onSave() {
    setError(null);
    setNotice(null);
    setBusy(true);
    try {
      await updateReport(engagementId, report.id, {
        body: { ...report.body, summary, findings },
      });
      setNotice("Saved.");
      router.refresh();
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 409) {
        setError("This report is finalized and can no longer be edited.");
      } else {
        setError("Could not save — try again.");
      }
    } finally {
      setBusy(false);
    }
  }

  async function onFinalize() {
    setError(null);
    setBusy(true);
    try {
      // Persist edits first, then lock.
      await updateReport(engagementId, report.id, {
        body: { ...report.body, summary, findings },
      });
      await finalizeReport(engagementId, report.id);
      router.refresh();
    } catch {
      setError("Could not finalize — try again.");
    } finally {
      setBusy(false);
    }
  }

  async function onDownload(format: ExportFormat) {
    setError(null);
    setBusy(true);
    try {
      const { blob, filename } = await exportReport(engagementId, report.id, format);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = filename;
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      URL.revokeObjectURL(url);
    } catch {
      setError("Could not export — try again.");
    } finally {
      setBusy(false);
    }
  }

  async function onDelete() {
    if (!window.confirm("Delete this report? This cannot be undone.")) {
      return;
    }
    setBusy(true);
    try {
      await deleteReport(engagementId, report.id);
      router.push(`/engagements/${engagementId}/reports`);
    } catch {
      setError("Could not delete — try again.");
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6" data-testid="report-builder">
      <div className="flex flex-wrap items-center gap-2">
        <ReportStatusBadge status={report.status} />
        <div className="ml-auto flex flex-wrap gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={busy}
            onClick={() => onDownload("csv")}
            data-testid="download-csv"
          >
            Download POA&amp;M CSV
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={busy}
            onClick={() => onDownload("markdown")}
            data-testid="download-md"
          >
            Download Markdown
          </Button>
        </div>
      </div>

      {isFinal && (
        <p
          role="note"
          className="rounded-md border border-emerald-500/40 bg-emerald-500/10 px-3 py-2 text-sm"
        >
          This report is <strong>finalized</strong> and read-only. Exports still work.
        </p>
      )}

      <div className="space-y-1.5">
        <label htmlFor="report_summary" className="text-sm font-medium">
          Summary
        </label>
        <textarea
          id="report_summary"
          className={fieldClass}
          rows={4}
          placeholder="Executive / technical narrative for this report…"
          value={summary}
          disabled={!editable}
          onChange={(e) => {
            setSummary(e.target.value);
            setNotice(null);
          }}
        />
      </div>

      <div className="space-y-4">
        <h3 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
          Findings ({findings.length})
        </h3>
        {findings.length === 0 && (
          <p className="text-sm text-muted-foreground">
            This report has no findings — run scans and regenerate.
          </p>
        )}
        {findings.map((finding, index) => (
          <div
            key={finding.finding_id}
            className="space-y-3 rounded-lg border p-3"
            data-testid="report-finding"
          >
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-muted-foreground">{finding.weakness_id}</span>
              <span className="font-medium">{finding.title}</span>
              <SeverityBadge severity={finding.severity} />
              {finding.cvss && (
                <span className="text-xs text-muted-foreground">
                  CVSS {finding.cvss.base_score.toFixed(1)}
                </span>
              )}
              {finding.mappings.length > 0 && (
                <span className="text-xs text-muted-foreground">
                  {finding.mappings.map((m) => m.code).join(", ")}
                </span>
              )}
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              {POAM_FIELDS.map(({ key, label, type }) => (
                <div key={key} className="space-y-1">
                  <label className="text-xs text-muted-foreground">{label}</label>
                  <input
                    type={type ?? "text"}
                    aria-label={label}
                    className={fieldClass}
                    value={(finding[key] as string) ?? ""}
                    disabled={!editable}
                    onChange={(e) => updateFinding(index, key, e.target.value)}
                  />
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>

      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      {notice && <p className="text-sm text-emerald-600">{notice}</p>}

      {canEdit && (
        <div className="flex flex-wrap gap-2 border-t pt-4">
          {!isFinal && (
            <>
              <Button type="button" disabled={busy} onClick={onSave}>
                {busy ? "Working…" : "Save changes"}
              </Button>
              <Button
                type="button"
                variant="outline"
                disabled={busy}
                onClick={onFinalize}
                data-testid="finalize"
              >
                Finalize
              </Button>
            </>
          )}
          <Button
            type="button"
            variant="outline"
            className="ml-auto text-destructive"
            disabled={busy}
            onClick={onDelete}
          >
            Delete
          </Button>
        </div>
      )}
    </div>
  );
}
