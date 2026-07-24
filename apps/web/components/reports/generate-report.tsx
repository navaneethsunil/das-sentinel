"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { REPORT_TYPE_LABELS } from "@/components/reports/meta";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { ApiError, generateReport } from "@/lib/api/client";
import type { ReportType } from "@/lib/api/types";

const fieldClass =
  "border-input w-full rounded-lg border bg-transparent px-2.5 py-1.5 text-sm outline-none " +
  "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50";

const TYPES: ReportType[] = ["poam", "technical", "executive"];

/** Generate a report snapshotting every canonical finding, then navigate to its
 * builder. `canEdit` (EXPORT_REPORTS) gates the whole surface. */
export function GenerateReport({
  engagementId,
  canEdit,
}: {
  engagementId: string;
  canEdit: boolean;
}) {
  const router = useRouter();
  const [reportType, setReportType] = useState<ReportType>("poam");
  const [title, setTitle] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  if (!canEdit) {
    return (
      <p className="text-sm text-muted-foreground">
        You do not have permission to generate reports.
      </p>
    );
  }

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    const trimmed = title.trim();
    if (!trimmed) {
      setError("Enter a report title.");
      return;
    }
    setSubmitting(true);
    try {
      const report = await generateReport(engagementId, {
        report_type: reportType,
        title: trimmed,
      });
      router.push(`/engagements/${engagementId}/reports/${report.id}`);
    } catch (caught) {
      setSubmitting(false);
      setError(
        caught instanceof ApiError && caught.detail
          ? caught.detail
          : "Could not generate the report — try again.",
      );
    }
  }

  return (
    <form onSubmit={onSubmit} className="flex flex-wrap items-end gap-2" noValidate>
      <div className="space-y-1.5">
        <Label htmlFor="report_type">Type</Label>
        <select
          id="report_type"
          className={fieldClass}
          value={reportType}
          onChange={(e) => setReportType(e.target.value as ReportType)}
        >
          {TYPES.map((t) => (
            <option key={t} value={t}>
              {REPORT_TYPE_LABELS[t]}
            </option>
          ))}
        </select>
      </div>
      <div className="grow space-y-1.5">
        <Label htmlFor="report_title">Title</Label>
        <input
          id="report_title"
          className={fieldClass}
          placeholder="Q3 assessment — POA&M"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />
      </div>
      <Button type="submit" disabled={submitting}>
        {submitting ? "Generating…" : "Generate report"}
      </Button>
      {error && (
        <p role="alert" className="w-full text-sm text-destructive">
          {error}
        </p>
      )}
    </form>
  );
}
