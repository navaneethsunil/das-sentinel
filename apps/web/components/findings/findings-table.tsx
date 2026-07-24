import Link from "next/link";

import { OwaspTag, ProvenanceBadge, SeverityBadge, StatusBadge } from "@/components/findings/meta";
import type { Finding } from "@/lib/api/types";

/** Presentational findings list — severity-first (the API orders it). Each row
 * links to the finding detail. Reused by the engagement detail card (a preview)
 * and the full findings page. */
export function FindingsTable({
  engagementId,
  findings,
}: {
  engagementId: string;
  findings: Finding[];
}) {
  return (
    <table className="w-full text-sm" data-testid="findings-table">
      <thead>
        <tr className="border-b text-left text-xs uppercase tracking-wider text-muted-foreground">
          <th className="py-2 pr-4 font-medium">Severity</th>
          <th className="py-2 pr-4 font-medium">Finding</th>
          <th className="py-2 pr-4 font-medium">Source</th>
          <th className="py-2 pr-4 font-medium">OWASP</th>
          <th className="py-2 pr-4 font-medium">Provenance</th>
          <th className="py-2 font-medium">Status</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((finding) => (
          <tr
            key={finding.id}
            className="border-b align-top last:border-0 hover:bg-muted/50"
            data-testid="finding-row"
          >
            <td className="py-2.5 pr-4">
              <SeverityBadge severity={finding.severity} />
            </td>
            <td className="py-2.5 pr-4">
              <Link
                href={`/engagements/${engagementId}/findings/${finding.id}`}
                className="font-medium underline-offset-4 hover:underline"
              >
                {finding.title}
              </Link>
              {finding.technique && (
                <span className="block text-xs text-muted-foreground">{finding.technique}</span>
              )}
            </td>
            <td className="py-2.5 pr-4 font-mono text-xs text-muted-foreground">
              {finding.source ?? "—"}
            </td>
            <td className="py-2.5 pr-4">
              <OwaspTag owasp={finding.owasp} />
            </td>
            <td className="py-2.5 pr-4">
              <ProvenanceBadge provenance={finding.provenance} />
            </td>
            <td className="py-2.5">
              <StatusBadge status={finding.status} />
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
