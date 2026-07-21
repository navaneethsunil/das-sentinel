"use client";

import { useState } from "react";

import { Button } from "@/components/ui/button";
import { getFindingEvidence } from "@/lib/api/client";
import type { EvidenceContent, FindingEvidence } from "@/lib/api/types";

interface Turn {
  role: string;
  content: string;
}

/** Best-effort parse of a probe transcript blob into conversation turns. Returns
 * null when the content is not the expected shape (then we show the raw text). */
function parseTurns(content: string): Turn[] | null {
  try {
    const doc: unknown = JSON.parse(content);
    if (doc && typeof doc === "object" && "transcript" in doc) {
      const raw = (doc as { transcript: unknown }).transcript;
      if (Array.isArray(raw)) {
        return raw
          .filter((t): t is Turn => !!t && typeof t === "object" && "role" in t && "content" in t)
          .map((t) => ({ role: String(t.role), content: String(t.content) }));
      }
    }
  } catch {
    // Not JSON — fall through to raw rendering.
  }
  return null;
}

function prettyJson(content: string): string {
  try {
    return JSON.stringify(JSON.parse(content), null, 2);
  } catch {
    return content;
  }
}

/** Fetches and renders one evidence blob (an LLM probe transcript) on demand.
 * The content comes through the API — the browser never talks to object storage
 * — and the API re-verified the SHA-256 before returning it. */
export function TranscriptViewer({
  engagementId,
  findingId,
  evidence,
}: {
  engagementId: string;
  findingId: string;
  evidence: FindingEvidence;
}) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [content, setContent] = useState<EvidenceContent | null>(null);
  const [showRaw, setShowRaw] = useState(false);

  async function toggle() {
    if (open) {
      setOpen(false);
      return;
    }
    setOpen(true);
    if (content === null) {
      setLoading(true);
      setError(null);
      try {
        setContent(await getFindingEvidence(engagementId, findingId, evidence.evidence_id));
      } catch {
        setError("Could not load this evidence.");
      } finally {
        setLoading(false);
      }
    }
  }

  const turns = content ? parseTurns(content.content) : null;

  return (
    <div className="rounded-md border" data-testid="evidence-item">
      <div className="flex items-center justify-between gap-4 px-3 py-2">
        <div className="min-w-0">
          <p className="truncate text-sm font-medium">{evidence.caption ?? "Evidence"}</p>
          <p className="font-mono text-xs text-muted-foreground">
            {evidence.kind} · {evidence.size_bytes} bytes · sha256:{" "}
            {evidence.content_sha256.slice(0, 16)}…
          </p>
        </div>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => void toggle()}
          data-testid="evidence-toggle"
        >
          {open ? "Hide transcript" : "View transcript"}
        </Button>
      </div>
      {open && (
        <div className="border-t px-3 py-3" data-testid="evidence-content">
          {loading && <p className="text-sm text-muted-foreground">Loading…</p>}
          {error && (
            <p role="alert" className="text-sm text-red-600">
              {error}
            </p>
          )}
          {content && !loading && !error && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-xs text-muted-foreground">
                  Verified via the evidence store (SHA-256 checked on read).
                </p>
                <button
                  type="button"
                  className="text-xs underline underline-offset-4"
                  onClick={() => setShowRaw((v) => !v)}
                >
                  {showRaw ? "Show conversation" : "Show raw JSON"}
                </button>
              </div>
              {!showRaw && turns ? (
                <div className="space-y-2">
                  {turns.map((turn, i) => (
                    <div key={i} className="rounded border px-3 py-2">
                      <p className="mb-1 text-xs font-medium uppercase tracking-wider text-muted-foreground">
                        {turn.role}
                      </p>
                      <p className="whitespace-pre-wrap break-words font-mono text-xs">
                        {turn.content}
                      </p>
                    </div>
                  ))}
                </div>
              ) : (
                <pre className="max-h-96 overflow-auto rounded border bg-muted/50 p-3 font-mono text-xs">
                  {prettyJson(content.content)}
                </pre>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
