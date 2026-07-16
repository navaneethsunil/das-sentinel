"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { addScopeItem, ApiError, removeScopeItem } from "@/lib/api/client";
import type { ScopeItem, ScopeKind, ScopeMatcherType } from "@/lib/api/types";

export const MATCHER_LABELS: Record<ScopeMatcherType, string> = {
  url: "URL",
  domain: "Domain",
  ip_cidr: "IP / CIDR",
  api_base: "API base",
  repo: "Repository",
};

const MATCHER_PLACEHOLDERS: Record<ScopeMatcherType, string> = {
  url: "https://app.example.com/portal",
  domain: "*.example.com",
  ip_cidr: "10.0.0.0/24",
  api_base: "https://api.example.com/v1",
  repo: "git@github.com:org/repo.git",
};

const selectClassName =
  "border-input h-8 w-full rounded-lg border bg-transparent px-2.5 text-sm outline-none " +
  "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50";

function ScopeList({
  title,
  kind,
  items,
  empty,
  busy,
  onRemove,
}: {
  title: string;
  kind: ScopeKind;
  items: ScopeItem[];
  empty: string;
  busy: boolean;
  onRemove: (item: ScopeItem) => void;
}) {
  return (
    <div data-testid={`scope-${kind}-list`}>
      <h3 className="text-sm font-medium">{title}</h3>
      {items.length === 0 ? (
        <p className="mt-1 text-sm text-muted-foreground">{empty}</p>
      ) : (
        <ul className="mt-1 divide-y text-sm">
          {items.map((item) => (
            <li key={item.id} className="flex items-center justify-between gap-4 py-1.5">
              <div className="min-w-0">
                <span className="font-mono break-all">{item.value}</span>
                <span className="ml-2 text-xs text-muted-foreground">
                  {MATCHER_LABELS[item.matcher_type]}
                  {item.notes ? ` — ${item.notes}` : ""}
                </span>
              </div>
              <Button
                size="sm"
                variant="ghost"
                disabled={busy}
                aria-label={`Remove ${item.value}`}
                onClick={() => onRemove(item)}
              >
                Remove
              </Button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Allow/deny scope lists + add form. The server validates and normalizes
 * every value per matcher type (422 on malformed) and deny always wins at
 * enforcement time — this editor only maintains the lists. Editing scope
 * after a ROE acceptance makes the ROE hash drift, forcing re-acceptance. */
export function ScopeEditor({ engagementId, items }: { engagementId: string; items: ScopeItem[] }) {
  const router = useRouter();
  const [kind, setKind] = useState<ScopeKind>("allow");
  const [matcherType, setMatcherType] = useState<ScopeMatcherType>("url");
  const [value, setValue] = useState("");
  const [notes, setNotes] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onAdd(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await addScopeItem(engagementId, {
        kind,
        matcher_type: matcherType,
        value,
        notes: notes || null,
      });
      // Keep kind/matcher for rapid entry of similar items; clear the rest.
      setValue("");
      setNotes("");
      router.refresh();
      setBusy(false);
    } catch (caught) {
      setBusy(false);
      if (caught instanceof ApiError && caught.status === 403) {
        setError("Your role can view scope but not change it.");
      } else if (caught instanceof ApiError && caught.status === 422) {
        setError(`The value is not a valid ${MATCHER_LABELS[matcherType]} matcher.`);
      } else {
        setError("Adding the scope item failed — try again.");
      }
    }
  }

  async function onRemove(item: ScopeItem) {
    setError(null);
    setBusy(true);
    try {
      await removeScopeItem(engagementId, item.id);
      router.refresh();
      setBusy(false);
    } catch (caught) {
      setBusy(false);
      setError(
        caught instanceof ApiError && caught.status === 403
          ? "Your role can view scope but not change it."
          : "Removing the scope item failed — try again.",
      );
    }
  }

  return (
    <div className="space-y-4">
      <ScopeList
        title="In scope (allow)"
        kind="allow"
        items={items.filter((item) => item.kind === "allow")}
        empty="No allow rules — nothing is in scope yet."
        busy={busy}
        onRemove={onRemove}
      />
      <ScopeList
        title="Out of scope (deny — always wins)"
        kind="deny"
        items={items.filter((item) => item.kind === "deny")}
        empty="No deny rules."
        busy={busy}
        onRemove={onRemove}
      />
      <form onSubmit={onAdd} className="space-y-3 border-t pt-4" noValidate>
        <div className="grid grid-cols-2 gap-4">
          <div className="space-y-1.5">
            <Label htmlFor="scope_kind">List</Label>
            <select
              id="scope_kind"
              className={selectClassName}
              value={kind}
              onChange={(e) => setKind(e.target.value as ScopeKind)}
            >
              <option value="allow">Allow (in scope)</option>
              <option value="deny">Deny (out of scope)</option>
            </select>
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="scope_matcher_type">Matcher type</Label>
            <select
              id="scope_matcher_type"
              className={selectClassName}
              value={matcherType}
              onChange={(e) => setMatcherType(e.target.value as ScopeMatcherType)}
            >
              {Object.entries(MATCHER_LABELS).map(([matcher, label]) => (
                <option key={matcher} value={matcher}>
                  {label}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="scope_value">Value</Label>
          <Input
            id="scope_value"
            required
            placeholder={MATCHER_PLACEHOLDERS[matcherType]}
            value={value}
            onChange={(e) => setValue(e.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="scope_notes">Notes (optional)</Label>
          <Input id="scope_notes" value={notes} onChange={(e) => setNotes(e.target.value)} />
        </div>
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
        <Button type="submit" size="sm" disabled={busy}>
          Add scope item
        </Button>
      </form>
    </div>
  );
}
