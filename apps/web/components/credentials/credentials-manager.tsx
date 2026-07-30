"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError, createCredential, deleteCredential } from "@/lib/api/client";
import type { Credential } from "@/lib/api/types";

/** Create / list / delete managed credentials. The secret is write-only: it is
 * sent once on create and never returned — the list shows only the name and the
 * `cred:<id>` reference to paste into a target's auth config. */
export function CredentialsManager({ credentials }: { credentials: Credential[] }) {
  const router = useRouter();
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [secret, setSecret] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);

  async function onCreate(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await createCredential({ name, description: description || null, secret });
      setName("");
      setDescription("");
      setSecret("");
      router.refresh();
      setBusy(false);
    } catch (caught) {
      setBusy(false);
      if (caught instanceof ApiError && caught.status === 409) {
        setError("A credential with this name already exists.");
      } else if (caught instanceof ApiError && caught.status === 403) {
        setError("Your role cannot manage credentials.");
      } else {
        setError("Creating the credential failed — try again.");
      }
    }
  }

  async function onDelete(credential: Credential) {
    setError(null);
    setBusy(true);
    try {
      await deleteCredential(credential.id);
      router.refresh();
      setBusy(false);
    } catch {
      setBusy(false);
      setError("Deleting the credential failed — try again.");
    }
  }

  async function onCopy(reference: string) {
    try {
      await navigator.clipboard.writeText(reference);
      setCopied(reference);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      // Clipboard blocked — the reference is visible for manual copy anyway.
    }
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">New credential</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={onCreate} className="space-y-3" noValidate>
            <div className="space-y-1.5">
              <Label htmlFor="cred_name">Name</Label>
              <Input
                id="cred_name"
                required
                placeholder="prod-api-key"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="cred_description">Description (optional)</Label>
              <Input
                id="cred_description"
                placeholder="Bearer token for the prod chatbot"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="cred_secret">Secret</Label>
              <Input
                id="cred_secret"
                type="password"
                required
                autoComplete="new-password"
                placeholder="paste the secret value — it is encrypted and never shown again"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
              />
              <p className="text-xs text-muted-foreground">
                Stored encrypted at rest. It is write-only — no screen or API ever displays it
                again.
              </p>
            </div>
            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
            <Button type="submit" size="sm" disabled={busy}>
              Create credential
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Credentials</CardTitle>
        </CardHeader>
        <CardContent>
          {credentials.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No credentials yet. Create one above, then reference it from a target.
            </p>
          ) : (
            <ul className="divide-y text-sm" data-testid="credentials-list">
              {credentials.map((credential) => (
                <li
                  key={credential.id}
                  className="flex items-center justify-between gap-4 py-3"
                  data-testid="credential-row"
                >
                  <div className="min-w-0">
                    <span className="font-medium">{credential.name}</span>
                    {credential.description && (
                      <span className="ml-2 text-xs text-muted-foreground">
                        {credential.description}
                      </span>
                    )}
                    <button
                      type="button"
                      onClick={() => onCopy(credential.reference)}
                      title="Copy reference"
                      className="mt-1 block font-mono text-xs text-muted-foreground underline-offset-4 hover:underline"
                    >
                      {copied === credential.reference ? "copied!" : credential.reference}
                    </button>
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={busy}
                    aria-label={`Delete ${credential.name}`}
                    onClick={() => onDelete(credential)}
                  >
                    Delete
                  </Button>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
