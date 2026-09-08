import { AccessDenied } from "@/components/access-denied";
import { CredentialsManager } from "@/components/credentials/credentials-manager";
import { FORBIDDEN, serverGetOrForbidden } from "@/lib/api/server";
import type { Credential } from "@/lib/api/types";

export const dynamic = "force-dynamic";

export default async function CredentialsPage() {
  const result = await serverGetOrForbidden<Credential[]>("/credentials");
  if (result === FORBIDDEN) {
    return (
      <AccessDenied
        title="Credentials"
        message="The credential vault is available to Admin and Tester roles only — the roles that
          configure engagements and targets. Ask an administrator if you need access."
      />
    );
  }
  const credentials = result ?? [];

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Credentials</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Store a secret once, encrypted at rest, then reference it as{" "}
          <span className="font-mono">cred:&lt;id&gt;</span> from a target&apos;s auth config —
          instead of pasting the secret as plaintext. The secret is never shown again.
        </p>
      </div>
      <CredentialsManager credentials={credentials} />
    </div>
  );
}
