import { CredentialsManager } from "@/components/credentials/credentials-manager";
import { serverGet } from "@/lib/api/server";
import type { Credential } from "@/lib/api/types";

export const dynamic = "force-dynamic";

export default async function CredentialsPage() {
  const credentials = (await serverGet<Credential[]>("/credentials")) ?? [];

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
