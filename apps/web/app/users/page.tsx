import { AccessDenied } from "@/components/access-denied";
import { UsersManager } from "@/components/users/users-manager";
import { FORBIDDEN, serverGetOrForbidden, serverMe } from "@/lib/api/server";
import type { User } from "@/lib/api/types";

export const dynamic = "force-dynamic";

export default async function UsersPage() {
  const [users, me] = await Promise.all([serverGetOrForbidden<User[]>("/users"), serverMe()]);
  if (users === FORBIDDEN) {
    return (
      <AccessDenied
        title="Users"
        message="User administration — creating accounts and assigning roles — is available to the
          Admin role only. Ask an administrator to make the change for you."
      />
    );
  }

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Users</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Create accounts and assign roles. Changing a role or deactivating a user signs them out
          everywhere so the change takes effect immediately.
        </p>
      </div>
      <UsersManager users={users ?? []} meId={me?.id ?? null} />
    </div>
  );
}
