import { UsersManager } from "@/components/users/users-manager";
import { serverGet, serverMe } from "@/lib/api/server";
import type { User } from "@/lib/api/types";

export const dynamic = "force-dynamic";

export default async function UsersPage() {
  const [users, me] = await Promise.all([serverGet<User[]>("/users"), serverMe()]);

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
