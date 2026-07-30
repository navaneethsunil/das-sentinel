"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  ApiError,
  createUser,
  deactivateUser,
  setUserRole,
} from "@/lib/api/client";
import { USER_ROLE_LABELS, type User, type UserRole } from "@/lib/api/types";

const ROLES: UserRole[] = ["read_only", "reviewer", "tester", "admin"];

const selectClassName =
  "border-input h-8 rounded-lg border bg-transparent px-2.5 text-sm outline-none " +
  "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 " +
  "disabled:cursor-not-allowed disabled:opacity-50";

/** Create / list users and manage their role + active state. Admin-only — the
 * API's MANAGE_USERS guard is the real enforcement; this page just surfaces it.
 * `meId` is the signed-in admin: the API forbids self-demotion / self-deactivation
 * (last-admin lockout), so those controls are disabled on the caller's own row. */
export function UsersManager({ users, meId }: { users: User[]; meId: string | null }) {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [role, setRole] = useState<UserRole>("read_only");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onCreate(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await createUser({ email, display_name: displayName, role, password });
      setEmail("");
      setDisplayName("");
      setRole("read_only");
      setPassword("");
      router.refresh();
      setBusy(false);
    } catch (caught) {
      setBusy(false);
      if (caught instanceof ApiError && caught.status === 409) {
        setError("A user with this email already exists.");
      } else if (caught instanceof ApiError && caught.status === 422) {
        setError(caught.detail ?? "Password must be at least 12 characters.");
      } else if (caught instanceof ApiError && caught.status === 403) {
        setError("Only admins can create users.");
      } else {
        setError("Creating the user failed — try again.");
      }
    }
  }

  async function onRoleChange(user: User, next: UserRole) {
    setError(null);
    setBusy(true);
    try {
      await setUserRole(user.id, next);
      router.refresh();
      setBusy(false);
    } catch {
      setBusy(false);
      setError(`Changing ${user.email}'s role failed — try again.`);
    }
  }

  async function onDeactivate(user: User) {
    setError(null);
    setBusy(true);
    try {
      await deactivateUser(user.id);
      router.refresh();
      setBusy(false);
    } catch {
      setBusy(false);
      setError(`Deactivating ${user.email} failed — try again.`);
    }
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-base">New user</CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={onCreate} className="space-y-3" noValidate>
            <div className="space-y-1.5">
              <Label htmlFor="user_email">Email</Label>
              <Input
                id="user_email"
                type="email"
                required
                placeholder="analyst@example.com"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="user_name">Display name</Label>
              <Input
                id="user_name"
                required
                placeholder="Alex Analyst"
                value={displayName}
                onChange={(e) => setDisplayName(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="user_role">Role</Label>
              <select
                id="user_role"
                className={`${selectClassName} w-full`}
                value={role}
                onChange={(e) => setRole(e.target.value as UserRole)}
              >
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {USER_ROLE_LABELS[r]}
                  </option>
                ))}
              </select>
              <p className="text-xs text-muted-foreground">
                Read only sees findings and reports; Tester runs scans and manages targets;
                Reviewer approves and validates; Admin manages users and everything else.
              </p>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="user_password">Temporary password</Label>
              <Input
                id="user_password"
                type="password"
                required
                autoComplete="new-password"
                placeholder="at least 12 characters"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
            <Button type="submit" size="sm" disabled={busy}>
              Create user
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Users</CardTitle>
        </CardHeader>
        <CardContent>
          <ul className="divide-y text-sm" data-testid="users-list">
            {users.map((user) => {
              const isSelf = user.id === meId;
              return (
                <li
                  key={user.id}
                  className="flex items-center justify-between gap-4 py-3"
                  data-testid="user-row"
                >
                  <div className="min-w-0">
                    <span className="font-medium">{user.display_name}</span>
                    {isSelf && <span className="ml-2 text-xs text-muted-foreground">(you)</span>}
                    {!user.is_active && (
                      <span className="ml-2 text-xs text-destructive">deactivated</span>
                    )}
                    <span className="block truncate text-xs text-muted-foreground">
                      {user.email}
                    </span>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <select
                      aria-label={`Role for ${user.email}`}
                      className={selectClassName}
                      value={user.role}
                      disabled={busy || isSelf || !user.is_active}
                      onChange={(e) => onRoleChange(user, e.target.value as UserRole)}
                    >
                      {ROLES.map((r) => (
                        <option key={r} value={r}>
                          {USER_ROLE_LABELS[r]}
                        </option>
                      ))}
                    </select>
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={busy || isSelf || !user.is_active}
                      aria-label={`Deactivate ${user.email}`}
                      onClick={() => onDeactivate(user)}
                    >
                      Deactivate
                    </Button>
                  </div>
                </li>
              );
            })}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
