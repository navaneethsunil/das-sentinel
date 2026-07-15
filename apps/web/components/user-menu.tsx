"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { getMe, logout, logoutAll } from "@/lib/api/client";
import type { User } from "@/lib/api/types";

const ROLE_LABELS: Record<User["role"], string> = {
  admin: "Admin",
  tester: "Tester",
  reviewer: "Reviewer",
  read_only: "Read-only",
};

/** Sidebar session block: who is signed in, sign out, sign out everywhere.
 * Client-side on purpose — the session cookie is HttpOnly, so signed-in state
 * only exists as the API's answer to /auth/me. */
export function UserMenu() {
  const [user, setUser] = useState<User | null | "loading">("loading");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getMe()
      .then(setUser)
      .catch(() => setUser(null));
  }, []);

  if (user === "loading") {
    return <div className="border-t px-5 py-4" data-testid="user-menu-loading" />;
  }

  if (user === null) {
    return (
      <div className="border-t px-5 py-4">
        <Link href="/login" className="text-sm font-medium underline underline-offset-4">
          Sign in
        </Link>
      </div>
    );
  }

  async function onLogout() {
    setBusy(true);
    try {
      await logout();
      window.location.assign("/login");
    } catch {
      setBusy(false);
    }
  }

  async function onLogoutAll() {
    if (!window.confirm("Sign out of every session on every device?")) {
      return;
    }
    setBusy(true);
    try {
      await logoutAll();
      window.location.assign("/login");
    } catch {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-3 border-t px-5 py-4" data-testid="user-menu">
      <div className="min-w-0">
        <p className="truncate text-sm font-medium">{user.display_name}</p>
        <p className="truncate text-xs text-muted-foreground">{user.email}</p>
        <Badge variant="outline" className="mt-1.5 text-[10px]">
          {ROLE_LABELS[user.role]}
        </Badge>
      </div>
      <div className="flex flex-col gap-1.5">
        <Button size="sm" variant="outline" disabled={busy} onClick={onLogout}>
          Sign out
        </Button>
        <Button size="sm" variant="ghost" disabled={busy} onClick={onLogoutAll}>
          Sign out everywhere
        </Button>
      </div>
    </div>
  );
}
