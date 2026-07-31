"use client";

import Link from "next/link";
import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { logout, logoutAll } from "@/lib/api/client";
import type { User } from "@/lib/api/types";
import { USER_ROLE_LABELS } from "@/lib/api/types";

/** Two-letter initials from a display name: first letters of the first two
 * words, else the first two characters. */
function initials(name: string): string {
  const words = name.trim().split(/\s+/).filter(Boolean);
  if (words.length >= 2) {
    return (words[0][0] + words[1][0]).toUpperCase();
  }
  return (name.trim().slice(0, 2) || "?").toUpperCase();
}

/** Top-right account menu: an initials avatar that opens a panel to reach
 * account settings and sign out. `user` is server-fetched in the layout, so
 * there is no loading flash. Rendered only when signed in. */
export function AccountMenu({ user }: { user: User }) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);

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
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-label="Account menu"
        className="flex size-9 items-center justify-center rounded-full bg-sidebar-primary text-sm font-semibold text-sidebar-primary-foreground shadow-sm outline-none focus-visible:ring-3 focus-visible:ring-ring/50"
      >
        {initials(user.display_name)}
      </button>
      {open && (
        <>
          {/* Click-away backdrop — native <details> would not close on outside click. */}
          <button
            type="button"
            aria-hidden
            tabIndex={-1}
            className="fixed inset-0 z-40 cursor-default"
            onClick={() => setOpen(false)}
          />
          <div
            role="menu"
            data-testid="account-menu"
            className="absolute right-0 z-50 mt-2 w-64 space-y-3 rounded-xl border bg-popover p-4 shadow-lg"
          >
            <div className="min-w-0">
              <p className="truncate text-sm font-medium">{user.display_name}</p>
              <p className="truncate text-xs text-muted-foreground">{user.email}</p>
              <Badge variant="outline" className="mt-1.5 text-[10px]">
                {USER_ROLE_LABELS[user.role]}
              </Badge>
            </div>
            <div className="flex flex-col gap-1.5">
              <Link
                href="/profile"
                role="menuitem"
                onClick={() => setOpen(false)}
                className={buttonVariants({ variant: "outline", size: "sm" })}
              >
                Account settings
              </Link>
              <Button size="sm" variant="ghost" disabled={busy} onClick={onLogout}>
                Sign out
              </Button>
              <Button size="sm" variant="ghost" disabled={busy} onClick={onLogoutAll}>
                Sign out everywhere
              </Button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
