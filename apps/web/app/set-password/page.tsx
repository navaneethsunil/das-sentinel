"use client";

import { ShieldCheck } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError, changeMyPassword } from "@/lib/api/client";

// First login with a temporary password: set a permanent one before entering
// the app. The session is already authenticated, so no current password is
// asked for here (the temp password was just proven at login).
export default function SetPasswordPage() {
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    if (password.length < 12) {
      setError("Password must be at least 12 characters.");
      return;
    }
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    setSubmitting(true);
    try {
      await changeMyPassword(null, password);
      window.location.assign("/");
    } catch (caught) {
      setSubmitting(false);
      if (caught instanceof ApiError && caught.status === 422) {
        setError(caught.detail ?? "Choose a different password.");
      } else {
        setError("Setting the password failed — try again.");
      }
    }
  }

  return (
    <div className="mx-auto flex min-h-[80vh] w-full max-w-sm flex-col justify-center">
      <div className="mb-6 flex flex-col items-center text-center">
        <span className="flex size-11 items-center justify-center rounded-xl bg-brand text-brand-foreground shadow-sm">
          <ShieldCheck className="size-6" aria-hidden />
        </span>
        <h1 className="mt-4 text-xl font-semibold tracking-tight">Set your password</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          You signed in with a temporary password. Choose a permanent one to continue.
        </p>
      </div>
      <Card>
        <CardContent>
          <form onSubmit={onSubmit} className="space-y-4" noValidate>
            <div className="space-y-1.5">
              <Label htmlFor="new_password">New password</Label>
              <Input
                id="new_password"
                type="password"
                autoComplete="new-password"
                required
                placeholder="at least 12 characters"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="confirm_password">Confirm password</Label>
              <Input
                id="confirm_password"
                type="password"
                autoComplete="new-password"
                required
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
              />
            </div>
            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
            <Button type="submit" className="w-full" disabled={submitting}>
              {submitting ? "Saving…" : "Set password"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
