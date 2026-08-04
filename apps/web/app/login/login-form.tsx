"use client";

import { useSearchParams } from "next/navigation";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError, login } from "@/lib/api/client";

export function LoginForm() {
  const searchParams = useSearchParams();
  const expired = searchParams.get("expired") === "1";

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      const { user } = await login(email, password);
      // Full navigation so the whole app (user menu included) remounts
      // against the fresh session. A temporary-password account is sent to
      // set a permanent one first.
      window.location.assign(user.must_change_password ? "/set-password" : "/");
    } catch (caught) {
      setSubmitting(false);
      // 401 is a rejected credential; 422 is a malformed one (blank email, no
      // password). Both mean "these credentials are no good" to the user, and
      // both must read the same so neither becomes an enumeration oracle.
      if (caught instanceof ApiError && (caught.status === 401 || caught.status === 422)) {
        setError("Invalid email or password.");
      } else {
        setError("Sign-in failed — the API is unreachable. Try again.");
      }
    }
  }

  return (
    <Card>
      <CardContent>
        {expired && (
          <p
            role="status"
            className="mb-4 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-sm text-amber-200"
          >
            Your session has expired or was revoked. Sign in again.
          </p>
        )}
        <form onSubmit={onSubmit} className="space-y-4" noValidate>
          <div className="space-y-1.5">
            <Label htmlFor="email">Email</Label>
            <Input
              id="email"
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(event) => setEmail(event.target.value)}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              autoComplete="current-password"
              required
              value={password}
              onChange={(event) => setPassword(event.target.value)}
            />
          </div>
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}
          <Button type="submit" className="w-full" disabled={submitting}>
            {submitting ? "Signing in…" : "Sign in"}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
