import { Suspense } from "react";

import { LoginForm } from "./login-form";

export const metadata = { title: "Sign in — DAS Sentinel" };

export default function LoginPage() {
  return (
    <div className="mx-auto flex min-h-[80vh] w-full max-w-sm flex-col justify-center">
      <div className="mb-6 flex flex-col items-center text-center">
        <span className="flex size-11 items-center justify-center rounded-xl bg-brand text-lg font-semibold text-brand-foreground shadow-sm">
          S
        </span>
        <h1 className="mt-4 text-xl font-semibold tracking-tight">Sign in to DAS Sentinel</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Authorized security testing — every action is attributed and audited.
        </p>
      </div>
      {/* Suspense: the form reads useSearchParams (expired-session banner). */}
      <Suspense>
        <LoginForm />
      </Suspense>
      <p className="mt-6 text-center text-xs text-muted-foreground/70">
        DAS Sentinel · authorized defensive assessments only
      </p>
    </div>
  );
}
