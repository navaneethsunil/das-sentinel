import { Suspense } from "react";

import { LoginForm } from "./login-form";

export const metadata = { title: "Sign in — DAS Sentinel" };

export default function LoginPage() {
  return (
    <div className="mx-auto flex min-h-[70vh] max-w-sm flex-col justify-center">
      {/* Suspense: the form reads useSearchParams (expired-session banner). */}
      <Suspense>
        <LoginForm />
      </Suspense>
    </div>
  );
}
