import { redirect } from "next/navigation";

import { ProfileForm } from "@/components/profile-form";
import { serverMe } from "@/lib/api/server";

export const dynamic = "force-dynamic";
export const metadata = { title: "Account settings — DAS Sentinel" };

export default async function ProfilePage() {
  const me = await serverMe();
  if (!me) {
    redirect("/login");
  }
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold tracking-tight">Account settings</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Update your profile and password. Changes are attributed and audited.
        </p>
      </div>
      <ProfileForm user={me} />
    </div>
  );
}
