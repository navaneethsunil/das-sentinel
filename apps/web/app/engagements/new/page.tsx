import { EngagementForm } from "@/components/engagements/engagement-form";

export const metadata = { title: "New engagement — DAS Sentinel" };

export default function NewEngagementPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">New engagement</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Created as a draft — scope, ROE acceptance, and activation come next.
        </p>
      </div>
      <EngagementForm />
    </div>
  );
}
