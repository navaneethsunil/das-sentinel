import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getHealth, getReadiness } from "@/lib/api/client";
import type { CheckState } from "@/lib/api/types";

// Live status must never be prerendered or cached.
export const dynamic = "force-dynamic";

type Probe = { name: string; state: CheckState | "unreachable"; detail?: string };

async function probeApi(): Promise<Probe[]> {
  const probes: Probe[] = [];
  try {
    await getHealth();
    probes.push({ name: "API (liveness)", state: "ok" });
  } catch {
    // Fail visible: the page renders the outage instead of erroring (detail stays server-side).
    return [{ name: "API (liveness)", state: "unreachable" }];
  }
  try {
    const readiness = await getReadiness();
    probes.push({ name: "Database", state: readiness.checks.database });
    probes.push({ name: "Valkey", state: readiness.checks.valkey });
  } catch {
    probes.push({ name: "API (readiness)", state: "unreachable" });
  }
  return probes;
}

function StateBadge({ state }: { state: Probe["state"] }) {
  if (state === "ok") {
    return <Badge className="bg-emerald-600 text-white hover:bg-emerald-600">ok</Badge>;
  }
  return <Badge variant="destructive">{state}</Badge>;
}

export default async function HealthPage() {
  const probes = await probeApi();
  const allOk = probes.every((probe) => probe.state === "ok");

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">System health</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Live view of the API and its backing services. Refresh to re-check.
        </p>
      </div>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-base">Services</CardTitle>
          <StateBadge state={allOk ? "ok" : "unavailable"} />
        </CardHeader>
        <CardContent>
          <ul className="divide-y">
            {probes.map((probe) => (
              <li key={probe.name} className="flex items-center justify-between py-2.5 text-sm">
                <span>{probe.name}</span>
                <StateBadge state={probe.state} />
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
    </div>
  );
}
