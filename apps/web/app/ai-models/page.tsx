import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { getLlmStatus } from "@/lib/api/client";
import type { LlmStatus } from "@/lib/api/types";

// Reflects live config — never prerender or cache.
export const dynamic = "force-dynamic";

const PROVIDER_LABELS: Record<string, string> = {
  anthropic: "Anthropic Claude",
  ollama: "Ollama (local)",
  vllm: "vLLM (local, GPU)",
};

function Row({ name, value }: { name: string; value: string }) {
  return (
    <li className="flex items-center justify-between gap-4 py-2.5 text-sm">
      <span className="text-muted-foreground">{name}</span>
      <span className="font-mono text-[13px]">{value}</span>
    </li>
  );
}

export default async function AiModelsPage() {
  let status: LlmStatus | null = null;
  try {
    status = await getLlmStatus();
  } catch {
    // Fail visible below rather than erroring the whole page.
  }

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">AI models</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          The language model the platform is configured to use right now, across triage,
          remediation, and log analysis.
        </p>
      </div>

      {status === null ? (
        <Card>
          <CardContent className="py-6 text-sm text-muted-foreground">
            The active-model status is unavailable (the API could not be reached).
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardHeader className="flex flex-row items-center justify-between">
            <CardTitle className="text-base">
              {PROVIDER_LABELS[status.provider] ?? status.provider}
            </CardTitle>
            {status.hosted ? (
              <Badge variant="outline" className="border-amber-500/50 text-amber-600">
                hosted · off-box
              </Badge>
            ) : (
              <Badge className="bg-emerald-600 text-white hover:bg-emerald-600">local · on-box</Badge>
            )}
          </CardHeader>
          <CardContent>
            <ul className="divide-y">
              <Row name="Provider" value={status.provider} />
              <Row name="Endpoint" value={status.endpoint ?? "—"} />
              <Row name="Default model" value={status.models.default} />
              <Row name="Triage model" value={status.models.triage} />
              <Row name="Classifier model" value={status.models.classifier} />
            </ul>
            <p className="mt-4 text-xs text-muted-foreground">
              {status.hosted
                ? "Hosted models send prompts off-box. Redaction runs before egress and each engagement must set hosted_models_allowed."
                : "Local inference — prompts stay on-box; no data leaves the deployment."}
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
