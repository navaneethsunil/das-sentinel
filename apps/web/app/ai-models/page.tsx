import { AiModelsManager } from "@/components/ai-models/ai-models-manager";
import { Card, CardContent } from "@/components/ui/card";
import { requireUser, serverGet } from "@/lib/api/server";
import type { AiModel, LlmStatus } from "@/lib/api/types";

// Reflects live config — never prerender or cache.
export const dynamic = "force-dynamic";

export default async function AiModelsPage() {
  const me = await requireUser();
  const models = (await serverGet<AiModel[]>("/llm/models")) ?? [];
  // Only relevant while nothing is registered: the environment-configured
  // provider is what analysis falls back to.
  const fallback = models.length === 0 ? await serverGet<LlmStatus>("/llm/status") : null;

  return (
    <div className="max-w-2xl space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">AI models</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Register a model once — a hosted provider API key, or a local Ollama endpoint — and
          engagements use it for triage, remediation, and log analysis. Keys are encrypted at rest
          and never shown again.
        </p>
      </div>

      <AiModelsManager models={models} canManage={me.role === "admin"} />

      {fallback && (
        <Card>
          <CardContent className="py-4 text-sm text-muted-foreground">
            Until a model is registered, analysis falls back to this deployment&apos;s environment
            configuration: <span className="font-mono">{fallback.provider}</span> ·{" "}
            <span className="font-mono">{fallback.models.default}</span>
            {fallback.endpoint ? (
              <>
                {" · "}
                <span className="font-mono">{fallback.endpoint}</span>
              </>
            ) : null}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
