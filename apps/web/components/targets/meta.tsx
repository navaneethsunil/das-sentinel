import { Badge } from "@/components/ui/badge";
import type { AuthStatus, EnvironmentLabel, TargetType } from "@/lib/api/types";

export const TARGET_TYPE_LABELS: Record<TargetType, string> = {
  web_app: "Web application",
  rest_api: "REST API",
  graphql_api: "GraphQL API",
  source_repo: "Source repository",
  source_archive: "Source archive",
  ai_chatbot: "AI chatbot",
  llm_api_wrapper: "LLM API wrapper",
  ai_agent: "AI agent",
};

export const ENVIRONMENT_LABELS: Record<EnvironmentLabel, string> = {
  dev: "Dev",
  staging: "Staging",
  production: "Production",
};

export const AUTH_STATUS_LABELS: Record<AuthStatus, string> = {
  none: "No auth",
  configured: "Configured",
  verified: "Verified",
};

// Mirrors apps/api schemas/targets.py _URL_TYPES — which types carry a URL
// vs a repo vs a free-form value. The API validates (422); this only picks
// the placeholder/hint.
const URL_TYPES: ReadonlySet<TargetType> = new Set([
  "web_app",
  "rest_api",
  "graphql_api",
  "ai_chatbot",
  "llm_api_wrapper",
  "ai_agent",
]);

export function primaryValueHint(targetType: TargetType): {
  label: string;
  placeholder: string;
} {
  if (URL_TYPES.has(targetType)) {
    return { label: "URL", placeholder: "https://portal.example.com" };
  }
  if (targetType === "source_repo") {
    return { label: "Repository", placeholder: "git@github.com:org/repo.git" };
  }
  return { label: "Archive reference", placeholder: "uploads/portal-src.zip" };
}

const ENVIRONMENT_STYLES: Record<EnvironmentLabel, string> = {
  dev: "",
  staging: "bg-sky-600 text-white hover:bg-sky-600",
  production: "bg-red-600 text-white hover:bg-red-600",
};

export function EnvironmentBadge({ environment }: { environment: EnvironmentLabel }) {
  return (
    <Badge
      variant={environment === "dev" ? "outline" : "default"}
      className={ENVIRONMENT_STYLES[environment]}
    >
      {ENVIRONMENT_LABELS[environment]}
    </Badge>
  );
}
