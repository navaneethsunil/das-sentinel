"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError, createAiModel, deleteAiModel, setDefaultAiModel } from "@/lib/api/client";
import type { AiModel } from "@/lib/api/types";

const selectClassName =
  "border-input h-8 w-full rounded-lg border bg-transparent px-2.5 text-sm outline-none " +
  "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50";

const MODEL_PLACEHOLDER = {
  anthropic: "claude-opus-4-8",
  ollama: "llama3.1:8b",
} as const;

/** Register a model once (Anthropic API key, or a local Ollama endpoint), then
 * engagements pick from this list. The API key is write-only: it is sent on
 * create, encrypted server-side, and never returned. Admin-only — a 403 is
 * surfaced as such rather than as a generic failure. */
export function AiModelsManager({ models, canManage }: { models: AiModel[]; canManage: boolean }) {
  const router = useRouter();
  const [provider, setProvider] = useState<AiModel["provider"]>("anthropic");
  const [name, setName] = useState("");
  const [modelId, setModelId] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [baseUrl, setBaseUrl] = useState("http://localhost:11434");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onCreate(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await createAiModel({
        name,
        provider,
        model_id: modelId,
        api_key: provider === "anthropic" ? apiKey : null,
        base_url: provider === "ollama" ? baseUrl : null,
        make_default: models.length === 0,
      });
      setName("");
      setModelId("");
      setApiKey("");
      router.refresh();
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 400) {
        // The provider itself rejected the key/model — show exactly why.
        setError(caught.detail ?? "The provider rejected the key or the model name.");
      } else if (caught instanceof ApiError && caught.status === 409) {
        setError("A model with this name is already registered.");
      } else if (caught instanceof ApiError && caught.status === 403) {
        setError("Only an admin can register AI models.");
      } else {
        setError("Registering the model failed — try again.");
      }
    } finally {
      setBusy(false);
    }
  }

  async function onAction(action: () => Promise<unknown>, failure: string) {
    setError(null);
    setBusy(true);
    try {
      await action();
      router.refresh();
    } catch (caught) {
      if (caught instanceof ApiError && caught.status === 409) {
        setError(caught.detail ?? "That change conflicts with the current state.");
      } else if (caught instanceof ApiError && caught.status === 403) {
        setError("Only an admin can change AI models.");
      } else {
        setError(failure);
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-6">
      {/* Registering a model is MANAGE_AI_MODELS (admin) — mirror the API guard
          rather than offering a form that 403s on submit. */}
      {canManage && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Add a model</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={onCreate} className="space-y-3">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label htmlFor="ai_provider">Provider</Label>
                  <select
                    id="ai_provider"
                    className={selectClassName}
                    value={provider}
                    onChange={(e) => setProvider(e.target.value as AiModel["provider"])}
                  >
                    <option value="anthropic">Anthropic Claude (hosted)</option>
                    <option value="ollama">Ollama (local)</option>
                  </select>
                </div>
                <div className="space-y-1.5">
                  <Label htmlFor="ai_name">Name</Label>
                  <Input
                    id="ai_name"
                    required
                    placeholder="triage-model"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                </div>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="ai_model_id">Model</Label>
                <Input
                  id="ai_model_id"
                  required
                  placeholder={MODEL_PLACEHOLDER[provider]}
                  value={modelId}
                  onChange={(e) => setModelId(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  {provider === "anthropic"
                    ? "The model id as the provider names it, e.g. claude-opus-4-8 or claude-sonnet-5."
                    : "The model as it is pulled in Ollama (ollama list), e.g. llama3.1:8b."}
                </p>
              </div>
              {provider === "anthropic" ? (
                <div className="space-y-1.5">
                  <Label htmlFor="ai_api_key">API key</Label>
                  <Input
                    id="ai_api_key"
                    type="password"
                    required
                    autoComplete="new-password"
                    placeholder="paste the provider API key — encrypted and never shown again"
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">
                    Stored encrypted at rest and write-only. Hosted models send prompts off-box:
                    redaction runs before egress and each engagement must set “hosted LLMs allowed”.
                  </p>
                </div>
              ) : (
                <div className="space-y-1.5">
                  <Label htmlFor="ai_base_url">Ollama endpoint</Label>
                  <Input
                    id="ai_base_url"
                    required
                    placeholder="http://localhost:11434"
                    value={baseUrl}
                    onChange={(e) => setBaseUrl(e.target.value)}
                  />
                  <p className="text-xs text-muted-foreground">
                    Local inference — prompts stay on-box. The model must already be pulled (see
                    ollama list). For Ollama on this machine keep localhost — it resolves to the
                    Docker host automatically.
                  </p>
                </div>
              )}
              {error && (
                <p role="alert" className="text-sm text-destructive">
                  {error}
                </p>
              )}
              <Button type="submit" size="sm" disabled={busy}>
                Add model
              </Button>
              <p className="text-xs text-muted-foreground">
                The key and endpoint are checked against the provider before the model is saved.
              </p>
            </form>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Registered models</CardTitle>
        </CardHeader>
        <CardContent>
          {models.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No models registered yet.{" "}
              {canManage
                ? "Add one above — engagements then pick from this list, and the default is used when an engagement does not pick one."
                : "An admin registers models under System → AI models."}
            </p>
          ) : (
            <ul className="divide-y text-sm" data-testid="ai-models-list">
              {models.map((model) => (
                <li
                  key={model.id}
                  className="flex items-center justify-between gap-4 py-3"
                  data-testid="ai-model-row"
                >
                  <div className="min-w-0">
                    <span className="font-medium">{model.name}</span>
                    {model.is_default && (
                      <Badge className="ml-2 bg-emerald-600 text-white hover:bg-emerald-600">
                        default
                      </Badge>
                    )}
                    {model.hosted ? (
                      <Badge variant="outline" className="ml-2 border-amber-500/50 text-amber-600">
                        hosted · off-box
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="ml-2">
                        local · on-box
                      </Badge>
                    )}
                    <span className="mt-1 block font-mono text-xs text-muted-foreground">
                      {model.provider} · {model.model_id}
                      {model.base_url ? ` · ${model.base_url}` : ""}
                    </span>
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    {canManage && !model.is_default && (
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={busy}
                        onClick={() =>
                          onAction(
                            () => setDefaultAiModel(model.id),
                            "Setting the default failed — try again.",
                          )
                        }
                      >
                        Make default
                      </Button>
                    )}
                    {canManage && (
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={busy}
                        onClick={() =>
                          onAction(
                            () => deleteAiModel(model.id),
                            "Removing the model failed — try again.",
                          )
                        }
                      >
                        Remove
                      </Button>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          )}
          {!canManage && error && (
            <p role="alert" className="mt-3 text-sm text-destructive">
              {error}
            </p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
