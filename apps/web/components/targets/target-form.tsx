"use client";

import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  AUTH_STATUS_LABELS,
  ENVIRONMENT_LABELS,
  primaryValueHint,
  TARGET_TYPE_LABELS,
} from "@/components/targets/meta";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ApiError, createTarget, updateTarget } from "@/lib/api/client";
import {
  type AuthStatus,
  type EnvironmentLabel,
  LLM_TARGET_TYPES,
  type Target,
  type TargetType,
} from "@/lib/api/types";

const selectClassName =
  "border-input h-8 w-full rounded-lg border bg-transparent px-2.5 text-sm outline-none " +
  "focus-visible:border-ring focus-visible:ring-3 focus-visible:ring-ring/50 " +
  "disabled:cursor-not-allowed disabled:opacity-50";

/** Create (no `target`) or edit (prefilled). target_type is immutable after
 * create — it fixes how primary_value is validated and matched — so the type
 * select is disabled on edit. auth_config carries credential REFERENCES only
 * (vault paths, secret names); the API rejects anything that looks like a
 * stored secret (TR-23). */
export function TargetForm({ engagementId, target }: { engagementId: string; target?: Target }) {
  const router = useRouter();
  const [name, setName] = useState(target?.name ?? "");
  const [targetType, setTargetType] = useState<TargetType>(target?.target_type ?? "web_app");
  const [environment, setEnvironment] = useState<EnvironmentLabel>(target?.environment ?? "dev");
  const [primaryValue, setPrimaryValue] = useState(target?.primary_value ?? "");
  const [authStatus, setAuthStatus] = useState<AuthStatus>(target?.auth_status ?? "none");
  const [authConfig, setAuthConfig] = useState(
    target?.auth_config ? JSON.stringify(target.auth_config, null, 2) : "",
  );
  const [connectorConfig, setConnectorConfig] = useState(
    target?.connector_config ? JSON.stringify(target.connector_config, null, 2) : "",
  );
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const hint = primaryValueHint(targetType);
  const isLlmTarget = LLM_TARGET_TYPES.includes(targetType);

  function parseJsonObject(raw: string): Record<string, unknown> | null {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error("not an object");
    }
    return parsed as Record<string, unknown>;
  }

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    let parsedAuthConfig: Record<string, unknown> | null = null;
    if (authConfig.trim()) {
      try {
        parsedAuthConfig = parseJsonObject(authConfig);
      } catch {
        setError("Auth config must be a JSON object (or empty).");
        return;
      }
    }

    let parsedConnectorConfig: Record<string, unknown> | null = null;
    if (isLlmTarget && connectorConfig.trim()) {
      try {
        parsedConnectorConfig = parseJsonObject(connectorConfig);
      } catch {
        setError("Connector config must be a JSON object (or empty).");
        return;
      }
    }

    setSubmitting(true);
    const fields = {
      name,
      environment,
      primary_value: primaryValue,
      auth_status: authStatus,
      auth_config: parsedAuthConfig,
      connector_config: parsedConnectorConfig,
    };
    try {
      if (target) {
        await updateTarget(engagementId, target.id, fields);
      } else {
        await createTarget(engagementId, { ...fields, target_type: targetType });
      }
      router.push(`/engagements/${engagementId}`);
      router.refresh();
    } catch (caught) {
      setSubmitting(false);
      if (caught instanceof ApiError && caught.status === 403) {
        setError("Your role can view targets but not change them.");
      } else if (caught instanceof ApiError && caught.status === 422) {
        setError(
          caught.detail ??
            `Some fields are invalid — the ${hint.label.toLowerCase()} must be well-formed for ` +
              "this target type, auth-config keys must be credential references " +
              "(e.g. password_ref, api_key_name) never secret values, and the connector config " +
              "must use known transport keys.",
        );
      } else {
        setError("Saving failed — try again.");
      }
    }
  }

  return (
    <form onSubmit={onSubmit} className="max-w-xl space-y-4" noValidate>
      <div className="space-y-1.5">
        <Label htmlFor="target_name">Name</Label>
        <Input id="target_name" required value={name} onChange={(e) => setName(e.target.value)} />
      </div>
      <div className="grid grid-cols-2 gap-4">
        <div className="space-y-1.5">
          <Label htmlFor="target_type">Type</Label>
          <select
            id="target_type"
            className={selectClassName}
            value={targetType}
            disabled={target !== undefined}
            onChange={(e) => setTargetType(e.target.value as TargetType)}
          >
            {Object.entries(TARGET_TYPE_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
          {target && (
            <p className="text-xs text-muted-foreground">
              The type is fixed after creation — it decides how the target is validated and matched
              against scope.
            </p>
          )}
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="target_environment">Environment</Label>
          <select
            id="target_environment"
            className={selectClassName}
            value={environment}
            onChange={(e) => setEnvironment(e.target.value as EnvironmentLabel)}
          >
            {Object.entries(ENVIRONMENT_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </div>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="target_primary_value">{hint.label}</Label>
        <Input
          id="target_primary_value"
          required
          placeholder={hint.placeholder}
          value={primaryValue}
          onChange={(e) => setPrimaryValue(e.target.value)}
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="target_auth_status">Auth status</Label>
        <select
          id="target_auth_status"
          className={selectClassName}
          value={authStatus}
          onChange={(e) => setAuthStatus(e.target.value as AuthStatus)}
        >
          {Object.entries(AUTH_STATUS_LABELS).map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="target_auth_config">Auth config (credential references only, JSON)</Label>
        <textarea
          id="target_auth_config"
          rows={4}
          className={
            "border-input w-full rounded-lg border bg-transparent px-2.5 py-1.5 font-mono " +
            "text-xs outline-none focus-visible:border-ring focus-visible:ring-3 " +
            "focus-visible:ring-ring/50"
          }
          placeholder={'{"username_ref": "vault://acme/portal-user"}'}
          value={authConfig}
          onChange={(e) => setAuthConfig(e.target.value)}
        />
        <p className="text-xs text-muted-foreground">
          References to secrets (vault paths, secret names) — never the secrets themselves.
        </p>
      </div>
      {isLlmTarget && (
        <div className="space-y-1.5">
          <Label htmlFor="target_connector_config">Connector config (transport shape, JSON)</Label>
          <textarea
            id="target_connector_config"
            rows={6}
            className={
              "border-input w-full rounded-lg border bg-transparent px-2.5 py-1.5 font-mono " +
              "text-xs outline-none focus-visible:border-ring focus-visible:ring-3 " +
              "focus-visible:ring-ring/50"
            }
            placeholder={
              '{\n  "mode": "chat_messages",\n  "response_pointer": "/choices/0/message/content",\n' +
              '  "auth_ref_key": "api_key_ref"\n}'
            }
            value={connectorConfig}
            onChange={(e) => setConnectorConfig(e.target.value)}
          />
          <p className="text-xs text-muted-foreground">
            How the suite talks to this LLM: request method, JSON pointers for the messages and
            response, and which auth-config key holds the credential reference. Leave empty for
            OpenAI-style chat completions. No secrets — only the transport shape.
          </p>
        </div>
      )}
      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
      <Button type="submit" disabled={submitting}>
        {submitting ? "Saving…" : target ? "Save changes" : "Add target"}
      </Button>
    </form>
  );
}
