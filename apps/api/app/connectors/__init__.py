"""LLM/chatbot target connectors (M2-B6).

The scope-validated `SuiteTarget`/`RunnerTarget` implementations the AI/LLM suites
(M2-B4/B5) drive attacks through. HTTP is the only transport for the MVP; the
package boundary keeps future transports (gRPC, SDK-wrapped) behind the same seam.
"""

from app.connectors.llm_target import (
    ConnectorConfigError,
    DnsResolver,
    HttpLLMTargetConnector,
    SecretResolver,
    TargetConnectionConfig,
    TargetConnectorError,
    TargetEgressGuard,
    build_llm_target_connector,
    env_secret_resolver,
    system_dns_resolver,
    validate_connector_config,
)

__all__ = [
    "ConnectorConfigError",
    "DnsResolver",
    "HttpLLMTargetConnector",
    "SecretResolver",
    "TargetConnectionConfig",
    "TargetConnectorError",
    "TargetEgressGuard",
    "build_llm_target_connector",
    "env_secret_resolver",
    "system_dns_resolver",
    "validate_connector_config",
]
