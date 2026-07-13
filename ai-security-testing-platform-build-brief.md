# AI Security Testing Platform - Build Brief (Functioning Application)

> **Purpose of this file:** Hand this to Claude Code or another coding assistant in an empty project folder to begin building the application. It defines what the application is, what it does, what it explicitly does not do, the required safety boundaries, and the suggested build order.

---

## Quick glossary

- **AI** - Artificial Intelligence.
- **LLM** - Large Language Model. The kind of AI that powers chatbots and assistants, such as ChatGPT, Claude, or local models.
- **OWASP** - Open Worldwide Application Security Project. A respected nonprofit that publishes free, widely used security standards.
- **OWASP Top 10 for LLM Applications** - OWASP's list of the most critical security risks in AI/LLM applications. Each risk has a code such as `LLM01`, `LLM02`, and so on.
- **NIST** - National Institute of Standards and Technology. A US government agency that publishes official standards.
- **NIST AI RMF** - NIST's Artificial Intelligence Risk Management Framework.
- **NIST SP 800-53** - NIST's catalog of security and privacy controls.
- **NIST SP 800-115** - NIST's technical guide for information security testing and assessment.
- **CVSS** - Common Vulnerability Scoring System. A standard 0-10 severity scoring system.
- **ROE** - Rules of Engagement. A signed authorization document that defines exactly what a security test is allowed to touch.
- **ATO** - Authority to Operate. A formal approval process for systems that need to operate in regulated environments.
- **POA&M** - Plan of Action and Milestones. A document used to track security weaknesses and remediation plans.
- **SAST** - Static Application Security Testing. Scans source code without running the app.
- **DAST** - Dynamic Application Security Testing. Tests a running application from the outside.
- **RAG** - Retrieval-Augmented Generation. An AI design where the app retrieves information from a knowledge base before answering.

---

## What this application is

An **AI security testing and automated penetration testing platform** for authorized security assessments of web applications, APIs, codebases, and AI/LLM applications.

The application combines:

1. Automated AI/LLM security tests.
2. Automated web/API security scanning.
3. Automated penetration-test workflow support.
4. Human-readable security findings.
5. Federal-style compliance mapping and report generation.

The platform must be designed for **authorized defensive security testing only**. It must require users to define the test scope, confirm authorization, and accept Rules of Engagement before running active tests against live systems.

This is a **functioning application**, not a research prototype. Build it as a real product foundation with a usable UI, persistent data storage, repeatable scan workflows, report generation, and clear safety controls.

---

## What this application explicitly does not do

The application must not be designed as an unrestricted offensive hacking tool.

It must not:

- Attack systems without explicit authorization.
- Attempt stealth, persistence, evasion, credential theft, destructive payloads, or data exfiltration.
- Run denial-of-service tests by default.
- Bypass authentication on systems outside the approved test scope.
- Automatically exploit high-risk findings without a separate approval gate.
- Claim that AI-generated findings are final without evidence and review status.

All active testing must be tied to a saved engagement, approved scope, and ROE acknowledgement.

---

## Core product modules

### 1. Engagement and scope management

Users must be able to create a security testing engagement before any scan runs.

Required fields:

- Engagement name.
- Client or internal system name.
- Authorized target URLs, domains, IP ranges, API base URLs, or repositories.
- Out-of-scope targets.
- Test window.
- Rate limits.
- Authentication method, if applicable.
- ROE acknowledgement.
- Contact person for test coordination.
- Emergency stop contact.

The app must block scans when:

- No engagement exists.
- No scope is defined.
- ROE has not been accepted.
- The target does not match the approved scope.

### 2. Target inventory

The app must maintain a target inventory for each engagement.

Supported target types:

- Web application URL.
- REST API.
- GraphQL API.
- Source code repository.
- AI chatbot endpoint.
- LLM API wrapper.
- AI agent with tools.
- Uploaded source-code archive.

Each target should store:

- Target type.
- Environment label, such as dev, staging, or production.
- Authentication status.
- Last scan time.
- Risk summary.
- Findings count by severity.

---

## Core automated AI/LLM security services

These services are anchored to the **OWASP Top 10 for LLM Applications** and should be implemented as repeatable test suites.

### 3. Prompt injection testing

Test whether an AI/LLM application can be tricked into ignoring instructions, revealing hidden policy, or performing unauthorized actions.

Include:

- Direct prompt injection tests.
- Indirect prompt injection tests through retrieved documents or tool outputs.
- Instruction hierarchy tests.
- Jailbreak-resistance checks.
- Tool-call manipulation attempts in a sandbox.

Output:

- Prompt used.
- Model response.
- Expected behavior.
- Actual behavior.
- Pass/fail result.
- Evidence.
- OWASP LLM mapping.
- Severity recommendation.

### 4. Data leakage testing

Test whether an AI/LLM application reveals sensitive information it should not disclose.

Include:

- System prompt leakage checks.
- Hidden instruction disclosure checks.
- Secret/token exposure checks.
- Training-data memorization style checks, where applicable.
- RAG data boundary checks.
- Cross-tenant data isolation tests.

Output:

- Data leakage category.
- Reproduction steps.
- Evidence excerpt.
- Impact.
- Suggested remediation.
- OWASP LLM mapping.
- NIST control mapping.

### 5. Insecure AI-generated code checks

Integrate a code scanner such as **Semgrep** to identify common security flaws in AI-generated or developer-written code.

Include checks for:

- Injection flaws.
- Hardcoded secrets.
- Insecure deserialization.
- Path traversal.
- Server-side request forgery.
- Cross-site scripting.
- Authentication and authorization mistakes.
- Unsafe cryptography.
- Insecure dependency usage.

Output:

- File path.
- Line number.
- Rule ID.
- Finding title.
- Severity.
- Code snippet.
- Remediation suggestion.

### 6. Unsafe AI agent permission testing

Test whether an AI agent that can use tools stays within allowed permissions.

Use a sandboxed test environment with fake tools first, such as:

- `send_email`, which only writes to a log.
- `query_database`, which only queries seeded test data.
- `create_ticket`, which only creates a local test record.
- `call_webhook`, which only calls a local mock endpoint.

Test for:

- Excessive agency.
- Unauthorized tool use.
- Tool-call parameter manipulation.
- Confused-deputy behavior.
- Unsafe delegation.
- Attempts to access out-of-scope resources.

Output:

- Tool invoked.
- Parameters requested.
- Whether the call was allowed or blocked.
- Policy decision.
- Evidence.
- Severity.
- Recommended permission boundary.

---

## Automated penetration-test helper

This section replaces any assist-only helper. The platform must provide an **automated penetration-test workflow helper** for authorized engagements.

The automation should support the human security team by running safe, repeatable, scoped workflows. It should not silently perform destructive exploitation. High-risk actions require explicit approval and must be logged.

### 7. Automated reconnaissance

Run non-intrusive reconnaissance against in-scope targets.

Include:

- Technology fingerprinting.
- HTTP header analysis.
- TLS configuration checks.
- OpenAPI/Swagger discovery when exposed.
- Sitemap and robots.txt review.
- Public metadata summarization.
- Application route discovery using safe crawling limits.

Do not include:

- Stealth scanning.
- Evasion.
- Credential harvesting.
- Social engineering.
- Intrusive brute force.

Output:

- Attack surface summary.
- Discovered technologies.
- Exposed endpoints.
- Security-relevant headers.
- TLS posture.
- Interesting public files.
- Recommended next scans.

### 8. Automated scanner orchestration

The app should orchestrate approved security scanners and normalize their output.

Recommended integrations:

- OWASP ZAP for DAST.
- Nuclei for template-based checks.
- Semgrep for SAST.
- Dependency scanner such as OSV-Scanner, npm audit, pip-audit, or similar.
- Secret scanner such as Gitleaks or TruffleHog.

Each scanner run must:

- Be tied to an engagement.
- Validate target scope before execution.
- Respect rate limits.
- Store raw output.
- Store normalized findings.
- Record scanner version and configuration.

### 9. Automated scanner-output triage

Use deterministic logic and an LLM to organize scanner results.

The app should:

- Deduplicate findings.
- Group related alerts.
- Identify likely false positives.
- Rank findings by severity and exploitability.
- Explain why a finding matters.
- Recommend validation steps.
- Preserve raw scanner evidence.

The LLM must not invent evidence. Every finding must cite scanner output, test evidence, source-code location, or captured response data.

### 10. Automated remediation guidance

For each finding, generate remediation guidance.

Include:

- Plain-English explanation.
- Technical root cause.
- Suggested fix.
- Secure code example, when applicable.
- Verification steps.
- References to mapped standards.

For code findings, the app may generate patch suggestions, but it should mark them as suggested changes requiring developer review.

### 11. Automated patch-validation workflow

The app should support rescanning after a fix.

Include:

- Link a finding to a remediation attempt.
- Rerun only relevant tests when possible.
- Compare before/after evidence.
- Mark findings as open, mitigated, fixed, accepted risk, or false positive.
- Keep an audit trail.

### 12. Automated findings-report drafting

The app must automatically create report-ready finding writeups.

Each finding should include:

- Title.
- Severity.
- CVSS score.
- Affected asset.
- Description.
- Evidence.
- Impact.
- Reproduction steps, when safe and authorized.
- Remediation.
- Validation status.
- OWASP mapping.
- NIST mapping.
- POA&M fields.

Reports should be editable before export.

---

## Federal-compliance layer

The compliance layer is a core differentiator.

### 13. Standards mapping

Map each finding to:

- OWASP Top 10 for LLM Applications.
- OWASP Web Security Testing Guide, where relevant.
- NIST AI RMF.
- NIST SP 800-53 controls.
- NIST SP 800-115 testing methodology categories.

Mappings can start as a maintained local JSON/YAML knowledge base and later become database-managed.

### 14. CVSS scoring

The application must support severity scoring with CVSS.

Include:

- CVSS vector fields.
- 0-10 numeric score.
- Critical, High, Medium, Low, and Informational bands.
- Manual override with justification.
- Audit history for score changes.

### 15. POA&M report generation

Generate Plan of Action and Milestones reports.

POA&M export should include:

- Weakness ID.
- Weakness description.
- Affected asset.
- Source of discovery.
- Severity.
- CVSS score.
- Control mapping.
- Recommended remediation.
- Responsible owner.
- Planned completion date.
- Current status.
- Milestones.
- Risk acceptance notes, if any.

Supported exports:

- CSV.
- Markdown.
- PDF.
- DOCX, if feasible.

### 16. Executive and technical reports

Generate two report styles:

- Executive summary for leadership.
- Technical report for engineers and security teams.

Executive report should include:

- Overall risk posture.
- Severity breakdown.
- Top risks.
- Business impact.
- Compliance impact.
- Recommended priorities.

Technical report should include:

- Detailed findings.
- Evidence.
- Reproduction notes.
- Affected endpoints/files.
- Remediation guidance.
- Retest status.

---

## LLM layer

The app should support both hosted LLM APIs and local/self-hosted models.

Required design:

- Model provider abstraction.
- Configurable model.
- API key stored in environment variables or a secrets manager.
- Optional local model support through Ollama, MLX, or similar.
- Prompt templates stored in versioned files.
- Token and cost tracking.
- Redaction layer before sending sensitive data to a hosted model.
- Per-engagement setting for whether hosted models are allowed.

The LLM can be used for:

- Test-case generation.
- Result summarization.
- Finding deduplication.
- Remediation drafting.
- Compliance mapping assistance.
- Report generation.

The LLM must not be treated as the sole source of truth. It must operate on evidence from scanners, tests, source code, or captured responses.

---

## Safety and authorization controls

Build these controls into the application from the beginning.

Required controls:

- Engagement-level scope enforcement.
- ROE acknowledgement before active scans.
- Target allowlist.
- Out-of-scope blocklist.
- Rate limiting.
- Scan intensity levels: passive, safe active, authenticated active, high-risk gated.
- High-risk action approval gate.
- Emergency stop button for running scans.
- Full audit log.
- Raw evidence retention.
- User roles.
- Clear labels for automated, AI-generated, validated, and manually overridden findings.

Recommended roles:

- Admin.
- Security tester.
- Reviewer.
- Read-only stakeholder.

High-risk gated actions may include:

- Exploit validation.
- Authenticated destructive checks.
- Password spraying or brute-force style tests.
- Large-scale crawling.
- Payloads that could modify data.

Default behavior must be safe and non-destructive.

---

## Suggested technical architecture

### Frontend

Build a web dashboard with:

- Engagements page.
- Target inventory page.
- Scan launcher.
- Live scan status.
- Findings dashboard.
- Finding detail view.
- Report builder.
- Settings page.

Suggested stack:

- Next.js or React.
- TypeScript.
- Tailwind CSS or a component system.

### Backend

Build an API and worker system with:

- Engagement management.
- Scope validation.
- Scanner orchestration.
- LLM orchestration.
- Finding normalization.
- Report generation.
- Audit logging.

Suggested stack:

- Python FastAPI or Node.js/NestJS.
- Background jobs with Celery, RQ, BullMQ, or similar.
- PostgreSQL for persistent data.
- Redis for job queue/cache, if needed.

### Scanner workers

Scanner workers should run tools in isolated processes or containers.

Responsibilities:

- Execute scanner commands.
- Enforce timeout and rate limits.
- Capture raw output.
- Normalize results.
- Report status back to backend.

### Database

Core tables/entities:

- Users.
- Organizations.
- Engagements.
- Scope items.
- Targets.
- Scans.
- Scanner runs.
- Findings.
- Evidence.
- Compliance mappings.
- CVSS scores.
- Reports.
- Audit events.
- LLM interactions.

---

## Suggested build order

### Stage 1: Application foundation

Build:

- Web UI shell.
- Backend API.
- Database schema.
- Engagement creation.
- Scope management.
- ROE acknowledgement.
- Target inventory.
- Audit logging.

Goal:

- A user can create an authorized engagement and add in-scope targets.

### Stage 2: AI/LLM test harness

Build:

- Prompt-injection test runner.
- Data-leakage test runner.
- Basic LLM target connector.
- Evidence capture.
- Pass/fail results.

Goal:

- A user can run AI security tests against an approved chatbot or LLM endpoint.

### Stage 3: Scanner integrations

Build:

- Semgrep integration.
- OWASP ZAP integration.
- Nuclei integration.
- Dependency scanner integration.
- Normalized findings model.

Goal:

- A user can run approved scanners and see findings in one dashboard.

### Stage 4: Automated pentest workflows

Build:

- Automated reconnaissance.
- Scan plan generation.
- Scanner-output triage.
- Finding deduplication.
- Remediation guidance.
- Patch-validation workflow.

Goal:

- The platform can run a scoped automated assessment workflow from target inventory to draft findings.

### Stage 5: Agent permission testing

Build:

- Sandboxed fake tools.
- Agent policy definition.
- Tool-call monitoring.
- Excessive-agency tests.
- Permission-boundary reports.

Goal:

- The platform can test whether an AI agent respects its allowed tool permissions.

### Stage 6: Compliance and reporting

Build:

- OWASP/NIST mapping database.
- CVSS scoring UI.
- POA&M export.
- Executive report.
- Technical report.
- PDF/CSV/Markdown exports.

Goal:

- A user can generate compliance-ready reports from validated findings.

---

## Minimum viable functioning application

The first complete version should include:

- User can create an engagement.
- User can define target scope.
- User must accept ROE.
- User can add a web app target, API target, code target, or LLM target.
- User can run prompt-injection and data-leakage tests against an LLM target.
- User can run Semgrep against uploaded or local code.
- User can import or run one DAST scanner.
- User can view normalized findings.
- User can generate AI-assisted remediation text.
- User can assign CVSS severity.
- User can export a basic POA&M CSV and Markdown technical report.

---

## Acceptance criteria

The application is ready for initial use when:

- Scans cannot run without an engagement and approved scope.
- Out-of-scope targets are blocked.
- At least one AI/LLM security test suite works end to end.
- At least one code scanner works end to end.
- At least one web/API scanner works end to end.
- Findings are normalized into a shared schema.
- Findings include evidence.
- Findings can be mapped to OWASP and NIST references.
- CVSS scoring is supported.
- POA&M export works.
- Report generation works.
- Audit logs capture who ran what, against which target, and when.
- The UI clearly distinguishes automated findings from human-validated findings.

---

## Important implementation rules for Claude Code

When building from this brief:

1. Start with the application foundation and scope controls before scanner execution.
2. Do not build unrestricted attack functionality.
3. Do not run live scans against public targets unless the user explicitly provides authorization and scope.
4. Prefer safe test targets, local mock apps, intentionally vulnerable labs, or user-owned systems.
5. Keep scanner execution modular so tools can be added or removed.
6. Store raw scanner output and normalized findings separately.
7. Treat LLM output as draft analysis, not verified truth.
8. Make the UI usable for security testers, engineers, and compliance reviewers.
9. Prioritize a working vertical slice over broad but shallow features.
10. Keep all high-risk testing behind explicit approval gates.

---

## Strategic product goal

The finished application should help a security team move from:

1. Approved scope,
2. Automated AI/web/code security testing,
3. Evidence-backed findings,
4. AI-organized triage and remediation,
5. Compliance mapping,
6. POA&M/report export,
7. Retesting and closure.

The key value is not just scanning. The key value is turning authorized security testing evidence into clear, prioritized, compliance-ready action.
