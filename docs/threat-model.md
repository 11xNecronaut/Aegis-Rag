# Threat model

Mappings use OWASP Top 10 for LLM Applications (2025) and MITRE ATLAS technique IDs checked against the ATLAS site in November 2026. OWASP titles for LLM03, LLM04, LLM06, LLM08 and LLM10 are from memory: confirm at genai.owasp.org before quoting them.

## System and trust boundaries

User (authenticated, one tenant) → API → input guard → retrieval (tenant-scoped) → prompt → model → tool proposals → policy → tools → output filters → user.

Untrusted by construction: user text, **every retrieved chunk**, **every tool result**, and the model's own output. Trusted: authenticated identity, configuration, the system prompt's existence (not its secrecy).

## Assets

Tenant documents and any PII in them; the system prompt; credentials (secrets manager); the action surface (tickets, webhooks); cost; the audit log.

## Attackers

1. Authenticated user probing for another tenant's data or for the system prompt.
2. Anyone who can place a document in a corpus (shared drive, email ingest, web page): indirect injection and RAG poisoning.
3. Unauthenticated client: credential guessing and log or cost flooding.
4. Compromised model: treated as worst case by the evaluation.

## Threats, controls and status

| Threat | OWASP | ATLAS | Controls | Attack IDs | Status |
|---|---|---|---|---|---|
| Direct prompt injection | LLM01 | AML.T0051.000 | `input_guard` (heuristic) | D01-D04 | Partly: paraphrase evades the guard |
| Indirect injection and RAG poisoning | LLM01, LLM04 | AML.T0051.001, AML.T0070 | `retrieval_guard`, ingest flagging (detect only), `tool_policy` | I01-I07 | Covered for known shapes; agent impact bounded deterministically |
| Obfuscated payloads | LLM01 | AML.T0068 | Normalisation, base64 decoding | D02, D03, I02b | Covered for tested encodings |
| Cross-tenant retrieval, cache and tool-argument leaks | LLM02, LLM08 | AML.T0057 | `tenant_scope`, `cache_isolation`, strict tool schemas | D05, I02, I08 | Covered deterministically |
| Excessive agency and confused deputy | LLM06 | AML.T0053 | `tool_policy`: allowlist, schemas, approval, call cap | I02, I05, I06 | Covered deterministically |
| Exfiltration via tools or rendered links | LLM06, LLM05 | AML.T0086 | `tool_policy` egress allowlist, `egress_filter` | D06, I03, I04, I05, I07 | Covered deterministically |
| System prompt leakage | LLM07 | AML.T0056 | Verbatim filter, canary, no secrets in prompt | D01-D04, D07, I01 | **Open**: transformed output (D07) evades everything and detection |
| Sensitive data in authorised answers | LLM02 | AML.T0057 | `output_redaction` (validated detectors) | I09 | Covered for well-formed identifiers only |
| Credential guessing, log and body flooding | LLM10 | n/a | Lockout, body cap, rotating capped logs, quotas | tests | Covered at single-process scale |
| Supply chain (models, libraries, containers) | LLM03 | n/a | CI secret scan, IaC scan; no dependency pinning or SBOM yet | none | **Open** |
| Embedding inversion, vector leakage | LLM08 | n/a | none | none | **Open** |
| Cost-based denial of wallet | LLM10 | AML.T0029 (verify) | Per-user rate limit, token caps are not enforced on real models | none | Partly |

## Assumptions that would invalidate this model

The model never holds credentials or network access itself; all side effects pass `policy.authorize`. Tenant identity comes only from authentication, never from model output or request body. Logs are append-only and shipped off-host in a real deployment.
