<h1 align="center">AegisRAG v0.2 </h1>

**A Security Evaluation Lab for Multi-Tenant RAG Systems and Tool-Using AI Agents**

AegisRAG is an experimental security evaluation lab designed to test, harden, and measure the security of multi-tenant Retrieval-Augmented Generation (RAG) systems and tool-using AI agents.

It is not a production product. It is a deliberately vulnerable, measurable environment where security controls can be independently enabled, attacked, evaluated, and explained.

The project is built around one central question:

> When a model can be persuaded to do almost anything, which security controls still hold?

## What's New in v0.2

Version 0.2 replaces the original ChatGPT-built MVP with a more complete and testable security evaluation framework.

It addresses every bug identified during the v0.1 review, with each fix mapped to a regression test in [`docs/CHANGES.md`](docs/CHANGES.md).

Major additions include:

- **Real agent execution loop:** Implements tool-using agent behaviour rather than relying solely on simulated request handling.
- **Hybrid retrieval:** Combines retrieval strategies for document discovery.
- **Attack catalogue:** Includes 17 documented attacks, statistical evaluation, and confidence intervals.
- **Guard-evasion fuzzer:** Generates attack variations to evaluate the effectiveness of heuristic security controls.
- **Sigma detections:** Includes Sigma rules mapped to MITRE ATLAS and tested against generated telemetry.
- **AWS infrastructure foundation:** Introduces Terraform configurations for core cloud security components.
- **Expanded regression testing:** Adds coverage for previously identified vulnerabilities and security invariants.

## Project Status

The following table distinguishes implemented functionality from work that has not yet been validated against live infrastructure.

| Component | Status |
|---|---|
| Application, security controls, attack runner, and detections | Implemented and tested locally |
| Automated test suite | 110+ tests |
| Sabotage mutation testing | 7/7 deliberate mutations detected |
| Evaluation results | Reproducible runs using a simulated model |
| Terraform infrastructure | Parses successfully; Checkov: 82 passed, 0 failed, 9 skipped with documented reasons |
| Ollama integration | Implemented, not tested against a live service |
| AWS Bedrock integration | Implemented, not tested against a live service |
| Cloud deployment | Not implemented |
| API Gateway, Lambda, Cognito/JWT integration | Not implemented |
| Real-LLM security evaluation | Pending |

**Important:** The Terraform infrastructure has not been applied. No AWS account was available during development.

---

## Quick Start

### 1. Installation

Clone the repository and install the project dependencies:

```bash
git clone <repository-url>
cd AegisRAG

make install
```

Alternatively, install manually:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Run the Test Suite

```bash
make test
```

This executes the unit, regression, and security invariant tests.

### 3. Run the Security Evaluation

```bash
make eval
```

Runs the complete attack evaluation matrix and generates:

```text
results/REPORT.md
```

The default evaluation takes approximately 15 seconds.

### 4. Start the Application

Seed the database and start the API:

```bash
make seed && make run
```

The application will be available at:

```text
http://127.0.0.1:8000
```

The default configuration uses the simulated LLM provider.

## Testing the API

AegisRAG includes demonstration tokens for local testing. These tokens are strictly for the lab environment and are rejected when `AEGIS_ENV=prod`.

### Health Check

```bash
curl -s http://127.0.0.1:8000/health
```

### Test a Normal RAG Query

Ask a question about documents belonging to Alice's tenant:

```bash
curl -s http://127.0.0.1:8000/ask \
  -H "Authorization: Bearer alice-demo-token" \
  -H "Content-Type: application/json" \
  -d '{"question": "How many days of paid time off do employees get?"}'
```

### Test Cross-Tenant Isolation

Attempt to retrieve confidential information belonging to Bob Corp:

```bash
curl -s http://127.0.0.1:8000/ask \
  -H "Authorization: Bearer alice-demo-token" \
  -H "Content-Type: application/json" \
  -d '{"question": "What is the launch project code for Bob Corp?"}'
```

With `tenant_scope` enabled, Alice cannot retrieve documents belonging to Bob's tenant.

### Inspect Pending Tool Approvals

```bash
curl -s http://127.0.0.1:8000/approvals \
  -H "Authorization: Bearer alice-demo-token"
```

---

## Security Control Architecture

AegisRAG implements eight independently configurable security controls.

They are divided into two categories based on their underlying enforcement mechanisms.

### 1. Deterministic Controls

These controls enforce security boundaries using trusted application data and explicit policies.

| Control | Purpose |
|---|---|
| `tenant_scope` | Enforces tenant isolation through SQL query predicates. The API fails closed when a tenant ID is unavailable. |
| `cache_isolation` | Prevents cross-tenant cache contamination by including tenant identity in cache keys. |
| `tool_policy` | Enforces tool allowlists, strict argument schemas, rejection of model-supplied `tenant_id` values, human approval for state-changing operations, and tool-call limits. |
| `egress_filter` | Removes non-allowlisted URLs and images from outputs and blocks webhook requests to non-allowlisted hosts. |

### 2. Probabilistic Controls

These controls use detection heuristics and input/output analysis. They reduce attack exposure but cannot guarantee prevention.

| Control | Purpose |
|---|---|
| `input_guard` | Detects prompt injection using normalized, weighted, and multilingual detection heuristics. |
| `retrieval_guard` | Applies injection detection to retrieved documents and tool-returned content. Suspicious chunks are quarantined rather than causing the entire request to fail. |
| `prompt_hardening` | Uses per-request nonce delimiters and delimiter neutralization to strengthen instruction boundaries. |
| `output_redaction` | Performs checksum-validated PII and secret redaction, alongside verbatim system-prompt filtering. |

### Control Configuration

AegisRAG supports four predefined security configurations:

| Mode | Enabled Controls |
|---|---|
| `baseline` | No preventive controls |
| `guardrails` | Probabilistic controls |
| `deterministic` | Deterministic controls |
| `layered` | All eight controls |

Individual controls can also be selected through environment configuration:

```bash
AEGIS_CONTROLS=tool_policy,tenant_scope
```

**Detection remains active even when preventive controls are disabled.**

This monitor-mode behaviour allows the evaluation framework to record potential attacks and their effects without necessarily blocking them.

---

## Security Evaluation Results

The evaluation currently contains 17 attacks.

An attack is considered successful when the attacker's objective is achieved, such as unauthorized information disclosure or execution of a forbidden action.

HTTP status codes alone are not used to determine attack success.

The default simulated model is configured to obey every recognized injected instruction, representing a worst-case compromised-model scenario.

### Attack Success by Security Configuration

| Configuration | Successful Attacks | Success Rate |
|---|---:|---:|
| Baseline | 17/17 | 100% |
| Guardrails only | 5/17 | 29% |
| Deterministic only | 7/17 | 41% |
| Layered | 1/17 | 6% |

These results demonstrate the importance of combining deterministic enforcement with probabilistic detection.

### Key Findings

**1. Deterministic controls provide distinct security boundaries.**

Each deterministic control addresses a different class of failure.

- Removing `tool_policy` re-enables agent-related attacks, including confused-deputy searches, webhook exfiltration, and forged tickets.
- Removing `tenant_scope` or `cache_isolation` reintroduces cross-tenant information disclosure.

No single control replaces the others.

**2. Keyword-based detection is insufficient.**

Across 63 attack variants against a simulated model that obeys recognized injected instructions:

- The original v0.1 guard missed 83% of variants.
- The v0.2 guard missed 27%.

Even with the improvements, the guard cannot reliably distinguish malicious instructions such as "create a ticket" from legitimate user requests.

This demonstrates why heuristic detection should not be treated as a substitute for deterministic authorization.

**3. Some attacks bypass every implemented control.**

Attack D07 requests the system prompt in reverse order.

It bypasses:

- Injection detection.
- Canary checks.
- Verbatim system-prompt filtering.
- Deterministic security controls.

It also generates no alert.

D07 is intentionally retained in the attack catalogue because it demonstrates an important architectural weakness: filtering cannot reliably protect secrets that should never have been placed in the system prompt.

**4. Outcome-based telemetry detects attacks that technique-based rules miss.**

Some attacks evade conventional guard mechanisms through paraphrasing, plain imperative instructions, and cache-related information disclosure.

Detection becomes more reliable when monitoring the resulting security effects:

- Unauthorized data access.
- Cross-tenant retrieval.
- Unexpected outbound requests.
- Canary exposure.
- PII disclosure.

**5. Security controls introduce usability trade-offs.**

In the evaluated dataset, the layered configuration:

- Blocks 1 out of 20 harmless questions.
- Correctly answers 93% of factual questions.

This highlights the need to evaluate both security effectiveness and legitimate application functionality.

### Important: Understanding the Evaluation Methodology

The default model used in the evaluation is a **simulated LLM**, implemented in:

```text
app/llm.py
```

It is designed to obey recognized instructions in its input with a configurable probability.

The simulator allows the agent loop and security controls to be evaluated deterministically without requiring a GPU, external API access, or paid inference services.

Consequently, the current evaluation results measure how the implemented security controls behave when confronted with a compromised or instruction-following model.

They do **not** establish the security or robustness of any real LLM.

In particular, prompt hardening demonstrates no measurable effect against this simulator because the simulation does not interpret the delimiters.

To evaluate actual model behaviour, use the Ollama or AWS Bedrock provider and generate a separate evaluation report.

The complete attack results, confidence intervals, and leave-one-out ablation analysis are documented in:

[`results/REPORT.md`](results/REPORT.md)

---

## Evaluating with a Real LLM

AegisRAG supports external model providers through configurable LLM integrations.

### Ollama

Start an Ollama instance and configure the provider:

```bash
export AEGIS_LLM_PROVIDER=ollama
export OLLAMA_MODEL=qwen3:8b

make run
```

### AWS Bedrock

Install the AWS SDK:

```bash
pip install boto3
```

Configure the provider:

```bash
export AEGIS_LLM_PROVIDER=bedrock
export AEGIS_BEDROCK_MODEL_ID=<bedrock-model-id>
export AWS_REGION=<aws-region>

make run
```

Both provider implementations translate transport failures into clean HTTP 502 responses without exposing internal stack traces.

**Note:** These integrations are implemented but have not yet been validated against live inference services.

---

## Sigma Detection Engineering

AegisRAG includes a collection of Sigma detection rules designed to identify suspicious activity within the evaluation environment.

Current detection coverage includes:

- 13 single-event detection rules.
- 3 correlation rules.
- MITRE ATLAS mapping.
- A subset Sigma rule evaluator.
- Detection testing against generated telemetry.

The objective is to connect offensive testing with defensive monitoring.

Instead of evaluating only whether an attack succeeds, the framework also examines whether its behaviour generates detectable security events.

---

## Infrastructure and Cloud Security

The `infra/` directory contains a Terraform-based AWS infrastructure foundation.

It currently covers:

- AWS KMS.
- S3 storage.
- AWS Secrets Manager.
- IAM configurations.
- CloudWatch logging.
- AWS budget monitoring.

Static validation was performed using Checkov:

| Result | Count |
|---|---:|
| Passed | 82 |
| Failed | 0 |
| Skipped | 9 |

The skipped checks have documented reasons.

**Infrastructure deployment has not been performed.**

The current Terraform configuration is a foundation, not a complete cloud deployment. It does not provision the application runtime, API Gateway, vector database, or Cognito authentication.

---

## Repository Structure

```text
AegisRAG/
│
├── app/
│   ├── Engine and agent execution loop
│   ├── Security controls
│   ├── Injection detection
│   ├── Output redaction
│   ├── Retrieval pipeline
│   ├── Tool execution and policy enforcement
│   └── API implementation
│
├── attacks/
│   ├── Attack corpus
│   ├── 17-attack catalogue
│   ├── Evaluation runner
│   ├── Guard-evasion fuzzer
│   └── Statistical analysis
│
├── detections/
│   ├── Sigma detection rules
│   ├── Correlation rules
│   └── Subset Sigma evaluator
│
├── infra/
│   └── Terraform AWS foundation
│
├── docs/
│   ├── Threat model
│   └── Change log and regression mapping
│
├── tests/
│   └── Unit, regression, and invariant tests
│
└── results/
    └── REPORT.md
```

---

## Known Limitations and Future Work

AegisRAG is an evolving research and engineering project. Several areas remain incomplete.

### 1. Real-Model Security Evaluation

The existing evaluation harness is ready for real-model testing.

Further validation requires access to a local inference service or AWS Bedrock, followed by repeatable attack evaluations.

### 2. Complete Cloud Deployment

The Terraform infrastructure currently provides a security-oriented foundation.

The following components remain unimplemented:

- AWS Lambda application runtime.
- API Gateway integration.
- Vector database deployment.
- Cognito authentication.
- Complete cloud application deployment.

Before deployment, Bedrock model availability should be verified in the selected region and budget alerts configured.

### 3. Production-Grade Identity Management

Authentication currently relies on two static demonstration tokens.

Production deployment requires proper per-user identity management and JWT validation against an established identity provider.

### 4. Semantic Embeddings

The current hashing-based embedder is deterministic and dependency-free, but it does not provide semantic understanding.

A production-oriented retrieval pipeline requires a proper embedding model and semantic vector search.

### 5. Transformed Secret Disclosure

D07 demonstrates that secrets can be disclosed through transformations that evade simple string-matching filters.

Future work should investigate semantic similarity detection, transformed-output analysis, and stronger architectural secret isolation.

The preferred mitigation remains keeping sensitive information out of system prompts wherever possible.

### 6. Additional AI and Supply Chain Risks

Further testing is needed for:

- OWASP LLM03: Supply Chain Vulnerabilities.
- Embedding inversion attacks.
- Model and dependency integrity.
- Cost-based denial-of-wallet attacks.
- More sophisticated resource exhaustion scenarios.

### 7. Independent Security Validation

The same author developed both the attack catalogue and the defensive controls.

This introduces the possibility of blind spots in the evaluation methodology.

Independent validation using tools such as Garak, PyRIT, or Promptfoo would help identify additional attack paths and provide a more objective assessment.

---

## Project Philosophy

AegisRAG is built around a simple security principle:

**An AI system should never be trusted to enforce the boundaries that its own behaviour can violate.**

Prompt engineering, injection detection, and output filtering are useful defensive layers, but they are not substitutes for authorization, tenant isolation, strict tool policies, and controlled data access.

The goal is not to prove that an AI system cannot be manipulated.

The goal is to identify what happens when it is manipulated, determine which controls still work, measure the failures, and build systems that remain secure even when the model does not behave as expected.

**AegisRAG v0.2 | Security Evaluation Lab for Multi-Tenant RAG and AI Agents**
