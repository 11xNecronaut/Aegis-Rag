# What changed from v0.1, and how each fix is proven

Every defect found in the review of the original MVP, the fix, and the test that now guards it.
Items marked (new) were found while building v0.2.

| # | v0.1 defect (reproduced) | v0.2 fix | Test |
|---|---|---|---|
| 1 | Demo attack #1 returned 400 from the injection filter, not tenant isolation (fixture text collided with a guard rule), so the demo proved the wrong thing | Success is judged by goal-based oracles; tenant isolation is tested with only `tenant_scope` enabled | `test_tenant_scope_alone_stops_direct_cross_tenant_question` |
| 2 | README curl example was a shell syntax error (apostrophe in single-quoted JSON) | Examples avoid the problem; a test parses every README curl | `test_readme_shell_examples_parse` |
| 3 | One poisoned chunk made the whole question fail with 400 | Chunk is quarantined, answer continues from clean chunks | `test_poisoned_chunk_is_quarantined_not_fatal` |
| 4 | Ollama down produced a bare 500 | `ModelError` becomes a 502 with a request id and no trace | `test_ollama_provider_connection_failure_is_wrapped`, `test_guard_block_and_model_down_error_shapes` |
| 5 | Static, forgeable `[END DOCUMENT]` delimiters; titles unsanitised | Per-request nonce delimiters, delimiter neutralisation, sanitised titles | `test_hardened_prompt_prevents_delimiter_forgery` |
| 6 | Unauthenticated requests grew the log without limit (2,000 bad tokens = 500 KB) | Failure rate limit with lockout; one burst event; size-capped rotating log | `test_auth_failure_flood_is_rate_limited_and_log_is_bounded` |
| 7 | A 3 MB tool payload wrote 2.9 MB into the security log | Body cap (counts chunked bodies), field limits, telemetry stores lengths and digests only | `test_oversized_bodies_are_rejected_including_chunked`, `test_telemetry_never_contains_raw_titles_prompts_or_bodies` |
| 8 | Titles with PII were logged and returned in cleartext | Hashed in logs, redacted in `sources` | `test_pii_redaction_applies_to_answers_and_source_titles` |
| 9 | `sources` repeated a title once per chunk | De-duplicated | `test_sources_are_deduplicated` |
| 10 | `pii_sanitizer_applied=True` was hardcoded | Events report what was actually found | `test_pii_redaction_applies_to_answers_and_source_titles` |
| 11 | `unknown_tool` branch was unreachable dead code | Removed; denial reason is `tool_not_allowlisted` | `test_unknown_tool_reason_is_allowlist_not_a_dead_branch` |
| 12 | `search_documents` "tool" was a stub; the tool endpoint was called by the user, so the model never chose tools and the exfiltration threat was not modelled | A real agent loop: the model proposes calls, policy decides, tools run | `test_confused_deputy_*`, `test_egress_denied_*`, `test_state_change_requires_human_approval_flow` |
| 13 | Control helpers defined twice (config.py and security.py) | One `Controls` model | `test_all_four_named_modes_exist_and_are_partitioned` |
| 14 | `tenant_scope=None` meant "all tenants" (fail-open) | Tenant API raises without a tenant; the cross-tenant read has an `_unsafe` name | `test_fail_closed_tenant_api` |
| 15 | `run_local.sh` wiped all data on every start | Idempotent seed; destructive reset needs `--reset` | `test_seed_is_idempotent_and_reset_is_explicit` |
| 16 | SQLite connections were never closed explicitly | Context manager closes every connection | `test_every_sqlite_connection_is_closed` |
| 17 | 13 of 14 rewordings bypassed the guard | Normalisation (invisible chars, homoglyphs, spacing, base64), weighted rules, multilingual rules; evasion is now measured | `test_guard_blocks_known_and_obfuscated_attacks`, `test_fuzzer_v2_improves_on_v01_without_claiming_perfection` |
| 18 | Redaction missed Aadhaar, PAN, cards, tokens, secrets, non-Indian phones | Checksum-validated detectors (Verhoeff, Luhn), PAN structure, token shapes, entropy-gated secrets | `tests/test_redact.py` |
| 19 (new) | Plural mismatch in retrieval: "password" did not match "passwords" | Light stemming | `test_plural_stemming_regression` |
| 20 (new) | Chunked request bodies returned 400 instead of 413 (FastAPI swallowed the limit exception) | Response override when the cap trips | `test_oversized_bodies_are_rejected_including_chunked` |
| 21 (new) | System-prompt leak oracle only looked for the canary, so a full prompt leak read as "safe" | Oracle matches distinctive prompt content, forward or reversed | `test_oracles_use_goal_not_status_code` |
| 22 (new) | Protocol-relative image URLs (`//evil.example/x`) were not covered by URL stripping | Image handling resolves hosts, not schemes | `test_image_exfiltration_shapes_are_all_removed` |

## What v0.1 left out and v0.2 adds

Agent loop with model-proposed tools; cache and tool-argument cross-tenant paths (a harder baseline than "filter deleted"); hybrid BM25 plus hashed-vector retrieval; 17-attack catalogue with goal oracles, Wilson confidence intervals, leave-one-out ablation and benign-utility measurement; guard-evasion fuzzer comparing v0.1 and v0.2; 16 Sigma rules (3 correlation) tagged with verified MITRE ATLAS and OWASP LLM IDs, evaluated against real telemetry, convertible to Elastic Lucene queries; a Terraform AWS foundation; CI definition.

## How the test suite itself was checked

Seven deliberate sabotages (policy always allows, tenant filter removed, guard threshold unreachable, cache ignores tenant, egress filter disabled, Luhn check removed, retrieval guard fails open) were applied one at a time. The first run caught 6 of 7. The survivor exposed a real gap (protocol-relative image URLs), a test was added, and all 7 are now caught.
