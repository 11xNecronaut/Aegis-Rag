"""Settings and the control model.

Security behaviour is expressed as eight independently switchable controls so that
every result can be attributed to a specific control (ablation), not to a vague "mode".
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

BASE_DIR = Path(__file__).resolve().parent.parent

# Probabilistic: pattern/heuristic based. Can be evaded; effectiveness depends on the attacker.
PROBABILISTIC = frozenset({"input_guard", "retrieval_guard", "prompt_hardening", "output_redaction"})
# Deterministic: enforced by code on trusted data (identity, allowlists). Do not depend on model behaviour.
DETERMINISTIC = frozenset({"tenant_scope", "cache_isolation", "tool_policy", "egress_filter"})
ALL_CONTROLS = PROBABILISTIC | DETERMINISTIC

MODES: dict[str, frozenset[str]] = {
    "baseline": frozenset(),
    "guardrails": PROBABILISTIC,
    "deterministic": DETERMINISTIC,
    "layered": ALL_CONTROLS,
}

DEFAULT_TOKENS = {"alice": "alice-demo-token", "bob": "bob-demo-token"}
TENANTS = {"alice": "tenant-alice", "bob": "tenant-bob"}


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def parse_controls(spec: str) -> frozenset[str]:
    names = frozenset(part.strip() for part in spec.split(",") if part.strip())
    unknown = names - ALL_CONTROLS
    if unknown:
        raise ValueError(f"Unknown controls {sorted(unknown)}; valid: {sorted(ALL_CONTROLS)}")
    return names


def label_for(controls: frozenset[str]) -> str:
    for name, members in MODES.items():
        if members == controls:
            return name
    return "custom(" + ",".join(sorted(controls)) + ")"


def _default_users() -> dict[str, dict[str, str]]:
    return {
        hash_token(DEFAULT_TOKENS[u]): {"user_id": u, "tenant_id": TENANTS[u]} for u in DEFAULT_TOKENS
    }


@dataclass(frozen=True)
class Settings:
    controls: frozenset[str] = ALL_CONTROLS
    env: str = "lab"
    db_path: Path = BASE_DIR / "data" / "aegis.db"
    log_path: Path = BASE_DIR / "data" / "security-events.jsonl"
    log_max_bytes: int = 5_000_000
    log_backups: int = 3
    llm_provider: str = "extractive"  # extractive | sim | ollama | bedrock
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen3:8b"
    bedrock_model_id: str = ""
    bedrock_region: str = "ap-south-1"
    sim_obedience: float = 1.0
    egress_allowlist: frozenset[str] = frozenset()
    tool_allowlist: frozenset[str] = frozenset({"search_documents", "create_ticket", "send_webhook"})
    max_tool_calls: int = 3
    uncontrolled_max_steps: int = 6  # lab-only bound so the vulnerable agent loop cannot spin forever
    max_body_bytes: int = 256 * 1024
    ask_rate_per_min: int = 30
    auth_fail_per_min: int = 10
    max_docs_per_tenant: int = 500
    users: Mapping[str, dict[str, str]] = field(default_factory=_default_users)
    uses_default_tokens: bool = True

    def has(self, control: str) -> bool:
        return control in self.controls

    @property
    def mode_label(self) -> str:
        return label_for(self.controls)


def load_settings(environ: Mapping[str, str] | None = None) -> Settings:
    env = os.environ if environ is None else environ
    if env.get("AEGIS_CONTROLS"):
        controls = parse_controls(env["AEGIS_CONTROLS"])
    else:
        mode = env.get("AEGIS_MODE", "layered").strip().lower()
        if mode not in MODES:
            raise ValueError(f"AEGIS_MODE must be one of {sorted(MODES)}; got {mode!r}")
        controls = MODES[mode]

    provider = env.get("AEGIS_LLM_PROVIDER", "extractive").strip().lower()
    if provider not in {"extractive", "sim", "ollama", "bedrock"}:
        raise ValueError("AEGIS_LLM_PROVIDER must be extractive, sim, ollama or bedrock")

    tokens = {
        "alice": env.get("ALICE_DEMO_TOKEN", DEFAULT_TOKENS["alice"]),
        "bob": env.get("BOB_DEMO_TOKEN", DEFAULT_TOKENS["bob"]),
    }
    uses_defaults = tokens == DEFAULT_TOKENS
    app_env = env.get("AEGIS_ENV", "lab").strip().lower()
    if app_env == "prod" and uses_defaults:
        raise ValueError("Refusing to start with default demo tokens when AEGIS_ENV=prod")
    for who, tok in tokens.items():
        if app_env == "prod" and len(tok) < 24:
            raise ValueError(f"Token for {who} is too short for AEGIS_ENV=prod (min 24 chars)")

    allow = frozenset(h.strip().lower() for h in env.get("AEGIS_EGRESS_ALLOWLIST", "").split(",") if h.strip())
    base = BASE_DIR / "data"
    return Settings(
        controls=controls,
        env=app_env,
        db_path=Path(env.get("AEGIS_DB_PATH", str(base / "aegis.db"))),
        log_path=Path(env.get("AEGIS_LOG_PATH", str(base / "security-events.jsonl"))),
        llm_provider=provider,
        ollama_url=env.get("OLLAMA_URL", "http://localhost:11434").rstrip("/"),
        ollama_model=env.get("OLLAMA_MODEL", "qwen3:8b"),
        bedrock_model_id=env.get("AEGIS_BEDROCK_MODEL_ID", ""),
        bedrock_region=env.get("AWS_REGION", "ap-south-1"),
        sim_obedience=float(env.get("AEGIS_SIM_OBEDIENCE", "1.0")),
        egress_allowlist=allow,
        users={hash_token(tokens[u]): {"user_id": u, "tenant_id": TENANTS[u]} for u in tokens},
        uses_default_tokens=uses_defaults,
    )
