"""Runtime configuration (env vars / backend/.env). Thresholds and weights live here for tuning."""

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=BACKEND_DIR / ".env", extra="ignore")

    # Tier 1 — typed decision model: "openai" (Decisions API, gpt-6-luna) or "jev" (TypeSafe via OpenRouter)
    decision_provider: str = "openai"
    decision_enabled: bool = True
    decision_timeout_s: float = 5.0          # cold calls can take ~4 s; warm ~0.4 s
    openai_api_key: str | None = None
    openai_base_url: str = "https://api.openai.com/v1"
    decision_model: str = "gpt-6-luna"
    openrouter_api_key: str | None = None
    openrouter_base_url: str = "https://openrouter.ai/api"
    jev_model: str = "jev-1.13"

    # Tier 2 — LLM deep audit via an OpenAI-compatible chat completions API (OpenAI by default)
    llm_provider: str = "openai"            # openai | openrouter
    llm_model: str = "gpt-5.6-luna"         # ~4 s; "gpt-5.4-mini" ~2.3 s
    llm_timeout_s: float = 20.0
    stt_model: str = "gpt-4o-mini-transcribe"  # live-call speech-to-text

    # Tier 0 models
    models_dir: Path = BACKEND_DIR / "models"
    temperature: float = 2.0
    torch_threads: int = 4

    # Verdict thresholds (TypeSafe guardrails cookbook)
    thresh_scam: float = 0.70
    thresh_suspicious: float = 0.35
    disagree_llm: float = 0.5
    llm_override_conf: float = 0.75
    url_skip_jev_below: float = 0.2

    # Fusion weights (log-odds space). Defaults, used when no channel-specific weights apply.
    w_jev: float = 0.50
    w_local: float = 0.30
    w_rules: float = 0.20
    w_local_offline: float = 0.65
    w_rules_offline: float = 0.35

    # Per-channel weights: online = (jev, local, rules), offline = (local, rules).
    # SMS local models flag legit transactional SMS (OTP/debit alerts) as spam, so they get little say;
    # tuned on demo/samples.json (see scripts/eval_samples.py).
    channel_weights: dict[str, dict[str, tuple[float, ...]]] = {
        "sms": {"online": (0.60, 0.10, 0.30), "offline": (0.25, 0.75)},
        "email": {"online": (0.45, 0.30, 0.25), "offline": (0.55, 0.45)},
        "url": {"online": (0.35, 0.40, 0.25), "offline": (0.55, 0.45)},
    }
    allowlisted_url_cap: float = 0.15

    db_path: Path = BACKEND_DIR / "scamshield.db"


settings = Settings()
