from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # =====================================================
    # SECURITY / AUTH
    # =====================================================

    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # =====================================================
    # DATABASE
    # =====================================================

    DATABASE_URL: str

    # =====================================================
    # LLM
    # =====================================================

    GROQ_API_KEY: str
    LLM_MODEL: str = "qwen/qwen3.6-27b"
    LLM_BASE_URL: str = "https://api.groq.com/openai/v1"

    # =====================================================
    # THREAT INTELLIGENCE
    # =====================================================

    ABUSEIPDB_API_KEY: str

    # =====================================================
    # SOAR EXECUTION
    # =====================================================

    SOAR_EXECUTION_MODE: str = "dry_run"

    SOAR_ENABLE_BLOCK_IP: bool = False

    SOAR_ENABLE_ISOLATE_ENDPOINT: bool = False

    # =====================================================
    # PYDANTIC SETTINGS
    # =====================================================

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()