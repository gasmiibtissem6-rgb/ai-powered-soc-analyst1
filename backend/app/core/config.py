from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # =====================================================
    # SECURITY / AUTH
    # =====================================================

    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Keycloak / OpenID Connect
    KEYCLOAK_URL: str = "http://keycloak:8080"
    KEYCLOAK_ISSUER: str = "http://localhost:8080/realms/soc"
    KEYCLOAK_REALM: str = "soc"
    KEYCLOAK_CLIENT_ID: str = "soc-backend"

    # Machine-to-machine ingestion authentication
    SOC_INGESTION_API_KEY: str

    # =====================================================
    # DATABASE / CACHE
    # =====================================================

    DATABASE_URL: str
    REDIS_URL: str = "redis://localhost:6379/0"

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
    VIRUSTOTAL_API_KEY: str = ""
    OTX_API_KEY: str = ""

    MISP_URL: str = ""
    MISP_API_KEY: str = ""
    MISP_VERIFY_SSL: bool = True

    # =====================================================
    # SOAR EXECUTION
    # =====================================================

    SOAR_EXECUTION_MODE: str = "dry_run"

    SOAR_ENABLE_BLOCK_IP: bool = False
    SOAR_ENABLE_ISOLATE_ENDPOINT: bool = False
    SOAR_ENABLE_DISABLE_USER: bool = False
    SOAR_ENABLE_SEND_NOTIFICATION: bool = False

    SLACK_WEBHOOK_URL: str = ""
    TEAMS_WEBHOOK_URL: str = ""

    # =====================================================
    # VAULT / SECRET MANAGEMENT
    # =====================================================

    VAULT_ADDR: str = ""
    VAULT_TOKEN: str = ""
    VAULT_MOUNT_POINT: str = "secret"
    VAULT_SECRET_PATH: str = "soc-backend"

    # =====================================================
    # PYDANTIC SETTINGS
    # =====================================================

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
