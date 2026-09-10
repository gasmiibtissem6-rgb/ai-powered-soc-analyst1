from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # =====================================================
    # SECURITY / AUTH
    # =====================================================
    CORS_ORIGINS: str = "https://soc.local,http://localhost:3002"
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
    DATABASE_ECHO: bool = False
    REDIS_URL: str = "redis://localhost:6379/0"
    QDRANT_URL: str = "http://localhost:6333"

    # =====================================================
    # LLM
    # =====================================================

    GROQ_API_KEY: str
    LLM_MODEL: str = "openai/gpt-oss-120b"
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
    # SHUFFLE SOAR
    # =====================================================

    SHUFFLE_ENABLED: bool = False
    SHUFFLE_WEBHOOK_URL: str = ""
    SHUFFLE_WEBHOOK_SECRET: str = ""
    SHUFFLE_VERIFY_SSL: bool = True
    SHUFFLE_TIMEOUT_SECONDS: int = 15

    # =====================================================
    # VAULT / SECRET MANAGEMENT
    # =====================================================

    VAULT_ADDR: str = ""
    VAULT_TOKEN: str = ""
    VAULT_MOUNT_POINT: str = "secret"
    VAULT_SECRET_PATH: str = "soc-backend"

    TRUSTED_HOSTS: str = (
        "soc.local,localhost,127.0.0.1,testserver"
    )

    # =====================================================
    # PYDANTIC SETTINGS
    # =====================================================

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()