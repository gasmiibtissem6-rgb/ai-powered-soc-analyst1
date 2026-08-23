from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    GROQ_API_KEY: str
    LLM_MODEL: str = "qwen/qwen3.6-27b"
    LLM_BASE_URL: str = "https://api.groq.com/openai/v1"
    ABUSEIPDB_API_KEY: str

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()