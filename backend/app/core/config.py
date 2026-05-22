from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "Secure IT UP Assessment Suite"
    environment: str = Field(default="development", alias="ENVIRONMENT")
    database_url: str = Field(default="sqlite:///./secure_it_up.db", alias="DATABASE_URL")
    secret_key: str = Field(
        default="dev-only-change-me-please-override-32-bytes", alias="SECRET_KEY"
    )
    access_token_expire_minutes: int = 720
    dev_seed_username: str = Field(default="admin@example.com", alias="DEV_SEED_USERNAME")
    dev_seed_password: str = Field(default="ChangeMeDevOnly!123", alias="DEV_SEED_PASSWORD")
    upload_max_bytes: int = 2_000_000
    cors_origins: str = Field(default="http://localhost:5173,http://127.0.0.1:5173")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore", populate_by_name=True)

    @property
    def is_development(self) -> bool:
        return self.environment.lower() in {"dev", "development", "local", "test"}

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if (
        not settings.is_development
        and settings.secret_key == "dev-only-change-me-please-override-32-bytes"
    ):
        raise RuntimeError("SECRET_KEY must be set outside development mode.")
    return settings
