from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    app_name: str = "AegisNova"
    environment: str = "development"
    secret_key: str = Field(min_length=24)
    database_url: str = "sqlite:///./aegisnova.db"
    cors_origins: str = "http://localhost:5173"
    access_token_minutes: int = 30
    max_upload_bytes: int = 5 * 1024 * 1024
    bootstrap_admin_email: str = ""
    @property
    def origins(self):
        return [x.strip() for x in self.cors_origins.split(",") if x.strip()]

settings = Settings()
