"""Typed application settings.

Settings come from environment variables and (in cloud) from Azure Key Vault
references mounted by Azure Container Apps. NEVER put secret values in this
module or in any committed file. See docs/SECURITY_MODEL.md § 5.

In Phase 1 a KeyVaultSettingsSource will be added so non-local environments
resolve `*_REF` variables (e.g. AZURELENS_SQL_CONNECTION_REF) against the
configured Key Vault via Managed Identity at startup.
"""

from __future__ import annotations

from enum import Enum
from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Environment(str, Enum):
    LOCAL = "local"
    DEV = "dev"
    STAGING = "staging"
    PROD = "prod"


class Settings(BaseSettings):
    """Application settings.

    All variables are prefixed `AZURELENS_` to avoid collisions in shared
    container environments.
    """

    model_config = SettingsConfigDict(
        env_prefix="AZURELENS_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    env: Environment = Field(default=Environment.LOCAL, description="Deployment environment")
    service_name: str = Field(default="azurelens-api", description="Service identifier for telemetry")

    # --- Identity / auth (validated, never secret) ----------------------------
    entra_tenant_id: str | None = Field(default=None, description="Platform Entra ID tenant")
    entra_audience: str | None = Field(default=None, description="Expected JWT audience")

    # --- Resource URIs (not secrets; secrets resolved via Managed Identity) ---
    keyvault_uri: str | None = Field(default=None, description="Azure Key Vault URI")
    cosmos_endpoint: str | None = Field(default=None, description="Cosmos DB endpoint")
    servicebus_fqns: str | None = Field(default=None, description="Service Bus fully qualified namespace")

    # --- Feature flags / observability ----------------------------------------
    enable_openapi: bool = Field(default=True, description="Expose OpenAPI in this env")
    appinsights_connection_string: str | None = Field(
        default=None, description="Application Insights connection string"
    )

    @property
    def is_local(self) -> bool:
        return self.env is Environment.LOCAL


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Cached settings accessor.

    Cached at process start; in tests, call `get_settings.cache_clear()` after
    monkeypatching the environment.
    """
    return Settings()
