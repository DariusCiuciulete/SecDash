"""
Application configuration using Pydantic Settings v2
"""
from typing import Optional, List
from pydantic import Field, PostgresDsn, RedisDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class DatabaseSettings(BaseSettings):
    """Database configuration"""
    url: PostgresDsn = Field(
        default="postgresql+asyncpg://secdash:secdash@localhost:5432/secdash",
        description="PostgreSQL connection URL"
    )
    echo: bool = Field(default=False, description="Enable SQL query logging")
    pool_size: int = Field(default=10, description="Connection pool size")
    max_overflow: int = Field(default=20, description="Max pool overflow")


class RedisSettings(BaseSettings):
    """Redis configuration"""
    url: RedisDsn = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL"
    )
    broker_url: RedisDsn = Field(
        default="redis://localhost:6379/1",
        description="Celery broker URL"
    )
    result_backend: RedisDsn = Field(
        default="redis://localhost:6379/2",
        description="Celery result backend URL"
    )


class SecuritySettings(BaseSettings):
    """Security and authentication configuration"""
    keycloak_server_url: str = Field(
        default="http://localhost:8080",
        description="Keycloak server URL"
    )
    keycloak_realm: str = Field(
        default="secdash",
        description="Keycloak realm name"
    )
    keycloak_client_id: str = Field(
        default="secdash-api",
        description="Keycloak client ID"
    )
    keycloak_client_secret: Optional[str] = Field(
        default=None,
        description="Keycloak client secret"
    )
    jwt_algorithm: str = Field(
        default="RS256",
        description="JWT signing algorithm"
    )
    jwt_audience: str = Field(
        default="secdash-api",
        description="JWT audience"
    )


class VaultSettings(BaseSettings):
    """HashiCorp Vault configuration"""
    url: str = Field(
        default="http://localhost:8200",
        description="Vault server URL"
    )
    token: Optional[str] = Field(
        default=None,
        description="Vault authentication token"
    )
    mount_point: str = Field(
        default="secret",
        description="Vault secret mount point"
    )


class ObservabilitySettings(BaseSettings):
    """Observability and monitoring configuration"""
    jaeger_endpoint: Optional[str] = Field(
        default="http://localhost:14268/api/traces",
        description="Jaeger traces endpoint"
    )
    sentry_dsn: Optional[str] = Field(
        default=None,
        description="Sentry DSN for error tracking"
    )
    log_level: str = Field(
        default="INFO",
        description="Application log level"
    )


class ScannerSettings(BaseSettings):
    """Security scanner configuration"""
    max_concurrent_scans: int = Field(
        default=5,
        description="Maximum concurrent scans"
    )
    scan_timeout: int = Field(
        default=600,
        description="Scan timeout in seconds"
    )
    docker_network: str = Field(
        default="secdash_default",
        description="Docker network for scanners"
    )
    nmap_image: str = Field(
        default="instrumentisto/nmap:7.95",
        description="Nmap Docker image"
    )
    zap_image: str = Field(
        default="ghcr.io/zaproxy/zaproxy:2.14.0",
        description="OWASP ZAP Docker image"
    )
    nuclei_image: str = Field(
        default="projectdiscovery/nuclei:v3.1.4",
        description="Nuclei Docker image"
    )
    metasploit_image: str = Field(
        default="metasploitframework/metasploit-framework:latest",
        description="Metasploit Docker image"
    )
    tshark_image: str = Field(
        default="linuxserver/wireshark:latest",
        description="Tshark/Wireshark Docker image"
    )
    openvas_image: str = Field(
        default="greenbone/openvas-scanner:latest",
        description="OpenVAS Docker image"
    )


class IntegrationSettings(BaseSettings):
    """External integration configuration"""
    splunk_hec_url: Optional[str] = Field(
        default=None,
        description="Splunk HEC endpoint URL"
    )
    splunk_hec_token: Optional[str] = Field(
        default=None,
        description="Splunk HEC token"
    )
    elasticsearch_url: Optional[str] = Field(
        default=None,
        description="Elasticsearch cluster URL"
    )
    elasticsearch_index_prefix: str = Field(
        default="secdash",
        description="Elasticsearch index prefix"
    )


class Settings(BaseSettings):
    """Main application settings"""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        env_nested_delimiter="__"
    )
    
    # Application info
    app_name: str = Field(default="SecDash", description="Application name")
    app_version: str = Field(default="2.0.0", description="Application version")
    debug: bool = Field(default=False, description="Debug mode")
    
    # API configuration
    api_prefix: str = Field(default="/api/v1", description="API prefix")
    allowed_hosts: List[str] = Field(
        default=["localhost", "127.0.0.1", "0.0.0.0"],
        description="Allowed hosts"
    )
    cors_origins: List[str] = Field(
        default=["http://localhost:3000", "http://127.0.0.1:3000"],
        description="CORS allowed origins"
    )
    
    # Component settings
    database: DatabaseSettings = Field(default_factory=DatabaseSettings)
    redis: RedisSettings = Field(default_factory=RedisSettings)
    security: SecuritySettings = Field(default_factory=SecuritySettings)
    vault: VaultSettings = Field(default_factory=VaultSettings)
    observability: ObservabilitySettings = Field(default_factory=ObservabilitySettings)
    scanners: ScannerSettings = Field(default_factory=ScannerSettings)
    integrations: IntegrationSettings = Field(default_factory=IntegrationSettings)


# Global settings instance
settings = Settings()
