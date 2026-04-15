from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

# Look for .env in the project root (lan-monitor/) regardless of cwd
_ROOT_ENV = Path(__file__).parent.parent.parent / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_ROOT_ENV),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    database_url: str = "sqlite:////data/db/lan_monitor.db"

    # Network scanning
    scan_cidr: str = "192.168.1.0/24"
    scan_interval_minutes: int = 30
    nmap_args: str = "-sV --open -T4"

    # Log paths
    zeek_log_dir: str = "/data/logs/zeek"
    suricata_log_path: str = "/data/logs/suricata/eve.json"
    router_syslog_path: str = "/data/logs/router/syslog"

    # Scoring thresholds
    outbound_fanout_threshold: int = 50
    sustained_upload_threshold_mb: float = 500.0
    long_lived_session_threshold_sec: int = 3600
    long_lived_session_count_threshold: int = 3
    dns_churn_threshold: int = 100
    domain_diversity_nxdomain_threshold: int = 20
    geo_asn_spread_threshold: int = 10
    behavior_deviation_z_threshold: float = 2.5
    suricata_alert_low_delta: float = 5.0
    suricata_alert_medium_delta: float = 15.0
    suricata_alert_high_delta: float = 30.0
    suricata_alert_critical_delta: float = 50.0

    # IoT/TV weight multiplier
    iot_weight_multiplier: float = 1.5

    # Alert thresholds
    alert_score_change_threshold: float = 10.0

    # GeoIP
    use_geoip: bool = False
    geoip_db_path: str = "/data/GeoLite2-City.mmdb"
    ip_api_base_url: str = "http://ip-api.com/json"

    # Baseline
    baseline_window_hours: int = 168  # 7 days
    baseline_compute_interval_hours: int = 24

    # LLM analysis
    llm_enabled: bool = False
    llm_provider: str = "ollama"   # ollama | lmstudio
    llm_base_url: str = "http://localhost:11434"
    llm_model: str = "llama3.2"


settings = Settings()
