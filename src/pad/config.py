from dataclasses import dataclass

@dataclass(frozen=True)
class RiskConfig:
    privilege_weights: dict
    asset_criticality: dict
    risk_threshold_high: float = 6.0
    risk_threshold_med: float = 3.0

DEFAULT_RISK_CONFIG = RiskConfig(
    privilege_weights={
        "user": 1.0,
        "sudo": 2.0,
        "admin": 2.5,
        "domain_admin": 3.0,
        "cloud_admin": 2.5,
        "service_account": 3.0,
    },
    asset_criticality={
        "dc01": 2.0,
        "db01": 2.0,
        "fileserver01": 1.5,
        "web01": 1.2,
        "default": 1.0,
    }
)
