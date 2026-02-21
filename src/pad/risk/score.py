from pad.config import RiskConfig, DEFAULT_RISK_CONFIG

def asset_criticality(host: str, cfg: RiskConfig = DEFAULT_RISK_CONFIG) -> float:
    return cfg.asset_criticality.get(host, cfg.asset_criticality["default"])

def privilege_level_weight(source: str, action: str, user: str, cfg: RiskConfig = DEFAULT_RISK_CONFIG) -> float:
    if source == "linux" and action == "sudo":
        return cfg.privilege_weights["sudo"]
    if source == "windows" and action in ("privileged_session", "process"):
        return cfg.privilege_weights["admin"]
    if source == "cloud":
        return cfg.privilege_weights["cloud_admin"]
    if "svc" in user.lower():
        return cfg.privilege_weights["service_account"]
    return cfg.privilege_weights["user"]

def risk_score(priv_w: float, anom: float, asset: float) -> float:
    return round(priv_w * anom * asset, 3)
