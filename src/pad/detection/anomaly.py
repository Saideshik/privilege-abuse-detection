from pad.baseline.profile import UserBaseline
from pad.features.build import FeatureRow

def anomaly_score(row: FeatureRow, baseline: UserBaseline) -> float:
    """Simple interpretable scoring (cap 1.0):
    - rare command: +0.5
    - new host: +0.3
    - unusual hour: +0.3
    """
    s = 0.0
    if row.cmd_key and row.cmd_key not in baseline.top_commands:
        s += 0.5
    if row.host and row.host not in baseline.top_hosts:
        s += 0.3
    if row.hour not in baseline.common_hours:
        s += 0.3
    return min(1.0, s)
