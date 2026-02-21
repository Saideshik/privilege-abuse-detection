from pad.baseline.profile import build_user_baseline, UserBaseline
from pad.features.build import build_feature_rows, summarize_for_baseline, FeatureRow
from pad.detection.anomaly import anomaly_score
from pad.detection.rules import rule_hits
from pad.mitre.mapping import MITRE
from pad.risk.score import asset_criticality, privilege_level_weight, risk_score

def build_baselines(rows: list[FeatureRow]) -> dict[str, UserBaseline]:
    cmd_counts, hour_counts, host_counts = summarize_for_baseline(rows)
    baselines: dict[str, UserBaseline] = {}
    for user in set(list(cmd_counts.keys()) + list(hour_counts.keys()) + list(host_counts.keys())):
        baselines[user] = build_user_baseline(cmd_counts[user], host_counts[user], hour_counts[user])
    return baselines

def detect(events):
    rows = build_feature_rows(events)
    baselines = build_baselines(rows)

    alerts = []
    for r in rows:
        base = baselines.get(r.event.user)
        if not base:
            continue

        anom = anomaly_score(r, base)
        hits = rule_hits(r)

        reasons = []
        if r.cmd_key and r.cmd_key not in base.top_commands:
            reasons.append("rare_command")
        if r.host and r.host not in base.top_hosts:
            reasons.append("new_host")
        if r.hour not in base.common_hours:
            reasons.append("unusual_hour")

        all_hits = list(dict.fromkeys(hits + reasons))

        if anom >= 0.6 or hits:
            asset = asset_criticality(r.event.host)
            priv = privilege_level_weight(r.event.source, r.event.action, r.event.user)
            risk = risk_score(priv, max(anom, 0.4 if hits else anom), asset)

            mitre = sorted({t for h in all_hits for t in MITRE.get(h, [])})
            alerts.append({
                "event": r.event.to_dict(),
                "anomaly_score": round(anom, 3),
                "detections": all_hits,
                "mitre": mitre,
                "risk": risk,
                "risk_components": {"privilege_weight": priv, "asset_criticality": asset}
            })

    return alerts
