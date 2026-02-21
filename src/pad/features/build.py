from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime
from pad.schema import NormalizedEvent

@dataclass
class FeatureRow:
    event: NormalizedEvent
    hour: int
    cmd_key: str
    host: str

def _hour(ts: str) -> int:
    try:
        return datetime.fromisoformat(ts).hour
    except Exception:
        return 0

def build_feature_rows(events: list[NormalizedEvent]) -> list[FeatureRow]:
    rows: list[FeatureRow] = []
    for e in events:
        cmd = e.command or e.process or e.action
        cmd_key = (cmd or "").lower().strip()
        rows.append(FeatureRow(event=e, hour=_hour(e.timestamp), cmd_key=cmd_key, host=e.host))
    return rows

def summarize_for_baseline(rows: list[FeatureRow]):
    cmd_counts = defaultdict(Counter)
    hour_counts = defaultdict(Counter)
    host_counts = defaultdict(Counter)

    for r in rows:
        u = r.event.user
        if r.cmd_key:
            cmd_counts[u][r.cmd_key] += 1
        hour_counts[u][r.hour] += 1
        host_counts[u][r.host] += 1

    return cmd_counts, hour_counts, host_counts
