from dataclasses import dataclass
from collections import Counter

@dataclass
class UserBaseline:
    top_commands: set[str]
    top_hosts: set[str]
    common_hours: set[int]

def build_user_baseline(
    cmd_counter: Counter,
    host_counter: Counter,
    hour_counter: Counter,
    top_k_cmd: int = 10,
    top_k_host: int = 5,
    top_k_hour: int = 8,
) -> UserBaseline:
    top_commands = {c for c, _ in cmd_counter.most_common(top_k_cmd)}
    top_hosts = {h for h, _ in host_counter.most_common(top_k_host)}
    common_hours = {hr for hr, _ in hour_counter.most_common(top_k_hour)}
    return UserBaseline(top_commands=top_commands, top_hosts=top_hosts, common_hours=common_hours)
