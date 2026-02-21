import re
from datetime import datetime
from pad.schema import NormalizedEvent

SUDO_RE = re.compile(r"^(?P<mon>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<host>\S+)\s+sudo:\s+(?P<user>\S+)\s+:\s+.*COMMAND=(?P<cmd>.+)$")

def parse_linux_auth(line: str, year: int = 2026) -> NormalizedEvent | None:
    m = SUDO_RE.match(line)
    if not m:
        return None
    mon = m.group("mon")
    day = int(m.group("day"))
    time_str = m.group("time")
    host = m.group("host")
    user = m.group("user")
    cmd = m.group("cmd")

    ts = f"{year}-{datetime.strptime(mon, '%b').month:02d}-{day:02d}T{time_str}"
    return NormalizedEvent(ts, "linux", user, host, "sudo", command=cmd, raw={"line": line})
