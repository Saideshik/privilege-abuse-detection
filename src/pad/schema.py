from dataclasses import dataclass, asdict
from typing import Any, Optional

@dataclass
class NormalizedEvent:
    timestamp: str
    source: str              # windows/linux/cloud
    user: str
    host: str
    action: str              # e.g., "logon", "process", "sudo", "iam"
    command: Optional[str] = None
    process: Optional[str] = None
    event_id: Optional[int] = None
    raw: Optional[dict[str, Any]] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
