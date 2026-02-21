from pad.schema import NormalizedEvent

def parse_cloud(evt: dict) -> NormalizedEvent | None:
    ts = evt.get("timestamp")
    user = evt.get("userIdentity", "unknown")
    host = evt.get("sourceIPAddress", "unknown")
    action = evt.get("eventName", "iam")

    return NormalizedEvent(
        ts, "cloud", user, host, "iam",
        command=action,
        raw=evt
    )
