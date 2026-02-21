from pad.schema import NormalizedEvent

def parse_windows(evt: dict) -> NormalizedEvent | None:
    ts = evt.get("timestamp")
    user = evt.get("user", "unknown")
    host = evt.get("host", "unknown")
    event_id = evt.get("event_id")

    if event_id == 4624:
        return NormalizedEvent(ts, "windows", user, host, "logon", event_id=event_id, raw=evt)
    if event_id == 4688:
        return NormalizedEvent(
            ts, "windows", user, host, "process",
            process=evt.get("process"),
            command=evt.get("command_line"),
            event_id=event_id,
            raw=evt
        )
    if event_id == 4672:
        return NormalizedEvent(ts, "windows", user, host, "privileged_session", event_id=event_id, raw=evt)

    return None
