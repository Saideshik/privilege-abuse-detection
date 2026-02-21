import re
from pad.features.build import FeatureRow

POWERSHELL_ENC = re.compile(r"\b(-enc|-encodedcommand)\b", re.IGNORECASE)
ADD_USER = re.compile(r"\b(useradd|net user)\b", re.IGNORECASE)

def rule_hits(row: FeatureRow) -> list[str]:
    hits: list[str] = []
    e = row.event

    if e.source == "windows" and (e.process or "").lower() == "powershell.exe":
        if POWERSHELL_ENC.search(e.command or ""):
            hits.append("suspicious_powershell_encoded_command")

    if e.source in ("linux", "windows"):
        if ADD_USER.search(e.command or ""):
            hits.append("account_creation_command_observed")

    if "svc" in e.user.lower() and e.action in ("process", "sudo", "iam"):
        hits.append("service_account_interactive_activity")

    return hits
