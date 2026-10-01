"""MITRE ATT&CK helpers: kill-chain ordering and technique names used by the rule set."""

from __future__ import annotations

KILL_CHAIN = [
    "Reconnaissance",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

TECHNIQUES = {
    "T1595": "Active Scanning",
    "T1190": "Exploit Public-Facing Application",
    "T1566.001": "Phishing: Spearphishing Attachment",
    "T1078": "Valid Accounts",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.004": "Command and Scripting Interpreter: Unix Shell",
    "T1204.002": "User Execution: Malicious File",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1505.003": "Server Software Component: Web Shell",
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1110.001": "Brute Force: Password Guessing",
    "T1110.003": "Brute Force: Password Spraying",
    "T1046": "Network Service Discovery",
    "T1087": "Account Discovery",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1569.002": "System Services: Service Execution",
    "T1105": "Ingress Tool Transfer",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1048": "Exfiltration Over Alternative Protocol",
    "T1548.003": "Abuse Elevation Control: Sudo and Sudo Caching",
}


def technique_name(technique_id: str) -> str:
    return TECHNIQUES.get(technique_id, technique_id)


def tactic_from_tag(tag: str) -> str | None:
    """Convert a Sigma tag like ``attack.credential_access`` to ``Credential Access``."""
    if not tag.startswith("attack."):
        return None
    name = tag[len("attack.") :]
    if name[:1].lower() == "t" and name[1:2].isdigit():
        return None
    words = name.replace("-", "_").split("_")
    pretty = " ".join(w.capitalize() for w in words)
    return pretty.replace("And", "and")


def technique_from_tag(tag: str) -> str | None:
    """Convert ``attack.t1059.001`` to ``T1059.001``."""
    if not tag.startswith("attack."):
        return None
    name = tag[len("attack.") :]
    if name[:1].lower() == "t" and name[1:2].isdigit():
        return name.upper()
    return None
