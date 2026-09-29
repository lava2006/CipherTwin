"""Normalized MITRE ATT&CK Mapping Layer for CipherTwin.

NOTE: This mapping layer is strictly deterministic and rule-based.
It derives ATT&CK techniques and tactics from observed telemetry events,
process names, and risk indicators without fabricating synthetic detections.

Mapping Chain:
Event & Indicators -> Observed Behavior -> MITRE Technique -> Tactic
"""
from typing import Dict, List, Optional

MITRE_TECHNIQUES: Dict[str, Dict] = {
    "T1078": {"name": "Valid Accounts", "tactic": "Initial Access"},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access"},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution"},
    "T1059.001": {"name": "PowerShell", "tactic": "Execution"},
    "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery"},
    "T1087": {"name": "Account Discovery", "tactic": "Discovery"},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement"},
    "T1021.004": {"name": "SSH", "tactic": "Lateral Movement"},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access"},
    "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration"},
    "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration"},
    "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact"},
    "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact"},
    "T1098": {"name": "Account Manipulation", "tactic": "Persistence"},
    "T1543": {"name": "Create or Modify System Process", "tactic": "Persistence"},
    "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control"},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access"},
    "T1105": {"name": "Ingress Tool Transfer", "tactic": "Command and Control"},
}

# Rule-based mapping table
EVENT_RULE_MAPPINGS: Dict[str, str] = {
    "failed_login": "T1110",
    "privilege_escalation": "T1098",
    "powershell": "T1059.001",
    "lateral_movement": "T1021",
    "data_exfiltration": "T1041",
    "usb_insertion": "T1098",
    "abnormal_process": "T1059",
    "ssh_attempt": "T1021.004",
    "credential_dump": "T1003",
}

INDICATOR_RULE_MAPPINGS: Dict[str, str] = {
    "brute_force": "T1110",
    "impossible_travel": "T1078",
    "sensitive_resource": "T1083",
    "credential_stuffing": "T1110",
}


def all_techniques() -> List[Dict]:
    """Return all catalog techniques with tactics and IDs."""
    return [{"id": k, **v} for k, v in MITRE_TECHNIQUES.items()]


def map_event_to_mitre(
    event_type: str,
    risk_indicators: Optional[List[str]] = None,
) -> Optional[Dict]:
    """Deterministically map event type and indicators to MITRE ATT&CK technique and tactic."""
    tech_id = EVENT_RULE_MAPPINGS.get(event_type)
    rule_reason = f"Event type '{event_type}' matched static rule"

    if not tech_id and risk_indicators:
        for ind in risk_indicators:
            if ind in INDICATOR_RULE_MAPPINGS:
                tech_id = INDICATOR_RULE_MAPPINGS[ind]
                rule_reason = f"Risk indicator '{ind}' matched static rule"
                break

    if not tech_id:
        return None

    info = MITRE_TECHNIQUES.get(tech_id)
    if not info:
        return None

    return {
        "technique_id": tech_id,
        "technique_name": info["name"],
        "tactic": info["tactic"],
        "mapping_method": "RULE_BASED",
        "rule_reason": rule_reason,
    }
