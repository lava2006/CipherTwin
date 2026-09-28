"""Reference catalog of MITRE ATT&CK techniques used by the threat engine."""
from typing import Dict, List

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
}


def all_techniques() -> List[Dict]:
    return [{"id": k, **v} for k, v in MITRE_TECHNIQUES.items()]
