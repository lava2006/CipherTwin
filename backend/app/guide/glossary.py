"""CipherGuide Glossary module.

Provides beginner-friendly definitions, everyday analogies, and technical context
for key cybersecurity, Digital Twin, and quantum optimization terms.
"""
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional
import re


@dataclass
class GlossaryTerm:
    term: str
    category: str
    simple_definition: str
    analogy: str
    technical_definition: str
    example: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


_RAW_ITEMS: Dict[str, Dict[str, Any]] = {
    "zero trust": {
        "term": "Zero Trust",
        "category": "Architecture",
        "simple_definition": "A security philosophy where nobody is trusted automatically, inside or outside the company. Every single access request must prove identity, healthy device state, and normal behavior.",
        "analogy": "Like a high-security hotel where having a room key doesn't let you into the kitchen, gym, or executive floor without swiping and verifying your identity at every single door.",
        "technical_definition": "A defense architecture based on NIST SP 800-207 requiring continuous authentication, strict least privilege, and dynamic risk scoring per session regardless of network perimeter.",
        "example": "CipherTwin evaluates identity confidence, device posture, and behavioral deviation on every request before granting access.",
    },
    "risk score": {
        "term": "Risk Score",
        "category": "Zero Trust",
        "simple_definition": "A calculated number from 0 to 100 representing how dangerous or abnormal an access request appears right now. Higher numbers indicate higher suspicion.",
        "analogy": "Like a credit score, but in reverse: 0 is completely clean and trusted, while 100 means an alarm is ringing.",
        "technical_definition": "A multi-factor weighted sum (0-100) combining identity confidence, device posture, behavioral anomalies, resource sensitivity, location anomalies, and previous history.",
        "example": "A score below 30 is Allowed, 30 to 60 is Restricted (diverted to a decoy), and above 60 is Denied.",
    },
    "digital twin": {
        "term": "Digital Twin",
        "category": "Architecture",
        "simple_definition": "A real-time virtual replica of your company's network, servers, laptops, users, and connections stored in a graph database.",
        "analogy": "Like a live GPS map of a city showing every street, building, and roadblock in real time.",
        "technical_definition": "A Neo4j graph model representing hosts, users, services, active sessions, and credential relationships kept synchronized via telemetry event streams.",
        "example": "The Digital Twin topology visualizes nodes and relationships showing where assets connect and where threats penetrate.",
    },
    "honeytoken": {
        "term": "Honeytoken",
        "category": "Deception",
        "simple_definition": "A piece of digital bait—like an unassigned lure password, decoy API key, or hidden file—that real employees never use. If anyone touches it, an alarm fires instantly.",
        "analogy": "Like an exploding dye pack tucked into a bank cash register: genuine employees never touch it, so any movement means a thief is active.",
        "technical_definition": "An intentionally planted decoy artifact (API credential, database record, decoy document) equipped with telemetry monitoring that alerts with 95%+ confidence when accessed.",
        "example": "A honeytoken credential planted in cloud configs triggers a critical alert when an attacker dumps credentials.",
    },
    "decoy": {
        "term": "Decoy (Honeypot)",
        "category": "Deception",
        "simple_definition": "An isolated, harmless lure server or web application designed to attract, confuse, and trap attackers without risking real data.",
        "analogy": "A theatrical movie set of a bank vault with stage walls and cameras: the burglar spends hours trying to crack a safe made of cardboard while police watch.",
        "technical_definition": "High, medium, or low fidelity deception nodes (such as Cowrie SSH honeypots or decoy web portals) that safely log keystrokes, commands, and attacker tools.",
        "example": "Attacker SSH sessions on port 2222 are trapped inside Cowrie, capturing their passwords and payloads while protecting production systems.",
    },
    "blast radius": {
        "term": "Blast Radius",
        "category": "Incident Response",
        "simple_definition": "The maximum reach an attacker could gain if they take over a specific laptop or server—all the other computers and files reachable from there.",
        "analogy": "If an intruder gets into the front foyer, the blast radius is whichever interior rooms don't have locked doors.",
        "technical_definition": "The directed reachability subgraph from a compromised node up to N hops away in the Neo4j Digital Twin.",
        "example": "If a developer workstation is compromised, the blast radius shows reachable build systems, source repositories, and databases within 3 hops.",
    },
    "twin forecast": {
        "term": "Twin Forecast (Impact Preview)",
        "category": "Architecture",
        "simple_definition": "A what-if preview that tests changes—like enforcing MFA or revoking access—on a private copy of the network before touching the real system.",
        "analogy": "Like testing flight maneuvers in a dry-run rehearsal before taking off with passengers to see how the plane handles turbulent weather.",
        "technical_definition": "An in-memory evaluation of Zero-Trust risk re-scoring and reachability traversal on an isolated subgraph copy without mutating live Neo4j database nodes.",
        "example": "Testing 'What if MFA is required for all finance users?' forecasts an 18% average risk reduction across 12 endpoints.",
    },
    "qaoa": {
        "term": "QAOA (Quantum Approximate Optimization Algorithm)",
        "category": "Quantum",
        "simple_definition": "A quantum computing technique designed to find the best possible policy rules and decoy placements out of billions of combinations.",
        "analogy": "Finding the fastest route through a massive maze by sending water through all paths at once rather than walking down one dead end at a time.",
        "technical_definition": "A hybrid quantum-classical variational algorithm (executed in PennyLane on a lightning.qubit statevector engine) optimizing cost Hamiltonians.",
        "example": "QAOA searches policy weight combinations to minimize false positives while maximizing detection across capacity constraints.",
    },
    "qubo": {
        "term": "QUBO (Quadratic Unconstrained Binary Optimization)",
        "category": "Quantum",
        "simple_definition": "A mathematical way of writing a complex decision problem into a grid of yes/no (1 or 0) choices that quantum optimizers can solve.",
        "analogy": "Converting a complicated puzzle with 20 rules into a checklist where each item is either checked or unchecked.",
        "technical_definition": "A matrix formulation min x^T Q x + c where x is a binary vector representing discrete policy actions and decoy allocations under penalty constraints.",
        "example": "CipherTwin formats policy reweighting and honeypot capacity into a QUBO matrix solved by QAOA or SciPy.",
    },
    "lateral movement": {
        "term": "Lateral Movement",
        "category": "Incident Response",
        "simple_definition": "When an attacker who has broken into one minor computer hops across the internal network into more sensitive servers and databases.",
        "analogy": "A thief climbing through a basement window, finding a keychain, and walking into the master bedroom and home office.",
        "technical_definition": "Techniques (MITRE ATT&CK T1021) where adversaries pivot through internal remote services (SSH, RDP, SMB) using harvested credentials.",
        "example": "An attacker hopping from an analyst terminal to the core database is flagged by behavioral deviation and isolated to a decoy.",
    },
    "telemetry": {
        "term": "Telemetry",
        "category": "Architecture",
        "simple_definition": "Continuous health and activity measurements streamed from computers across the network—logins, processes started, and connections made.",
        "analogy": "Like the dashboard dials in an airplane showing altitude, speed, fuel, and engine temperature every second.",
        "technical_definition": "High-velocity event streams (EDR process events, IAM authentications, NetFlow records) transported via RabbitMQ topic exchanges.",
        "example": "The telemetry feed streams 1 event per second into the twin consumer, immediately updating the risk score.",
    },
    "posture": {
        "term": "Device Posture",
        "category": "Zero Trust",
        "simple_definition": "The health and security condition of a computer: whether its disk is encrypted, firewall is on, and operating system updates are current.",
        "analogy": "A health checkup before entering a sterile laboratory: verifying clean clothes, a mask, and no symptoms.",
        "technical_definition": "An endpoint security evaluation combining patch status, endpoint protection status, disk encryption, and local policy compliance.",
        "example": "A laptop with missing patches has a degraded device posture, increasing its risk score on sensitive requests.",
    },
    "mfa": {
        "term": "MFA (Multi-Factor Authentication)",
        "category": "Zero Trust",
        "simple_definition": "Requiring two or more proofs of identity before letting someone log in—such as a password plus a temporary code on your smartphone.",
        "analogy": "Needing both a physical metal key and a secret alarm code to unlock your front door.",
        "technical_definition": "Authentication requiring two or more independent credentials (knowledge, possession, inherence) to prevent credential-stuffing attacks.",
        "example": "Enabling MFA for the finance team drops average identity risk from 45% down to 10%.",
    },
    "mitre attack": {
        "term": "MITRE ATT&CK",
        "category": "Incident Response",
        "simple_definition": "A worldwide encyclopedia of real attack tactics and techniques used by actual adversaries, organized into clear categories.",
        "analogy": "A master playbook used by sports coaches that lists every play and trick the opposing team might try.",
        "technical_definition": "A curated knowledge base and matrix of adversary tactics, techniques, and procedures (TTPs) based on real-world threat observations.",
        "example": "Extracted attack commands are mapped to techniques like T1059 (Command Execution) and T1003 (Credential Dumping).",
    },
    "qubit": {
        "term": "Qubit (Quantum Bit)",
        "category": "Quantum",
        "simple_definition": "The basic unit of quantum information. Unlike normal computer bits that are strictly 0 or 1, a qubit can represent a combination of both simultaneously.",
        "analogy": "A normal coin sitting flat is either Heads or Tails; a spinning coin in mid-air is in a blend of both states until it stops.",
        "technical_definition": "A two-state quantum mechanical system whose state vector |psi> = alpha|0> + beta|1> enables superposition and quantum entanglement.",
        "example": "CipherTwin executes 11 to 17 qubits on PennyLane's lightning.qubit engine to represent decision variables.",
    },
}

GLOSSARY_ITEMS: Dict[str, GlossaryTerm] = {
    k: GlossaryTerm(**v) for k, v in _RAW_ITEMS.items()
}


def get_all_terms() -> List[GlossaryTerm]:
    """Return all glossary items sorted by canonical term name."""
    return sorted(GLOSSARY_ITEMS.values(), key=lambda x: x.term)


get_glossary = get_all_terms


def get_glossary_term(query: str) -> Optional[GlossaryTerm]:
    """Lookup a term by exact name or substring match."""
    q = query.strip().lower()
    if q in GLOSSARY_ITEMS:
        return GLOSSARY_ITEMS[q]
    for key, item in GLOSSARY_ITEMS.items():
        if q in key or key in q:
            return item
        if q in item.term.lower():
            return item
    return None


def explain_term(query: str) -> Optional[Dict[str, Any]]:
    """Legacy helper returning dictionary representation."""
    term = get_glossary_term(query)
    return term.to_dict() if term else None


def find_terms_in_text(text: str) -> List[Dict[str, Any]]:
    """Find glossary terms that appear in a given text snippet."""
    found = []
    text_lower = text.lower()
    for key, item in GLOSSARY_ITEMS.items():
        pattern = r"\b" + re.escape(key) + r"\b"
        if re.search(pattern, text_lower):
            found.append(item.to_dict())
    return found
