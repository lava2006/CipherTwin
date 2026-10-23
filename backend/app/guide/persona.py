"""CipherTwinGuide Persona and Response Style Definitions.

Supports 7 roles and 5 response styles with dynamic role-tailored starter questions
and free-text intent extraction.
"""
from typing import Dict, List, Tuple

ROLES = [
    "Beginner/General user",
    "Developer/Software engineer",
    "Cybersecurity analyst/SOC",
    "SysAdmin/DevOps",
    "Researcher/Advanced technical user",
    "Project manager/Decision-maker",
    "Student/Learner",
]

STYLES = [
    "Simple Explanation",
    "Practical Guidance",
    "Technical Deep Dive",
    "Troubleshooting",
    "Executive Summary",
]

ROLE_DESCRIPTIONS = {
    "Beginner/General user": "Clear, accessible explanations using everyday analogies; avoid unexplained jargon.",
    "Developer/Software engineer": "API contracts, data schemas, code flow, integration points, and architectural logic.",
    "Cybersecurity analyst/SOC": "Attack vectors, IOCs, MITRE ATT&CK tactics, risk factor breakdown, and triage steps.",
    "SysAdmin/DevOps": "Service status, port bindings, resource health, pipeline latencies, deployment, and recovery commands.",
    "Researcher/Advanced technical user": "Algorithmic mechanisms, QUBO formulations, graph topology mathematics, and experimental verification.",
    "Project manager/Decision-maker": "High-level risk posture, business impact, compliance, system availability, and strategic recommendations.",
    "Student/Learner": "Pedagogical step-by-step breakdowns, foundational principles, learning takeaways, and illustrative examples.",
}

STYLE_DESCRIPTIONS = {
    "Simple Explanation": "Concise, plain-language breakdown with analogies; focus on intuition.",
    "Practical Guidance": "Step-by-step actionable procedures and concrete recommendations.",
    "Technical Deep Dive": "Exhaustive technical detail, packet/event fields, and architectural causality.",
    "Troubleshooting": "Root-cause diagnostics, log anomaly detection, and verification commands.",
    "Executive Summary": "Bottom-line metrics, operational risk status, and key takeaways for leadership.",
}

ROLE_STARTER_QUESTIONS: Dict[str, List[str]] = {
    "Beginner/General user": [
        "What is Zero Trust in simple words?",
        "What is happening on the dashboard right now?",
        "What is a honeypot and how does it protect us?",
        "Why was the most recent user request blocked or allowed?",
    ],
    "Developer/Software engineer": [
        "What endpoints ingest telemetry and what payload schema is expected?",
        "How does the Zero-Trust scoring engine calculate factor contributions?",
        "What is the database schema for access decisions and decoy sessions?",
        "How do I integrate an external SIEM with the RabbitMQ topic exchange?",
    ],
    "Cybersecurity analyst/SOC": [
        "What attack techniques and commands were captured in the decoy honeypot?",
        "Show me the factor breakdown for the latest high-risk access decision.",
        "Are there any lateral movement attempts detected in the Digital Twin?",
        "What is our current threat level and active decoy status?",
    ],
    "SysAdmin/DevOps": [
        "What is the health status of RabbitMQ, Neo4j, and the SQLite database?",
        "How many telemetry events per second is the pipeline currently ingesting?",
        "How can I restart or check logs for the Cowrie honeypot bridge?",
        "Are any services degraded or dropping messages?",
    ],
    "Researcher/Advanced technical user": [
        "How is the QUBO matrix constructed for policy reoptimization?",
        "What graph algorithm is used to model attack paths in the Digital Twin?",
        "How does QAOA compare against classical simulated annealing in benchmarks?",
        "What is the mathematical formulation of the zero-trust risk scoring function?",
    ],
    "Project manager/Decision-maker": [
        "Provide an executive summary of our current security risk posture.",
        "How many security incidents were automatically mitigated this week?",
        "What is our system uptime and subsystem operational readiness?",
        "What are the top three security recommendations for leadership?",
    ],
    "Student/Learner": [
        "Explain how a Digital Twin helps cybersecurity analysts learn attack paths.",
        "What is the difference between an IDS and an Adaptive Deception system?",
        "Can you walk me step by step through how an access decision is evaluated?",
        "What are the basic components of the CipherTwin architecture?",
    ],
}

def detect_persona_in_text(text: str, current_role: str, current_style: str) -> Tuple[str, str, bool]:
    """Inspect user free text for explicit role or style overrides.
    
    Returns (role, style, changed_flag).
    """
    lower = text.lower()
    detected_role = current_role
    detected_style = current_style
    changed = False

    # Check for role keywords
    if any(k in lower for k in ["soc analyst", "security analyst", "cyber analyst", "i'm a soc", "i am a soc"]):
        if detected_role != "Cybersecurity analyst/SOC":
            detected_role = "Cybersecurity analyst/SOC"
            changed = True
    elif any(k in lower for k in ["developer", "software engineer", "dev", "programmer", "i'm a dev"]):
        if detected_role != "Developer/Software engineer":
            detected_role = "Developer/Software engineer"
            changed = True
    elif any(k in lower for k in ["sysadmin", "devops", "system admin", "sre", "i'm a sysadmin"]):
        if detected_role != "SysAdmin/DevOps":
            detected_role = "SysAdmin/DevOps"
            changed = True
    elif any(k in lower for k in ["researcher", "scientist", "academic", "i'm a researcher"]):
        if detected_role != "Researcher/Advanced technical user":
            detected_role = "Researcher/Advanced technical user"
            changed = True
    elif any(k in lower for k in ["manager", "project manager", "pm", "executive", "ciso", "director"]):
        if detected_role != "Project manager/Decision-maker":
            detected_role = "Project manager/Decision-maker"
            changed = True
    elif any(k in lower for k in ["student", "learner", "studying", "beginner", "newbie", "layman"]):
        if "student" in lower or "learner" in lower:
            target = "Student/Learner"
        else:
            target = "Beginner/General user"
        if detected_role != target:
            detected_role = target
            changed = True

    # Check for style keywords
    if any(k in lower for k in ["deep dive", "technical deep dive", "in-depth", "exhaustive"]):
        if detected_style != "Technical Deep Dive":
            detected_style = "Technical Deep Dive"
            changed = True
    elif any(k in lower for k in ["simple", "plain english", "simple explanation", "explain simply", "like i'm 5"]):
        if detected_style != "Simple Explanation":
            detected_style = "Simple Explanation"
            changed = True
    elif any(k in lower for k in ["practical", "actionable", "step by step", "how to"]):
        if detected_style != "Practical Guidance":
            detected_style = "Practical Guidance"
            changed = True
    elif any(k in lower for k in ["troubleshoot", "debug", "root cause", "fix it"]):
        if detected_style != "Troubleshooting":
            detected_style = "Troubleshooting"
            changed = True
    elif any(k in lower for k in ["executive summary", "summary for leadership", "tldr", "high level overview"]):
        if detected_style != "Executive Summary":
            detected_style = "Executive Summary"
            changed = True

    return detected_role, detected_style, changed
