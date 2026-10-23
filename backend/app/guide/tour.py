"""Guided Tour step definitions and live example fetchers for CipherTwin."""
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from app.db.session import SessionLocal
from app.models.twin import TwinNode
from app.models.risk import RiskDecision
from app.models.deception import DecoySession
from app.models.policy import PolicyImprovement
from app.guide.glossary import explain_term


@dataclass
class TourStep:
    step: int
    title: str
    concept: str
    plain_text: str
    live_example: str
    try_question: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)



def get_all_tour_steps(db: Optional[Session] = None) -> List[Dict[str, Any]]:
    """Return the 8 Guided Tour steps enriched with live system data."""
    close_at_end = False
    if db is None:
        db = SessionLocal()
        close_at_end = True

    try:
        # 1. Digital Twin stats
        node_count = db.query(TwinNode).count()
        server_count = db.query(TwinNode).filter(TwinNode.type == "server").count()

        # 2. Risk decision
        latest_decision = db.query(RiskDecision).order_by(RiskDecision.timestamp.desc()).first()
        dec_score = f"{latest_decision.risk_score:.1f}" if latest_decision else "35.0"
        dec_verdict = (latest_decision.decision.upper() if latest_decision else "ALLOW")

        # 3. Decoy session
        latest_decoy = db.query(DecoySession).order_by(DecoySession.timestamp.desc()).first()
        decoy_type = latest_decoy.decoy_type if latest_decoy else "ssh"
        decoy_ip = latest_decoy.source_ip if latest_decoy else "172.24.0.1"

        # 4. Policy improvement
        latest_opt = db.query(PolicyImprovement).order_by(PolicyImprovement.timestamp.desc()).first()
        opt_method = latest_opt.method if latest_opt else "quantum"

        raw_steps = [
            {
                "step": 1,
                "title": "What the Network and its Digital Twin Are",
                "concept": "Digital Twin",
                "plain_text": "Imagine a live, interactive 3D blueprint of a city building, but for computers. CipherTwin keeps a real-time graph model of every laptop, database, and employee account. When any computer connects or sends data, the Digital Twin updates immediately so security teams can see the whole picture.",
                "live_example": f"Currently tracking {node_count} nodes (including {server_count} servers and workstations) connected in the graph.",
                "try_question": "What is the Digital Twin and how many devices are connected?",
            },
            {
                "step": 2,
                "title": "How the System Decides Who Gets In (Risk Score)",
                "concept": "Zero Trust Risk Score",
                "plain_text": "Rather than trusting anyone who has a password, CipherTwin calculates a dynamic 'Risk Score' from 0 to 100 for every single action. It checks five things: is the person who they claim to be? Is their laptop healthy and updated? Is their behavior normal? Is the file sensitive? Where are they logging in from?",
                "live_example": f"Most recent decision: Risk Score was {dec_score}/100, resulting in an automatic {dec_verdict} enforcement.",
                "try_question": "How was the most recent risk score calculated?",
            },
            {
                "step": 3,
                "title": "Why the System Explains its Decisions",
                "concept": "Explainability",
                "plain_text": "Nobody likes a computer that says 'Access Denied' without giving a reason. CipherTwin generates clear, plain-English explanations showing exactly which factors triggered the decision—like an unrecognized location or a missing security patch—so employees and auditors understand why.",
                "live_example": "Each decision produces a breakdown showing the exact percentage contribution of Identity, Device, Behavior, and Location.",
                "try_question": "Explain why the last decision was made in plain English.",
            },
            {
                "step": 4,
                "title": "What a Decoy is and Why Attackers Get Sent There",
                "concept": "Adaptive Deception",
                "plain_text": "When someone's risk score looks suspicious (between 30 and 60), we don't just kick them out—they would just try again with a different trick. Instead, CipherTwin quietly routes them into a 'decoy'—a realistic lure server with synthetic databases. The attacker thinks they succeeded, but they are trapped in a harmless room.",
                "live_example": f"Live Cowrie decoys are running on port 2222, emulating legitimate {decoy_type.upper()} servers.",
                "try_question": "Why was this session sent to a decoy?",
            },
            {
                "step": 5,
                "title": "What the System Learns from the Attacker",
                "concept": "Threat Intelligence",
                "plain_text": "Inside the decoy trap, we record every command, tool, and password the attacker types. We don't get hurt because the server is isolated, but we learn their exact playbook and automatically map their tools against global hacker encyclopedias like MITRE ATT&CK.",
                "live_example": f"Recorded interaction events from source IP {decoy_ip}, classifying behavior and mapping techniques like T1059 and T1110.",
                "try_question": "What tools and commands did attackers run in the honeypot?",
            },
            {
                "step": 6,
                "title": "How Policies Get Improved (Why Quantum?)",
                "concept": "Quantum-Assisted Policy Reoptimization",
                "plain_text": "Company security rules need regular tune-ups: if rules are too strict, real workers can't do their jobs; if too loose, hackers slip through. Finding the perfect balance across hundreds of rules is a huge math puzzle. CipherTwin uses quantum algorithms (QAOA) to search for optimal weights, comparing against classical computers to always choose the best result.",
                "live_example": f"Latest optimization used {opt_method} optimization to reweight access rules and allocate honeypot capacity.",
                "try_question": "Why did you use quantum optimization instead of classical?",
            },
            {
                "step": 7,
                "title": "The What-If Twin Forecast (Impact Preview)",
                "concept": "Twin Forecast",
                "plain_text": "Before security managers change a major rule—like forcing two-factor authentication or blocking an infected laptop—they can test it safely in a 'Twin Forecast'. It creates a private sandbox copy of the network to preview how many logins would be blocked and how much risk would drop, without touching the real system.",
                "live_example": "Runs reachability and risk re-scoring on an in-memory subgraph copy, guaranteeing 0 mutations to live databases.",
                "try_question": "What if device admin-workstation is compromised?",
            },
            {
                "step": 8,
                "title": "How to Ask Good Questions",
                "concept": "Conversation with CipherGuide",
                "plain_text": "You can ask CipherGuide anything in plain English! Try asking 'What happened today?', 'Why did you block Bob?', or 'What if we require MFA for all engineers?'. You can also toggle between Simple mode (with everyday analogies), Manager mode (business impact), and Analyst mode (forensic details).",
                "live_example": "Supports conversational exploration with high/medium/low confidence ratings and complete evidence receipts.",
                "try_question": "Give me a daily briefing of what happened across the network today.",
            },
        ]
        return [TourStep(**s) for s in raw_steps]
    finally:
        if close_at_end:
            db.close()


def get_tour_step(step_id: int, db: Optional[Session] = None) -> Optional[TourStep]:
    """Return a single tour step by step number (1-8)."""
    steps = get_all_tour_steps(db)
    for s in steps:
        if s.step == step_id:
            return s
    return None


get_tour_steps = get_all_tour_steps

