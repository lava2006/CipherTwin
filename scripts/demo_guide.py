"""CipherGuide End-to-End Walkthrough Demonstration.

Executes a live showcase of CipherGuide capabilities:
1. Guided Tour overview with live network metrics
2. Audience Lens comparisons (Simple, Manager, Analyst)
3. Grounded Trust Receipts & Confidence Scoring
4. Twin Forecast (Impact Preview) with zero live graph mutations
5. Deception telemetry from Cowrie decoys & MITRE ATT&CK mapping
6. Quantum vs. Classical solver honesty (QAOA vs. SciPy)
7. Guarded Action staging and confirmation workflow
8. Markdown incident briefing report generation
"""
import json
import sys
import os

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure backend directory is in path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

from app.db.session import SessionLocal
from app.guide.service import get_guide_service
from app.guide.tour import get_all_tour_steps
from app.guide.forecast import run_twin_forecast
from app.guide.tools import tool_registry


def print_banner(title: str):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def run_demo():
    print_banner("1. CIPHERGUIDE GUIDED TOUR PREVIEW")
    db = SessionLocal()
    try:
        steps = get_all_tour_steps(db)
        print(f"Loaded {len(steps)} progressive onboarding steps for beginners:")
        for s in steps[:3]:
            print(f"  * Step {s.step}: {s.title} [{s.concept}]")
            print(f"    Live Metric: {s.live_example}")

        print_banner("2. AUDIENCE LENSES DEMONSTRATION")
        guide = get_guide_service()
        question = "Why was the last access request redirected to a decoy?"

        print(f"Question: \"{question}\"")
        for lens in ["simple", "manager", "analyst"]:
            print(f"\n--- Lens: {lens.upper()} ---")
            res = guide.ask(question=question, lens=lens, beginner_mode=(lens == "simple"), db=db)
            answer_snippet = res["answer"][:280] + "..." if len(res["answer"]) > 280 else res["answer"]
            print(answer_snippet)

        print_banner("3. GROUNDED TRUST RECEIPT & CONFIDENCE")
        dec_res = tool_registry.execute("get_decision", db=db)
        print("Retrieved Forensic Evidence:")
        print(f"  * Found: {dec_res.get('found')}")
        print(f"  * Confidence: {dec_res.get('confidence')}")
        if dec_res.get("found"):
            ev = dec_res.get("evidence", {})
            print(f"  * Decision ID: {ev.get('id')}")
            print(f"  * Risk Score: {ev.get('risk_score')} / 100")
            print(f"  * Action Enforced: {ev.get('decision')}")

        print_banner("4. TWIN FORECAST (IMPACT PREVIEW - ZERO MUTATIONS)")
        fc = run_twin_forecast(db, change_type="require_mfa", target="finance")
        print(f"Evaluated Scenario: {fc['headline']}")
        print(f"  * Risk Before: {fc['before_average_risk']} ➔ After: {fc['after_average_risk']} (Delta: {fc['risk_delta']})")
        print(f"  * Policy Flips: {fc['flips_count']} requests affected")
        print(f"  * Live Database Isolation: {'VERIFIED - 0 MUTATIONS' if fc['isolation_verified'] else 'FAILED'}")

        print_banner("5. HONEST QUANTUM VS. CLASSICAL SOLVER COMPARISON")
        solv = tool_registry.execute("solver_comparison", db=db)
        ev_solv = solv.get("evidence", {})
        print(f"Outcome: {ev_solv.get('winner')}")
        print(f"  * QAOA (lightning.qubit): Cost = {ev_solv.get('qaoa_cost')} | Runtime = {ev_solv.get('quantum_ms')} ms")
        print(f"  * Classical SciPy: Cost = {ev_solv.get('classical_cost')} | Runtime = {ev_solv.get('classical_ms')} ms")
        print(f"  * Decoys Assigned: {ev_solv.get('decoys_allocated')}")
        print(f"  * Honest Assessment: {ev_solv.get('assessment')}")

        print_banner("6. GUARDED ACTIONS WORKFLOW")
        prop = guide.ask(question="Propose blocking device laptop-alice-01", lens="analyst", db=db)
        act = prop.get("proposed_action")
        if act:
            print(f"Action Proposed: {act.get('action_type')} on target {act.get('target')}")
            print(f"Status: {act.get('status')}")
            print("Confirming action explicitly with analyst credentials...")
            conf = guide.confirm_action(action_id=act["action_id"], db=db, confirmed=True)
            print(f"Confirmation Result: {conf.get('status')} - {conf.get('message')}")

        print_banner("7. INCIDENT REPORT BRIEFING")
        report = guide.generate_incident_report("inc-demo-99")
        print("Generated Markdown Report Snippet:")
        for line in report.splitlines()[:12]:
            print("  " + line)

        print("\n" + "=" * 70)
        print("  CIPHERGUIDE DEMO COMPLETED SUCCESSFULLY")
        print("=" * 70)
    finally:
        db.close()


if __name__ == "__main__":
    run_demo()
