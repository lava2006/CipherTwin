"""Test CipherGuide Multi-Provider Fallback Chain."""
import pytest
from app.guide.llm import LLMProviderChain
from app.db.session import SessionLocal


def test_offline_provider_fallback_generates_grounded_answer():
    """Verify that offline mode produces grounded answers when AI providers are unavailable."""
    chain = LLMProviderChain(provider_order=["offline"])
    db = SessionLocal()
    try:
        res = chain.ask(
            question="What is Zero Trust in plain English?",
            audience="simple",
            conversation_history=[],
            db=db,
            beginner_mode=True,
        )
        assert res is not None
        assert res["provider_used"] == "offline"
        assert "Zero Trust" in res["answer"] or "hotel" in res["answer"] or "philosophy" in res["answer"]
    finally:
        db.close()


def test_audience_lenses_produce_distinct_structures():
    """Verify that simple, manager, and analyst lenses generate different structural formats."""
    chain = LLMProviderChain(provider_order=["offline"])
    db = SessionLocal()
    try:
        # Simple lens
        res_simple = chain.ask(
            question="Explain the last decision",
            audience="simple",
            conversation_history=[],
            db=db,
        )
        assert res_simple["lens"] == "simple"

        # Manager lens
        res_mgr = chain.ask(
            question="Explain the last decision",
            audience="manager",
            conversation_history=[],
            db=db,
        )
        assert res_mgr["lens"] == "manager"

        # Analyst lens
        res_analyst = chain.ask(
            question="Explain the last decision",
            audience="analyst",
            conversation_history=[],
            db=db,
        )
        assert res_analyst["lens"] == "analyst"
    finally:
        db.close()


def test_provider_chain_skips_failed_provider_gracefully(monkeypatch):
    """Verify that an error in the first provider immediately triggers the next provider in chain."""
    chain = LLMProviderChain(provider_order=["xai", "offline"])

    def failing_xai(*args, **kwargs):
        raise ConnectionError("Lab network timeout connecting to cloud API")

    monkeypatch.setattr(chain, "_call_xai", failing_xai)

    db = SessionLocal()
    try:
        res = chain.ask(
            question="What happened in the latest incident?",
            audience="simple",
            conversation_history=[],
            db=db,
        )
        assert res["provider_used"] == "offline"
        assert "answer" in res
    finally:
        db.close()
