# CipherTwin Changes Log

This document tracks all modifications made to existing modules during the implementation of CipherGuide.

## Initial Baseline Checkpoint
- Tag `before-cipherguide` created on branch `feature/cipherguide`.
- Full test suite verified passing (98 passed, 9 skipped).

## Modified Files Registry

| File | Nature of Change | Purpose | Backward Compatible |
| :--- | :--- | :--- | :--- |
| `backend/app/workers/telemetry_generator.py` | Renamed from `telemetry_simulator.py` | Terminology cleanup per global rule 2 | Yes (Alias provided) |
| `backend/app/core/config.py` | Added LLM provider configs (`llm_provider_order`, `xai_*`, `ollama_*`), `enable_telemetry_feed` | Support CipherGuide multi-provider LLM chain | Yes |
| `backend/app/api/__init__.py` | Registered `guide.router` | Mount `/api/guide` endpoints onto FastAPI | Yes |
| `backend/app/api/policies.py` | Added `/forecast` route and aliases | Terminology compliance for what-if policy forecast | Yes |
| `backend/app/main.py` | Cleaned terminology in comments & OpenAPI description | Terminology compliance per global rule 1 | Yes |
| `backend/app/schemas/policy.py` | Added `PolicyForecastIn`, `PolicyForecastOut` | Terminology compliance for what-if policy forecast | Yes |
| `backend/requirements.txt` | Added `openai>=1.0.0` | Enable OpenAI-compatible client for Grok/Groq and Ollama | Yes |
| `Makefile` | Added `feed`, `demo-guide`, `guide-smoke` targets | Terminology compliance and automated guide testing | Yes |
| `.env.example` | Added CipherGuide LLM configuration placeholders | Guide deployment documentation | Yes |
| `dashboard/app.py` | Added beginner callout and links to CipherGuide, Tour, and Glossary | Improve beginner navigation from analyst console | Yes |
| `tests/test_qaoa_optimizer.py` | Updated assertions and terminology | Test stability and terminology compliance | Yes |
| `tests/test_rabbitmq_pipeline.py` | Renamed test helper function | Terminology compliance (`mock` removal) | Yes |
| `tests/test_policies_and_feedback.py` | Renamed test and comments to forecast | Terminology compliance (`simulation` removal) | Yes |
| `tests/test_system_health_and_audit.py` | Renamed test function | Terminology compliance (`fake` removal) | Yes |
| `README.md` | Added CipherGuide documentation and cleaned terminology | Project documentation | Yes |

## Newly Added Files
- `backend/app/api/guide.py` (FastAPI router)
- `backend/app/guide/__init__.py`
- `backend/app/guide/glossary.py` (15+ term beginner glossary with analogies)
- `backend/app/guide/prompts.py` (anti-injection, lenses, offline templates)
- `backend/app/guide/forecast.py` (in-memory Twin Forecast engine)
- `backend/app/guide/tour.py` (8-step guided tour enriched with live metrics)
- `backend/app/guide/tools.py` (grounded tool execution registry)
- `backend/app/guide/llm.py` (multi-provider chain: Grok/Groq ➔ Ollama ➔ Offline)
- `backend/app/guide/service.py` (conversational orchestrator, guarded actions, reports)
- `dashboard/pages/1_🛡️_CipherGuide.py` (Streamlit assistant UI)
- `dashboard/pages/2_🧭_Guided_Tour.py` (Streamlit 8-step tour UI)
- `dashboard/pages/3_📖_Glossary.py` (Streamlit glossary UI)
- `scripts/demo_guide.py` (End-to-end walkthrough demonstration script)
- `docs/DEMO.md` (3-minute and 1-minute presentation scripts)
- `tests/test_guide_anti_injection.py`
- `tests/test_guide_forecast_isolation.py`
- `tests/test_guide_guarded_actions.py`
- `tests/test_guide_provider_chain.py`
- `tests/test_guide_tools_grounding.py`
