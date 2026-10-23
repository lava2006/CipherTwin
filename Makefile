# CipherTwin Makefile

.PHONY: test-all test-unit test-integration test-e2e lint format feed demo-guide guide-smoke

TEST_DIR := tests
BACKEND_DIR := backend

PYTHON ?= python3
PIP ?= pip3

test-all: test-unit test-integration test-e2e

test-unit:
	@$(PYTHON) -m pytest $(TEST_DIR) -q -m "unit" || $(PYTHON) -m pytest $(TEST_DIR) -q

test-integration:
	@$(PYTHON) -m pytest $(TEST_DIR) -q -m "integration" || $(PYTHON) -m pytest $(TEST_DIR) -q -k "integration"

test-e2e:
	@$(PYTHON) -m pytest $(TEST_DIR) -q -m "e2e" || $(PYTHON) -m pytest $(TEST_DIR) -q -k "e2e"

feed:
	@cd $(BACKEND_DIR) && $(PYTHON) -c "from app.db.session import SessionLocal; from app.workers.telemetry_generator import TelemetryGenerator; gen = TelemetryGenerator(SessionLocal()); print('Generated telemetry feed event:', gen.generate_one())"

demo-guide:
	@$(PYTHON) scripts/demo_guide.py

guide-smoke:
	@cd $(BACKEND_DIR) && $(PYTHON) -c "from app.guide.llm import test_providers_smoke; test_providers_smoke()"

lint:
	@$(PYTHON) -m ruff check $(BACKEND_DIR) $(TEST_DIR) 2>/dev/null || $(PYTHON) -m py_compile $(BACKEND_DIR)/app/**/*.py

format:
	@$(PYTHON) -m ruff format $(BACKEND_DIR) $(TEST_DIR) 2>/dev/null || echo "ruff not available, skipping format"

install-deps:
	@$(PIP) install -r $(BACKEND_DIR)/requirements.txt
