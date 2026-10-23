# Remaining Implementation Plan for CipherTwinGuide (Accelerated Execution)

## Tasks to Complete (Fast Track)
1. **Frontend UI Integration**
   - Add `CipherTwinGuide.tsx` component under `frontend/src/components/Guide/`.
   - Include role selector (dropdown) populated from `backend/app/guide/persona.ROLES`.
   - Include style selector (dropdown) from `backend/app/guide/persona.STYLES`.
   - Chat thread UI with sections for **Verified**, **Explanation**, **Recommendation**, **Simulated**, **Unavailable**.
   - Persist selected role/style in `localStorage` (`ct_guide_role`, `ct_guide_style`).
   - Wire up API calls to `/api/guide/ask` using existing `api` utility.
   - Add a launch button in `DashboardLayout.tsx` (e.g., a pill with Shield icon).
   - Ensure responsive design, keyboard operable, no new UI libs.

2. **Documentation Updates**
   - Update `README.md` with a "CipherTwinGuide" section describing usage and UI.
   - Add placeholders in `.env.example` for any new env vars (none needed currently).

3. **Testing**
   - Add tests for `ContextBuilder` (verify secret redaction, truncation, intent detection). 
   - Add end‑to‑end test for the new frontend component using Playwright (light check for rendering). 
   - Run full test suite (`pytest -q`) to ensure existing 121 tests still pass.

4. **Final Verification**
   - Manual sanity check: start backend, frontend, and ensure the guide panel works, falls back to offline mode when Ollama is unavailable.
   - Verify no regression: existing dashboards, routes, and metrics unchanged.

## Execution Strategy (Accelerated)
- **Parallel Subagents**: Launch a subagent (`self`) to implement the frontend component while the main agent finalizes docs and runs tests.
- **Background Tasks**: Use the `run_command` tool to start the Vite dev server and FastAPI backend after code changes, then run tests.
- **Artifact Tracking**: All new files will be created in the workspace; updates are logged.

All steps will be performed sequentially with minimal waiting.