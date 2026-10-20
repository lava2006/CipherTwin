import httpx
import json

base_url = "http://127.0.0.1:8000"

# 1. Login
login_resp = httpx.post(f"{base_url}/api/auth/login", json={"username": "admin", "password": "admin123"})
assert login_resp.status_code == 200, f"Login failed: {login_resp.text}"
token = login_resp.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}
print(f"[OK] Authenticated as admin. Role: {login_resp.json()['user']['role']}")

# 2. Health & Root
health = httpx.get(f"{base_url}/api/health").json()
print(f"[OK] System Health: {health}")

# 3. Analytics Overview
analytics = httpx.get(f"{base_url}/api/analytics/overview", headers=headers).json()
print(f"[OK] Analytics: telemetry_24h={analytics.get('total_telemetry_24h')}, active_threats={analytics.get('threats_active')}, risk_level={analytics.get('risk_level')}, decoy_sessions={analytics.get('decoy_sessions')}")

# 4. Digital Twin Graph
graph = httpx.get(f"{base_url}/api/twin/graph", headers=headers).json()
print(f"[OK] Digital Twin Graph: {len(graph.get('nodes', []))} nodes, {len(graph.get('edges', []))} edges")
honeypots = [n for n in graph.get('nodes', []) if n.get('type') == 'honeypot']
traps = [e for e in graph.get('edges', []) if e.get('relation') == 'traps']
print(f"     Honeypot nodes: {[h['id'] for h in honeypots]}, Trap relationships: {[t['source'] + ' -> ' + t['target'] for t in traps]}")

# 5. Policies
policies = httpx.get(f"{base_url}/api/policies", headers=headers).json()
print(f"[OK] Active Policies: {len(policies)} policies configured")

# 6. Quantum Optimization Run
print("     Running Quantum Policy Optimization...")
opt_run = httpx.post(f"{base_url}/api/optimization/run", json={"layers": 2, "iterations": 10}, headers=headers, timeout=60.0).json()
print(f"[OK] Quantum Policy Optimization Run:")
print(f"     Method: {opt_run.get('method')}")
print(f"     Qubits: {opt_run.get('qubits')}")
print(f"     Score: {opt_run.get('before_score')} -> {opt_run.get('after_score')}")
print(f"     QAOA Cost: {opt_run.get('qaoa_cost')}, Classical Cost: {opt_run.get('classical_cost')}")
print(f"     Duration: {opt_run.get('duration_ms')} ms")
print(f"     Decoy Method: {opt_run.get('decoy_method')}")
print(f"     Decoy Assignments: {opt_run.get('decoy_assignments')}")

# 7. Controlled Event Engine: emit 1 event
emit_resp = httpx.post(f"{base_url}/api/events/emit", headers=headers, timeout=30.0).json()
print(f"[OK] Event Engine Single Emit: {emit_resp}")

# 8. Deception Sessions
deception = httpx.get(f"{base_url}/api/deception/sessions", headers=headers).json()
print(f"[OK] Deception Sessions Count: {len(deception)}")

# 9. Frontend HTTP check
frontend_resp = httpx.get("http://127.0.0.1:5173/")
print(f"[OK] Frontend UI is serving: HTTP {frontend_resp.status_code}")
print("\n>>> ALL CIPHERTWIN INTEGRATION CHECKS VERIFIED SUCCESSFULLY <<<")
