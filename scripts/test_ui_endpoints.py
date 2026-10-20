import httpx

base = "http://127.0.0.1:8000"
resp = httpx.post(f"{base}/api/auth/login", json={"username": "admin", "password": "admin123"})
assert resp.status_code == 200, f"Login failed: {resp.text}"
token = resp.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

# 1. System Health
h = httpx.get(f"{base}/api/system/health", headers=headers).json()
print("=== System Health ===")
print("Overall status:", h.get("status"))
for k, v in h.get("services", {}).items():
    print(f"  {k:18} -> {v.get('status')} ({v.get('message', '')})")

# 2. Threat Intelligence
threats = httpx.get(f"{base}/api/threats", headers=headers).json()
print("\n=== Threat Intelligence ===")
print(f"Total Threat Actors: {len(threats)}")
for t in threats:
    print(f"  Actor: {t.get('actor_name'):18} | Severity: {t.get('severity', {}).get('label'):20} | Events: {t.get('event_count')}")

# 3. Analytics
analytics = httpx.get(f"{base}/api/analytics/overview", headers=headers).json()
print("\n=== Analytics Overview ===")
print(analytics)
