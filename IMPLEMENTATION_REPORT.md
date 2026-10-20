# CipherTwin — Implementation Report: RabbitMQ Topic Exchange, Cowrie Bridge, Remote VM Ingestion

**Date:** 2026-10-20  
**Scope:** Parts A–D of the infrastructure enhancement plan  
**Environment:** WSL2 (Docker Desktop not integrated; live Docker-based verification not possible in this session)

---

## Executive Summary

All code changes for Parts A–D have been implemented and compile cleanly. Live Docker-based verification (PART A steps 1–6, PART B step 3, PART C live testing) could **not** be executed because Docker Desktop is not integrated with this WSL2 distro. A complete verification checklist is provided in Section 7 for the next session with Docker available.

---

## 1. Files Changed / Created

| File | Action | Purpose |
|------|--------|---------|
| `backend/app/core/config.py` | Modified | Added topic exchange, DLX, queue, routing key, ingest API key, rate limit, VM publisher, Cowrie bridge settings |
| `backend/app/schemas/telemetry_events.py` | Created | Pydantic v2 models: EDREvent, IAMEvent, NetFlowEvent, CowrieEvent; ROUTING_KEY_TO_MODEL registry |
| `backend/app/schemas/__init__.py` | Modified | Export new telemetry event models and ROUTING_KEY_TO_MODEL |
| `backend/app/services/rabbitmq_topology.py` | Created | Declares topic exchange `telemetry`, DLX `telemetry.dlx`, queue `twin.events`, bindings for `.edr/.iam/.netflow/.cowrie` |
| `backend/app/services/publisher.py` | Created | Publisher class with dedup, validation, live AMQP publish, in-memory buffer fallback |
| `backend/app/services/neo4j_client.py` | Modified | Added "Attacker" label, "INTERACTED_WITH" rel type, `merge_attacker_decoy_interaction()` |
| `backend/app/api/ingest.py` | Created | POST /ingest/edr, /iam, /netflow, /cowrie, /batch; X-API-Key auth, rate limiting, body/batch caps |
| `backend/app/api/twin.py` | Modified | Added GET /twin/summary, /twin/device/{id}, /twin/user/{id} |
| `backend/app/main.py` | Modified | Added GET /health/live and /api/health/live |
| `backend/app/api/__init__.py` | Modified | Register ingest router |
| `backend/deception/cowrie_bridge.py` | Created | Tails cowrie.json, persists offset, publishes to `telemetry.cowrie`, handles log rotation |
| `backend/deception/__init__.py` | Created | Package marker |
| `backend/Dockerfile.bridge` | Created | Docker image for cowrie-bridge service |
| `docker-compose.yml` | Modified | Added `cowrie-bridge` service on internal + DMZ networks |
| `backend/requirements.txt` | Modified | Added `requests` |
| `Makefile` | Created | `make test-all`, `test-unit`, `test-integration`, `test-e2e` targets |
| `tests/test_ingest.py` | Created | 13 tests: auth (401/422), valid events, batch limits, idempotency, live probe |

---

## 2. PART A — Backend Integration Audit (Documented)

Docker was unavailable; the following is the expected verification procedure and PASS/FAIL criteria.

| Check | Command | Expected Result | Status |
|-------|---------|-----------------|--------|
| A1. Stack comes up healthy | `docker compose up -d --build --wait` + `docker compose ps` | All 7 services (rabbitmq, neo4j, cowrie, cowrie-bridge, decoy-web, backend, frontend) show `healthy` | ⏳ Not verifiable (no Docker) |
| A2. Topic exchange exists | `rabbitmqctl list_exchanges` or `GET http://localhost:15672/api/exchanges/%2F` | Exchange `telemetry` of type `topic` present | ⏳ |
| A2b. DLX exists | Same API | Exchange `telemetry.dlx` of type `fanout` present | ⏳ |
| A2c. Queues declared | `GET /api/queues/%2F` | `twin.events`, `telemetry.dlq` present, durable | ⏳ |
| A2d. Bindings | `GET /api/bindings/%2F/e/%2F/telemetry` | 4 bindings: telemetry.edr, .iam, .netflow, .cowrie → twin.events | ⏳ |
| A2e. Consumer count | `GET /api/queues/%2F/twin.events` | `consumers >= 1` (twin consumer running) | ⏳ |
| A3. Valid event published+consumed | Publisher.publish("telemetry.edr", {...}) → process_one() → Neo4j | Queue depth returns to 0; Cypher node count +1 | ⏳ |
| A4. Malformed → DLQ | Publish invalid JSON to twin.events | Message lands in `telemetry.dlq`, acked from source | ⏳ |
| A4b. Dedup | Publish same event_id twice | Second publish returns "Duplicate dropped", graph count not doubled | ⏳ |
| A5. /health | `curl http://localhost:8000/health` | `{"status":"ok", ...}` | ⏳ |
| A5b. /health/live | `curl http://localhost:8000/health/live` | `{"status":"ok", ...}` | ⏳ |
| A5c. /twin/summary | `curl http://localhost:8000/api/twin/summary` | JSON with nodes, relationships, online, compromised counts | ⏳ |
| A5d. /twin/device/dev-01 | `curl http://localhost:8000/api/twin/device/dev-01` | Node + relationships JSON | ⏳ |
| A5e. /twin/user/user-01 | `curl http://localhost:8000/api/twin/user/user-01` | Node + relationships JSON | ⏳ |
| A5f. /twin/graph | `curl http://localhost:8000/api/twin/graph` | Graph payload from Neo4j | ⏳ |
| A5g. 404 case | `curl /api/twin/device/nonexistent` | HTTP 404 | ⏳ |
| A5h. 503 case | Stop neo4j → `curl /api/twin/graph` → restart | HTTP 503 while down, recovers after restart | ⏳ |
| A6. `make test-all` | `make test-all` | All tests pass | ⏳ |

---

## 3. PART B — Cowrie → RabbitMQ Bridge

### 3.1 Audit Finding (B1)

**Cowrie is NOT connected to RabbitMQ in the existing codebase.**

- The `cowrie` Docker service exists (ports 2222/2223) and writes JSON logs to `/cowrie/cowrie-git/var/log/cowrie/cowrie.json`.
- The backend's `CowrieService` reads that file directly via `ingest_logs_to_db()` into the `decoy_sessions` table.
- **There is no bridge publishing Cowrie events to RabbitMQ.** The `telemetry.cowrie` routing key did not exist.

### 3.2 Implementation (B2)

| Component | File | Details |
|-----------|------|---------|
| CowrieEvent schema | `backend/app/schemas/telemetry_events.py` | Fields: event_id, timestamp, session, src_ip, eventid, username, password_present (bool, no raw password), command, url, url_sha256, raw |
| ROUTING_KEY_TO_MODEL | `backend/app/schemas/telemetry_events.py` | Maps `telemetry.cowrie` → CowrieEvent, plus edr/iam/netflow |
| Cowrie bridge | `backend/deception/cowrie_bridge.py` | Tails cowrie.json, persists (inode, offset) in state file, survives rotation, publishes malformed-line-safe events to `telemetry.cowrie` |
| Bridge Docker service | `docker-compose.yml` + `Dockerfile.bridge` | `cowrie-bridge` container on internal + DMZ networks |
| Neo4j Attacker/Decoy | `backend/app/services/neo4j_client.py` | `merge_attacker_decoy_interaction(attacker_ip, decoy_id, session_id)` — MERGE-based, idempotent, increments count, tracks sessions |

### 3.3 Proof Procedure (B3)

From the host, run:
```bash
ssh -p 2222 root@localhost
# Try 3 bad passwords, then login, then: ls, wget http://example.com/x
```

Expected results:
- `cowrie.json` contains lines for `cowrie.session.connect`, `cowrie.login.failed` (x3), `cowrie.login.success`, `cowrie.command.input` (x2)
- RabbitMQ management API shows messages in `twin.events` with routing key `telemetry.cowrie`
- Neo4j Cypher:
  ```cypher
  MATCH (a:Attacker {ip: '127.0.0.1'})-[:INTERACTED_WITH]->(d:Decoy) RETURN a, d
  ```
  Returns 1 Attacker node, 1 Decoy node, 1 INTERACTED_WITH relationship with count >= 1.

Status: ⏳ Not verifiable (no Docker).

---

## 4. PART C — Remote VM Ingestion

### 4.1 HTTP Ingest Endpoints (C1)

| Endpoint | Method | Auth | Routing Key | Validation |
|----------|--------|------|-------------|------------|
| `/ingest/edr` | POST | X-API-Key | `telemetry.edr` | EDREvent model |
| `/ingest/iam` | POST | X-API-Key | `telemetry.iam` | IAMEvent model |
| `/ingest/netflow` | POST | X-API-Key | `telemetry.netflow` | NetFlowEvent model |
| `/ingest/cowrie` | POST | X-API-Key | `telemetry.cowrie` | CowrieEvent model |
| `/ingest/batch` | POST | X-API-Key | per-event route | List of typed events, max 100 |
| `/ingest/health/live` | GET | None | — | Liveness probe |

Security:
- `INGEST_API_KEY` required (no default); server refuses to start ingest if unset
- Rate limit: 60 requests/minute per API key (fixed window)
- Body cap: 1 MB; batch cap: 100 events
- 401 for bad/missing key, 422 for invalid payload, 429 for rate limit, 413 for oversized body
- Unknown devices/users/resources are MERGEd as new nodes (never rejected)

### 4.2 Direct AMQP Path (C2)

- Dedicated RabbitMQ user `vm_publisher` with write-only permission on exchange `telemetry` (no configure/read)
- `guest/guest` remains local-only (default RabbitMQ behavior)
- Documented in `tools/vm_agent.py` and Section 6 below

### 4.3 Remote Agent (C3)

`tools/vm_agent.py` — stdlib + `requests` only:
- Reads `/var/log/auth.log` (or `journalctl -u ssh`) → IAMEvent
- Reads `/proc/net/tcp` and `/proc/net/tcp6` → NetFlowEvent
- Reads `ps -eo pid,ppid,user,comm,args` → EDREvent
- `device_id` from hostname (`--device-id` or `HOSTNAME` env)
- Timestamps in UTC
- Batches every `--interval` seconds (default 5)
- Retries with fixed interval on transient failure
- `--once --dry-run` prints JSON without sending

### 4.4 Networking (C4)

**Ports to open on the twin host (restricted to the remote VM's IP):**

| Port | Service | Source | Command (ufw) |
|------|---------|--------|---------------|
| 8000/tcp | FastAPI ingest API | Remote VM IP | `ufw allow from <VM_IP> to any port 8000` |
| 5672/tcp | RabbitMQ AMQP (optional, direct path) | Remote VM IP | `ufw allow from <VM_IP> to any port 5672` |
| 2222/tcp | Cowrie honeypot (optional) | Any (honeypot) | Already exposed on 127.0.0.1 only |

**Finding the host IP the VM should use:**
- Bridged adapter: `ip addr show eth0` on the host → use that IP
- NAT: Host is reachable via the NAT gateway (often `10.0.2.2` or `192.168.1.1`)
- Host-only: Host's host-only adapter IP

**Copy-paste test commands from the other VM:**

```bash
# 1. Connectivity
curl -i http://<TWIN_HOST>:8000/ingest/health/live

# 2. Valid event
curl -i -X POST http://<TWIN_HOST>:8000/ingest/iam \
  -H "Content-Type: application/json" \
  -H "X-API-Key: <INGEST_API_KEY>" \
  -d '{"event_id":"evt-vm-1","timestamp":"2026-01-01T00:00:00Z","device_id":"vm-01","event_type":"ssh_failed","username":"root","src_ip":"10.0.0.5","success":false}'

# 3. Invalid event (expect 422)
curl -i -X POST http://<TWIN_HOST>:8000/ingest/iam \
  -H "X-API-Key: <INGEST_API_KEY>" \
  -d '{"event_id":"evt-bad"}'  # missing required fields

# 4. Wrong key (expect 401)
curl -i -X POST http://<TWIN_HOST>:8000/ingest/iam \
  -H "X-API-Key: wrong-key" \
  -d '{"event_id":"evt-bad2","timestamp":"2026-01-01T00:00:00Z","device_id":"vm-01","event_type":"ssh_failed"}'

# 5. Generate real activity + run agent
ssh vm-01  # failed logins
nc -z <other-host> 443  # network flow
python3 tools/vm_agent.py --once --dry-run --url http://<TWIN_HOST>:8000 --api-key <KEY> --device-id vm-01

# 6. Verify on host
curl http://localhost:8000/api/twin/device/vm-01
# Cypher: MATCH (d:Device {id:'vm-01'})-[:CONNECTED_TO]->(o) RETURN d, o
```

### 4.5 Ingest Tests (C4)

`tests/test_ingest.py` — 13 tests covering:
- 401 on missing/wrong API key
- 202 on valid edr/iam/netflow/cowrie events
- 422 on invalid payloads
- Batch accepted/rejected counts
- Batch size limit (422 when > 100)
- Idempotent resend (duplicate dropped)
- `/ingest/health/live` liveness probe

Status: Code written; tests not yet runnable (no Python packages installed in this environment).

---

## 5. PART D — Still Unverified

The following require Docker + live services and **could not be executed** in this session:

1. **Full stack startup** — `docker compose up -d --build --wait`; all services healthy
2. **RabbitMQ topology verification** — exchange `telemetry` (topic), DLX, queues, bindings, consumer count
3. **End-to-end event flow** — publish → consume → Neo4j graph write
4. **Malformed message → DLQ** verification
5. **Dedup by event_id** verification
6. **Cowrie bridge live test** — SSH into honeypot, verify events in RabbitMQ and Neo4j
7. **Remote VM ingest** — run `vm_agent.py` from another VM, verify device node in Neo4j
8. **`make test-all`** — full test suite execution

**5-line checklist for the next session (with Docker):**
```
1. docker compose up -d --build --wait && docker compose ps  (all healthy)
2. curl http://localhost:15672/api/exchanges/%2F  (verify telemetry topic exchange + 4 bindings)
3. python3 -m pytest tests/ -q  (all tests pass, including new test_ingest.py)
4. ssh -p 2222 root@localhost  (3 bad pw, login, ls, wget) → verify cowrie.json + RabbitMQ + Neo4j
5. From other VM: run vm_agent.py → curl localhost:8000/api/twin/device/<hostname> → verify in Neo4j
```

---

## 6. Security Notes

| Item | Recommendation |
|------|---------------|
| Default credentials | `RABBITMQ_USER/PASSWORD`, `NEO4J_PASSWORD`, `INGEST_API_KEY` must be changed from `.env.example` placeholders |
| INGEST_API_KEY | No default; server logs error if unset at startup. Rotate regularly. |
| Ports exposed | 8000 (FastAPI), 5672 (AMQP), 15672 (management), 2222/2223 (Cowrie), 8081 (decoy web) — all bound to 127.0.0.1 except Cowrie |
| Cowrie isolation | Runs on `ciphertwin-dmz` network; no production credentials or host paths mounted |
| Password handling | Cowrie bridge stores `password_present` boolean only — raw passwords never leave the honeypot |
| VM publisher | Write-only on `telemetry` exchange; no configure/read permissions |
| Rate limiting | 60 req/min per API key prevents ingestion-based DoS |

---

## 7. README and CLAUDE.md Updates

README.md and CLAUDE.md should be updated to document:
- New `/ingest/*` endpoints and `INGEST_API_KEY` requirement
- Cowrie bridge service and `telemetry.cowrie` routing key
- Topic exchange topology (`telemetry`, `telemetry.dlx`, `twin.events`)
- `vm_agent.py` usage for remote VM telemetry
- Updated data-flow diagram including Cowrie → RabbitMQ → twin-consumer → Neo4j

These updates are ready to be applied in the next session once live verification confirms the implementation.
