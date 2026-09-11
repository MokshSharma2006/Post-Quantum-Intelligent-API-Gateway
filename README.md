# Post-Quantum AI-Powered API Gateway

A modular cybersecurity capstone project that combines **post-quantum
cryptography, API gateway security, rate limiting, deterministic payload
inspection, AI-based anomaly detection, ZeroMQ messaging, security-event
logging, and a real-time dashboard**.

## 1. Project Overview

The Post-Quantum AI-Powered API Gateway is a security proxy placed
between API clients and a backend service.

``` text
Client
  |
  v
+-------------------------------+
|  C++ API Gateway              |
|-------------------------------|
|  PQC Handshake                |
|  AI Client Blocklist          |
|  Synchronous Security Filter  |
|  Token Bucket Rate Limiter    |
|  Request Metrics              |
|  Security Event Log           |
+---------------+---------------+
                |
                | ZeroMQ
                v
+-------------------------------+
|  Python AI Security Engine    |
|-------------------------------|
|  Behavioral Features          |
|  Payload Inspection            |
|  Threat Scoring                |
|  NORMAL / SUSPICIOUS /         |
|  MALICIOUS Classification      |
|  Optional Gemini Analysis      |
+---------------+---------------+
                |
                v
          Backend API

Dashboard <---- /metrics, /health, /events
```

The gateway can detect and block obvious attacks synchronously, regulate
request bursts, send request-security metadata to the Python engine,
receive AI decisions, and expose security telemetry to the dashboard.

## 2. Main Technologies

  Component                 Technology
  ------------------------- -----------------------
  Gateway                   C++
  HTTP framework            Crow
  Cryptography              liboqs
  Key encapsulation         ML-KEM-768
  Digital signature         ML-DSA-65
  Traffic control           Token Bucket
  AI/security engine        Python
  Messaging                 ZeroMQ
  Backend                   Flask
  Dashboard                 HTML, CSS, JavaScript
  Charts                    Chart.js
  HTTP client               libcurl
  Build system              CMake + Ninja
  Development environment   WSL2 Ubuntu

## 3. Implemented Security Features

### Post-Quantum Cryptography

-   ML-KEM-768 key generation
-   ML-KEM-768 encapsulation/decapsulation
-   Shared-secret verification
-   ML-DSA-65 key generation
-   ML-DSA-65 signing and verification

### Gateway Protection

-   Per-client token-bucket rate limiting
-   Synchronous payload pre-filter
-   AI-generated client blocklist
-   CORS support
-   Request metrics
-   Security event logging

### Attack Detection

The deterministic pre-filter currently detects patterns associated
with: - SQL injection - Command injection - Path traversal - Script
injection

The Python security engine additionally evaluates: - Request bursts -
Request frequency - Requests per second - Unknown endpoints - Unknown
methods - Repeated endpoint behavior - SQL injection indicators -
Command injection indicators - Path traversal indicators -
Authentication-related indicators - Script injection indicators -
Oversized payloads

### AI Security Engine

The AI engine classifies requests into: - `NORMAL` - `SUSPICIOUS` -
`MALICIOUS`

Actions are: - `ALLOW` - `MONITOR` - `BLOCK`

The deterministic security engine remains the enforcement authority.
Optional Gemini analysis provides additional contextual analysis for
suspicious/malicious requests when configured.

### Security Event Log

The gateway stores the latest 100 security events in memory.

Events include: - timestamp - client IP - endpoint - event type -
action - attack type

Endpoint:

``` text
GET /events
```

### Dashboard

The dashboard displays: - gateway status - request metrics -
allowed/blocked requests - requests per second - AI
normal/suspicious/malicious counts - latest AI decision - AI
explanation - payload score - payload indicators - currently blocked
clients - traffic charts - threat distribution - security component
status - real-time security events

## 4. Request Processing Flow

A normal request follows:

``` text
Client
  |
  v
AI blocklist check
  |
  v
Synchronous security pre-filter
  |
  v
Request sanitization
  |
  v
ZeroMQ -> Python AI Engine
  |
  v
Token Bucket Rate Limiter
  |
  v
Backend API
  |
  v
Client
```

A request can be stopped before reaching the backend by the AI
blocklist, pre-filter, or rate limiter.

AI decisions are asynchronous. Therefore, the first request that causes
an AI block decision may already have been forwarded before the
asynchronous decision reaches the gateway; subsequent requests from the
blocked client are denied.

## 5. Project Structure

``` text
post-quantum-api-gateway/
├── ai/
│   └── security_engine.py
├── backend/
│   └── app.py
├── dashboard/
│   └── index.html
├── gateway/
│   ├── include/
│   │   ├── ai_decision_receiver.hpp
│   │   ├── ai_enforcement.hpp
│   │   ├── pqc_manager.hpp
│   │   ├── rate_limiter.hpp
│   │   ├── security_event_log.hpp
│   │   ├── security_metrics.hpp
│   │   ├── token_bucket.hpp
│   │   └── zmq_client.hpp
│   ├── src/
│   │   └── main.cpp
│   ├── CMakeLists.txt
│   └── build/
├── tests/
├── docs/
└── README.md
```

Build artifacts, Python environments, secrets, logs, and Windows
metadata are excluded through `.gitignore`.

## 6. Requirements

Recommended environment:

-   Ubuntu under WSL2
-   C++ compiler with C++17 support
-   CMake
-   Ninja
-   Python 3
-   ZeroMQ development libraries
-   libcurl development libraries
-   OpenSSL development libraries
-   Crow
-   liboqs

## 7. Build

``` bash
cd ~/post-quantum-api-gateway

rm -rf gateway/build

cmake -S gateway -B gateway/build -GNinja

cmake --build gateway/build
```

The gateway executable is produced in:

``` text
gateway/build/gateway
```

## 8. Run the System

### Terminal 1 --- Backend

``` bash
cd ~/post-quantum-api-gateway
source .venv/bin/activate
python3 backend/app.py
```

Backend:

``` text
http://127.0.0.1:5000
```

### Terminal 2 --- AI Security Engine

``` bash
cd ~/post-quantum-api-gateway
source .venv/bin/activate
python3 ai/security_engine.py
```

The AI engine uses:

``` text
Input  : tcp://127.0.0.1:5555
Output : tcp://127.0.0.1:5556
```

### Terminal 3 --- Gateway

``` bash
cd ~/post-quantum-api-gateway
./gateway/build/gateway
```

Gateway:

``` text
http://localhost:8080
```

### Terminal 4 --- Dashboard

``` bash
cd ~/post-quantum-api-gateway
python3 -m http.server 3000 --directory dashboard --bind 0.0.0.0
```

Dashboard:

``` text
http://localhost:3000
```

## 9. API Endpoints

### Gateway root

``` text
GET /
```

Returns gateway service and enabled security components.

### Health

``` text
GET /health
```

Checks gateway/backend security-service status.

### Metrics

``` text
GET /metrics
```

Returns request, rate-limiter, AI, payload, and security metrics.

### Events

``` text
GET /events
```

Returns the latest security events.

### Reset

``` text
POST /metrics/reset
```

Resets: - request metrics - rate limiter state - AI enforcement state -
security event log

### Backend hello

``` text
GET /api/hello
```

Proxies a normal request to the backend.

### Backend data

``` text
GET /api/data
POST /api/data
```

Used for normal API traffic and security-payload testing.

### PQC information/handshake

The gateway also exposes the implemented post-quantum demonstration
endpoints used to validate the ML-KEM/ML-DSA component.

## 10. Security Testing

### Normal request

``` bash
curl -i http://localhost:8080/api/hello
```

Expected:

``` text
HTTP/1.1 200 OK
```

### SQL injection pre-filter

``` bash
curl -i -X POST http://localhost:8080/api/data \
-H "Content-Type: application/json" \
-d "{\"query\":\"' OR 1=1 --\"}"
```

Expected:

``` text
HTTP/1.1 403 Forbidden
```

and:

``` text
Request blocked by gateway pre-filter: SQL_INJECTION
```

### Command injection

``` bash
curl -i -X POST http://localhost:8080/api/data \
-H "Content-Type: application/json" \
-d "{\"query\":\"; cat /etc/shadow\",\"action\":\"search\"}"
```

This is detected by the payload security engine and classified as
malicious.

### Rate-limit test

``` bash
for i in {1..30}; do
    curl -s -o /dev/null -w "%{http_code}\n" \
    http://localhost:8080/api/hello
done
```

The expected result is a mixture of:

``` text
200
429
```

The `429` responses demonstrate rate limiting.

### Event log

``` bash
curl -s http://localhost:8080/events
```

Example structure:

``` json
{
  "events": [
    {
      "timestamp": "16:30:46",
      "client_ip": "127.0.0.1",
      "endpoint": "/api/data",
      "event_type": "PRE_FILTER_BLOCK",
      "action": "BLOCK",
      "attack_type": "SQL_INJECTION"
    }
  ],
  "count": 1
}
```

## 11. AI Decision Model

The Python engine combines behavioral and payload indicators into a
score.

Conceptually:

``` text
Behavior score
      +
Payload score
      |
      v
Final threat score
      |
      +---- < 30 ----> NORMAL ----> ALLOW
      |
      +---- 30-69 ---> SUSPICIOUS -> MONITOR
      |
      +---- >= 70 ---> MALICIOUS -> BLOCK
```

A sufficiently strong payload indicator can also directly cause a
malicious/block decision.

## 12. AI Explainability

The dashboard displays deterministic explanations such as:

``` text
Risk score: 40/100.
Evidence: Command injection pattern detected
(payload score contribution).
The request was classified as MALICIOUS and BLOCKED.
```

This makes the AI/security decision understandable during demonstration
and evaluation.

## 13. Sensitive Data Handling

The AI engine sanitizes request bodies before analysis and redacts
sensitive fields such as: - password - passwd - secret - token - API
key - authorization - access token - refresh token - cookie

The body sent for analysis is also size-limited.

## 14. Metrics

Important gateway metrics include:

``` text
total_requests
allowed_requests
blocked_requests
requests_per_second

ai_total_decisions
ai_normal
ai_suspicious
ai_malicious
ai_block_decisions
ai_blocked_clients

ai_last_score
ai_last_threat
ai_last_action

payload_score
payload_indicators
llm_provider
llm_enabled
llm_explanation
llm_confidence
llm_severity
llm_attack_type
llm_recommendation
```

## 15. Verified Results

The current implementation has been manually validated for:

-   successful gateway-to-backend proxying
-   ML-KEM-768 encapsulation/decapsulation
-   shared-secret matching
-   ML-DSA-65 signing/verification
-   normal request allowance
-   SQL injection pre-filter blocking
-   command injection detection
-   path traversal detection
-   rate limiting with HTTP 429 responses
-   AI malicious classification
-   AI-generated client blocking
-   event logging
-   event-log reset
-   metrics reset
-   dashboard live updates
-   deterministic AI explanations

## 16. Important Scope Clarification

This project demonstrates a **post-quantum security architecture**, but
the local gateway's ML-KEM/ML-DSA implementation is a working
cryptographic handshake/authentication demonstration rather than a
complete replacement for TLS across every HTTP byte.

Similarly, the current AI enforcement uses an in-process gateway
blocklist. It does not currently install operating-system firewall
rules.

The optional Gemini component is integrated but can operate in disabled
mode when no API credential is configured. The deterministic security
engine remains usable without an external LLM.

## 17. Current Limitations

-   Security state is in memory and is lost when the gateway restarts.
-   Event logs are in memory and limited to the latest 100 events.
-   AI decisions are asynchronous.
-   The first malicious request can potentially be forwarded before the
    AI decision returns.
-   No persistent database/Redis layer is used in the current local
    gateway.
-   No production TLS termination is included.
-   No automatic OS firewall-rule management is included.
-   No distributed/multi-node deployment is included.
-   The current project is intended as a capstone prototype, not a
    production API-security appliance.

## 18. Future Enhancements Not Included in the Current Version

The following items are intentionally outside the current final scope:

1.  Full HTTPS/TLS termination with production-grade PQ/hybrid TLS.
2.  Automatic OS firewall/router rule management.
3.  Persistent security-event storage.
4.  Redis/database-backed distributed metrics.
5.  Distributed gateway deployment and horizontal scaling.
6.  Advanced LLM/agentic zero-day investigation workflows.
7.  Automated Postman regression collection integrated into CI.
8.  Dedicated performance/latency benchmarking suite.
9.  Production authentication/authorization and API-key management.
10. Advanced IP reputation, geo-blocking, and threat-intelligence feeds.
11. High-availability/failover deployment.
12. Kubernetes/container-orchestration deployment.

These are future extensions rather than missing requirements for the
current capstone prototype.

## 19. Git Workflow

Check status:

``` bash
git status
```

Review changes:

``` bash
git diff --check
git diff --stat
```

Commit:

``` bash
git add .
git commit -m "Describe the completed feature"
```

Push:

``` bash
git push origin main
```

The repository should remain free of secrets, build artifacts, `.venv`,
logs, and Windows `Zone.Identifier` files.

## 20. Conclusion

The completed system demonstrates how several modern security techniques
can be combined in one API-security architecture:

**Post-quantum cryptography + deterministic filtering + rate limiting +
AI anomaly/payload analysis + automated enforcement + security
telemetry + real-time visualization.**

It is therefore suitable as a cybersecurity/AI capstone demonstration
showing both defensive security engineering and practical system
integration.
