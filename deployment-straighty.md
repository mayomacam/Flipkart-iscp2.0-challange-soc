# Api gateway
1. Scalability:
* API Gateway plugins scale with the number of services.
* Each instance processes only its own traffic; can horizontally scale with microservices.

2. Latency:
* Adding PII detection inside the request path adds minimal latency if optimized.
* Unlike network-layer inspection, using structured data (JSON), and using regex/pattern detection will be faster.

3. Cost-effectiveness:
* No need to over-provision network hardware or process all raw traffic.
* Existing infrastructure (API Gateway / Sidecar framework) can host the code.

4. Ease of integration:
* Works with microservices without changing business logic.
* Can easily plug into logging, database writes, or response payloads.
* Schema-aware detection reduces false positives.
* Can also update script to set own logs, which can also help detect if problem arise with fields, if banned words used in them.

5. Redaction capability:
* Can mask or redact sensitive fields in outgoing responses, incoming requests, or logs.
* Works in real-time for both internal and external clients.

# Example 
1. Applies PII detection/redaction code (use code here).
2. Forwards the redacted data to the service or database.

Means when api request went to users database path then this is where we should put it.
For thinking of Soc, it can also generate alert.
Encoding for ", ', <, >, { and } and some others.
