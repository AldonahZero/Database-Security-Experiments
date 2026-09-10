#!/usr/bin/env python3
import argparse
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Optional, Tuple


def parse_headers(header_list: Optional[List[str]]) -> dict:
    headers = {}
    if not header_list:
        return headers
    for item in header_list:
        if ":" not in item:
            raise argparse.ArgumentTypeError(
                f"Invalid header format '{item}'. Expected 'Key: Value'."
            )
        key, value = item.split(":", 1)
        headers[key.strip()] = value.strip()
    return headers


def send_request(
    url: str, method: str, body: Optional[str], headers: dict, timeout: float
) -> Tuple[float, Optional[int]]:
    data = None
    if body is not None:
        data = body.encode("utf-8")
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    request = urllib.request.Request(
        url, data=data, headers=headers, method=method.upper()
    )
    start = time.time()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            # Read response to ensure full round-trip; content is discarded.
            response.read()
            status = getattr(response, "status", getattr(response, "code", None))
    except urllib.error.HTTPError as exc:
        try:
            exc.read()
        except Exception:  # pragma: no cover - best effort cleanup
            pass
        status = exc.code
    return (time.time() - start) * 1000, status


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Measure response times for an HTTP endpoint and report statistics as JSON."
    )
    parser.add_argument("--url", required=True, help="Full URL to request.")
    parser.add_argument(
        "--method",
        default="GET",
        choices=["GET", "POST", "PUT", "DELETE", "PATCH"],
        help="HTTP method to use (default: GET).",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=10,
        help="Number of requests to issue (ignored when --duration is set).",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.2,
        help="Delay in seconds between requests (default: 0.2).",
    )
    parser.add_argument(
        "--duration",
        type=float,
        help="If set, run for this many seconds instead of a fixed sample count.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=15.0,
        help="Timeout per request in seconds (default: 15).",
    )
    parser.add_argument(
        "--body",
        help="Optional request body (for non-GET requests).",
    )
    parser.add_argument(
        "--header",
        action="append",
        help="Additional headers in 'Key: Value' format. Can be repeated.",
    )

    args = parser.parse_args()
    headers = parse_headers(args.header)

    attempts = 0
    successes = []
    errors = []
    start_time = time.time()

    while True:
        if args.duration is not None:
            if time.time() - start_time >= args.duration:
                break
        else:
            if attempts >= args.samples:
                break
        attempts += 1
        try:
            elapsed_ms, status = send_request(
                args.url, args.method, args.body, headers, args.timeout
            )
            successes.append(elapsed_ms)
            if status is not None and status >= 400:
                errors.append(
                    {
                        "attempt": attempts,
                        "error": f"HTTP {status}",
                        "note": "counted in successes despite error status",
                    }
                )
        except urllib.error.URLError as exc:
            errors.append({"attempt": attempts, "error": str(exc)})
        except Exception as exc:  # pylint: disable=broad-except
            errors.append({"attempt": attempts, "error": str(exc)})
        time.sleep(max(args.delay, 0))

    avg_ms = sum(successes) / len(successes) if successes else None

    result = {
        "url": args.url,
        "method": args.method,
        "attempts": attempts,
        "successes": len(successes),
        "failures": len(errors),
        "avg_ms": avg_ms,
        "samples_ms": successes,
        "errors": errors,
    }

    print(json.dumps(result))


if __name__ == "__main__":
    main()
