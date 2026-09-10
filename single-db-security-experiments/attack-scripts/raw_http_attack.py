#!/usr/bin/env python3
import argparse
import json
import sys
import time
import urllib.parse
import urllib.request
from typing import Optional


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Send a single raw HTTP request with injectable param for WAF/IDS testing."
    )
    parser.add_argument(
        "--url", required=True, help="Base URL without query parameters"
    )
    parser.add_argument(
        "--param",
        required=True,
        help="Single key=value or raw 'id=1 UNION ...' style parameter.",
    )
    parser.add_argument(
        "--method", default="GET", choices=["GET"], help="Only GET supported currently"
    )
    parser.add_argument(
        "--attack-id", required=True, help="Identifier tag added as X-Attack-ID header."
    )
    parser.add_argument("--timeout", type=float, default=20.0)
    args = parser.parse_args()

    if "=" not in args.param:
        print("param 需要是 key=value 格式", file=sys.stderr)
        sys.exit(2)

    key, value = args.param.split("=", 1)

    # 对 value 进行最小化编码，保留 SQL 注入所需的结构但移除非法控制字符
    safe_chars = "*'-._~:/?&=,()%+"
    encoded_value = urllib.parse.quote(value, safe=safe_chars)
    q = f"{urllib.parse.quote_plus(key)}={encoded_value}"
    full_url = f"{args.url}?{q}"

    req = urllib.request.Request(full_url, headers={"X-Attack-ID": args.attack_id})
    start = time.time()
    status: Optional[int] = None
    body_snippet = None
    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            status = getattr(resp, "status", getattr(resp, "code", None))
            data = resp.read(4096)
            body_snippet = data.decode(errors="ignore")[:300]
    except Exception as exc:  # noqa: BLE001
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": str(exc),
                    "url": full_url,
                    "elapsed_ms": (time.time() - start) * 1000,
                }
            )
        )
        sys.exit(1)

    print(
        json.dumps(
            {
                "ok": True,
                "status": status,
                "url": full_url,
                "elapsed_ms": (time.time() - start) * 1000,
                "body_snippet": body_snippet,
                "attack_id": args.attack_id,
            }
        )
    )


if __name__ == "__main__":
    main()
