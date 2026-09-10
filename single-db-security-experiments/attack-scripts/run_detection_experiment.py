#!/usr/bin/env python3
import csv
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence

import requests

BASE_URL = os.environ.get("WAF_BASE_URL", "http://modsecurity:8080")
SURICATA_RULES = Path("/root/attack-scripts/rules/sql-injection.rules")
RESULTS_ROOT_CANDIDATES: Sequence[Path] = (
    Path("/workspace/results"),
    Path("/root/results"),
    Path("results"),
)
SURICATA_OUTPUT_DIR = Path("/var/log/suricata")
EVE_JSON_PATH = SURICATA_OUTPUT_DIR / "eve.json"


def resolve_results_dir() -> Path:
    for candidate in RESULTS_ROOT_CANDIDATES:
        if candidate.exists():
            return candidate
    default = Path("/workspace/results")
    default.mkdir(parents=True, exist_ok=True)
    return default


RESULTS_DIR = resolve_results_dir()
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
DETECTION_CSV = RESULTS_DIR / "detection_metrics.csv"
MODSECURITY_AUDIT_LOG = Path("/var/log/modsecurity/audit.log")

DEFAULT_MALICIOUS_COUNT = max(
    100, int(os.environ.get("MALICIOUS_PAYLOAD_COUNT", "150"))
)
DEFAULT_BENIGN_COUNT = max(100, int(os.environ.get("BENIGN_PAYLOAD_COUNT", "150")))


def _take_unique(values: Iterable[str], count: int) -> List[str]:
    seen = set()
    result: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
        if len(result) >= count:
            break
    if len(result) < count:
        raise ValueError(f"无法生成 {count} 条唯一 payload，仅得到 {len(result)} 条")
    return result


def generate_basic_sql_injection_payloads(count: int) -> List[str]:
    left_values = [
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "10",
        "11",
        "12",
        "13",
        "21",
        "42",
    ]
    connectors = [
        " OR ",
        " or ",
        " Or ",
        " oR ",
        " OR  ",
        "  OR ",
        " OR\t",
        "\tOR ",
        " OR/**/",
        "/**/OR ",
        " OR/*basic*/",
        "/*!OR*/",
    ]
    comparators = [
        "1=1",
        "(1=1)",
        "1=1--",
        "1=1 --",
        "1=1#",
        "1=1/*keep*/",
        "1=1/**/",
        "1=1/**/AND/**/2=2",
        "1=1 AND 2=2",
        "1=1 OR 2=2",
        "(1=1 AND 2=2)",
        "1=1 UNION SELECT 1",
    ]
    suffixes = [
        "",
        " --",
        " #",
        " /*basic*/",
        " --+",
        " --test",
    ]
    payloads = (
        f"{left}{connector}{comparator}{suffix}"
        for left in left_values
        for connector in connectors
        for comparator in comparators
        for suffix in suffixes
    )
    return _take_unique(payloads, count)


def generate_obfuscated_sql_injection_payloads(count: int) -> List[str]:
    left_values = [
        "0",
        "1",
        "2",
        "3",
        "4",
        "5",
        "6",
        "7",
        "8",
        "9",
        "10",
        "11",
        "12",
        "13",
        "21",
        "42",
    ]
    connectors = [
        "/**/OR/**/",
        "/*foo*/OR/*bar*/",
        " OR/*obf*/ ",
        " /*!OR*/ ",
        " OR/**/",
        "/**/OR ",
        " OR\t",
        "\tor\t",
        " OR\\u0020",
        " OR\f",
        " OR\v",
        " OR\u00a0",
    ]
    comparators = [
        "'1'='1'",
        "('1'='1')",
        "'1'='1'--",
        "'1'='1' /*string*/",
        "'1'='1'#",
        "'1'='1'/**/",
        "'1'='1'/**/AND/**/'2'='2'",
        "'1'='1' OR '2'='2'",
        "('1'='1' AND '2'='2')",
        "'1'='1' UNION SELECT '1'",
        "'1'='1'/*obf*/",
        "'1'='1'/*!50000*/",
    ]
    suffixes = [
        "",
        " --",
        " #",
        " /*obf*/",
        " --+",
        " --test",
    ]
    payloads = (
        f"{left}{connector}{comparator}{suffix}"
        for left in left_values
        for connector in connectors
        for comparator in comparators
        for suffix in suffixes
    )
    return _take_unique(payloads, count)


def generate_stored_procedure_payloads(count: int) -> List[str]:
    prefixes = [
        "1; ",
        "0; ",
        "2; ",
        "3; ",
        "4; ",
        "5; ",
        "-1; ",
        "'1'; ",
        '"1"; ',
        "1) ; ",
        "1'); ",
        '"1" ); ',
    ]
    templates = [
        "CALL pg_sleep({duration})",
        "SELECT pg_sleep({duration})",
        "PERFORM pg_sleep({duration})",
        "EXECUTE pg_sleep({duration})",
        "DO $$BEGIN PERFORM pg_sleep({duration}); END$$",
        "DO $$ BEGIN PERFORM pg_sleep({duration}); END $$",
    ]
    suffixes = [
        "; --",
        "; -- delay",
        "; /*sleep*/",
        "; #",
        "; --test",
        "; -- pause",
    ]
    durations = [f"{value/10:.1f}" for value in range(1, 401)]
    payloads = (
        f"{prefix}{template.format(duration=duration)}{suffix}"
        for prefix in prefixes
        for template in templates
        for duration in durations
        for suffix in suffixes
    )
    return _take_unique(payloads, count)


def generate_numeric_payloads(count: int, start: int = 1) -> List[str]:
    return [str(start + index) for index in range(count)]


@dataclass
class Scenario:
    name: str
    display: str
    malicious_payloads: List[str]
    benign_payloads: List[str]
    suricata_sid: int


SCENARIOS: List[Scenario] = [
    Scenario(
        name="basic_sql_injection",
        display="基础SQL注入",
        malicious_payloads=generate_basic_sql_injection_payloads(
            DEFAULT_MALICIOUS_COUNT
        ),
        benign_payloads=generate_numeric_payloads(DEFAULT_BENIGN_COUNT, start=1),
        suricata_sid=100001,
    ),
    Scenario(
        name="obfuscated_sql_injection",
        display="混淆SQL注入",
        malicious_payloads=generate_obfuscated_sql_injection_payloads(
            DEFAULT_MALICIOUS_COUNT
        ),
        benign_payloads=generate_numeric_payloads(DEFAULT_BENIGN_COUNT, start=2000),
        suricata_sid=100002,
    ),
    Scenario(
        name="stored_procedure",
        display="存储过程调用",
        malicious_payloads=generate_stored_procedure_payloads(DEFAULT_MALICIOUS_COUNT),
        benign_payloads=generate_numeric_payloads(DEFAULT_BENIGN_COUNT, start=4000),
        suricata_sid=100003,
    ),
]


def ensure_directories() -> None:
    SURICATA_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "detection_logs").mkdir(parents=True, exist_ok=True)


def log_info(message: str) -> None:
    print(f"[INFO] {message}")


def send_request(
    param_value: str, headers: Optional[Dict[str, str]] = None
) -> requests.Response:
    url = f"{BASE_URL}/pg/users"
    params = {"id": param_value}
    response = requests.get(url, params=params, headers=headers, timeout=10)
    return response


def modsecurity_detected(response: requests.Response) -> bool:
    if response.status_code >= 400:
        return True
    if "modsecurity" in response.text.lower():
        return True
    return False


def parse_suricata_alerts(eve_path: Path, sid: int) -> int:
    if not eve_path.exists():
        return 0
    count = 0
    with eve_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") != "alert":
                continue
            alert = event.get("alert") or {}
            if alert.get("signature_id") == sid:
                count += 1
    return count


def evaluate_modsecurity(scenario: Scenario) -> Dict[str, float]:
    blocked_malicious = 0
    for payload in scenario.malicious_payloads:
        try:
            response = send_request(payload)
        except requests.RequestException as exc:
            log_info(f"ModSecurity 恶意请求 {payload!r} 失败: {exc}")
            continue
        if modsecurity_detected(response):
            blocked_malicious += 1
        time.sleep(0.2)

    blocked_benign = 0
    for payload in scenario.benign_payloads:
        try:
            response = send_request(payload)
        except requests.RequestException as exc:
            log_info(f"ModSecurity 正常请求 {payload!r} 失败: {exc}")
            continue
        if modsecurity_detected(response):
            blocked_benign += 1
        time.sleep(0.2)

    total_malicious = len(scenario.malicious_payloads)
    total_benign = len(scenario.benign_payloads)
    tpr = (blocked_malicious / total_malicious) * 100 if total_malicious else 0.0
    fpr = (blocked_benign / total_benign) * 100 if total_benign else 0.0
    return {
        "tpr": round(tpr, 1),
        "fpr": round(fpr, 1),
        "blocked_malicious": blocked_malicious,
        "blocked_benign": blocked_benign,
    }


def evaluate_suricata(scenario: Scenario) -> Dict[str, float]:
    eve_path = EVE_JSON_PATH

    def wait_for_eve(path: Path, attempts: int = 10, delay: float = 0.5) -> None:
        for _ in range(attempts):
            if path.exists():
                return
            time.sleep(delay)
        path.touch(exist_ok=True)

    bypass_headers = {"X-Bypass-WAF": "1"}

    def send_payloads(payloads: List[str]) -> None:
        for payload in payloads:
            try:
                send_request(payload, headers=bypass_headers)
            except requests.RequestException as exc:
                log_info(f"请求 {payload!r} 失败: {exc}")
            time.sleep(0.2)

    wait_for_eve(eve_path)
    baseline = parse_suricata_alerts(eve_path, scenario.suricata_sid)

    send_payloads(scenario.malicious_payloads)
    time.sleep(1.0)
    after_malicious = parse_suricata_alerts(eve_path, scenario.suricata_sid)
    malicious_alerts = max(after_malicious - baseline, 0)

    send_payloads(scenario.benign_payloads)
    time.sleep(1.0)
    after_benign = parse_suricata_alerts(eve_path, scenario.suricata_sid)
    benign_alerts = max(after_benign - after_malicious, 0)

    total_malicious = len(scenario.malicious_payloads)
    total_benign = len(scenario.benign_payloads)
    tpr = (
        min(malicious_alerts, total_malicious) / total_malicious * 100
        if total_malicious
        else 0.0
    )
    fpr = min(benign_alerts, total_benign) / total_benign * 100 if total_benign else 0.0
    return {
        "tpr": round(tpr, 1),
        "fpr": round(fpr, 1),
        "alerts_malicious": malicious_alerts,
        "alerts_benign": benign_alerts,
    }


def write_results(rows: List[Dict[str, object]]) -> None:
    file_exists = DETECTION_CSV.exists()
    with DETECTION_CSV.open("a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "tool",
                "scenario",
                "tpr_percent",
                "fpr_percent",
                "malicious_samples",
                "benign_samples",
                "extra",
            ],
        )
        if not file_exists:
            writer.writeheader()
        for row in rows:
            writer.writerow(row)


def main() -> None:
    ensure_directories()
    all_rows: List[Dict[str, object]] = []
    for scenario in SCENARIOS:
        log_info(f"评估 ModSecurity 场景: {scenario.display}")
        modsec_stats = evaluate_modsecurity(scenario)
        all_rows.append(
            {
                "tool": "ModSecurity (OWASP CRS)",
                "scenario": scenario.display,
                "tpr_percent": modsec_stats["tpr"],
                "fpr_percent": modsec_stats["fpr"],
                "malicious_samples": len(scenario.malicious_payloads),
                "benign_samples": len(scenario.benign_payloads),
                "extra": json.dumps(
                    {
                        "blocked_malicious": modsec_stats["blocked_malicious"],
                        "blocked_benign": modsec_stats["blocked_benign"],
                    }
                ),
            }
        )

        log_info(f"评估 Suricata 场景: {scenario.display}")
        suricata_stats = evaluate_suricata(scenario)
        all_rows.append(
            {
                "tool": "Suricata (SQL规则集)",
                "scenario": scenario.display,
                "tpr_percent": suricata_stats["tpr"],
                "fpr_percent": suricata_stats["fpr"],
                "malicious_samples": len(scenario.malicious_payloads),
                "benign_samples": len(scenario.benign_payloads),
                "extra": json.dumps(
                    {
                        "alerts_malicious": suricata_stats["alerts_malicious"],
                        "alerts_benign": suricata_stats["alerts_benign"],
                    }
                ),
            }
        )

    write_results(all_rows)
    log_info(f"结果已写入 {DETECTION_CSV}")


if __name__ == "__main__":
    main()
