import os
import random
import statistics
import string
import subprocess
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import psycopg2
from psycopg2.extras import RealDictCursor

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SAMPLES = 500  # 增加到500个样本，确保测试时间足够长以便CPU采样
READ_SAMPLE_SET = 1000
SEARCH_PREFIXES = ["alpha", "beta", "gamma", "delta"]

ENVIRONMENTS = [
    {
        "name": "baseline",
        "tool": "Baseline",
        "dsn": {
            "host": os.environ.get("BASELINE_HOST", "127.0.0.1"),
            "port": int(os.environ.get("BASELINE_PORT", "5433")),
            "dbname": os.environ.get("BASELINE_DB", "juiceshop_db"),
            "user": os.environ.get("BASELINE_USER", "youruser"),
            "password": os.environ.get("BASELINE_PASSWORD", "password123"),
        },
        "containers": ["postgres-db"],
    },
    {
        "name": "acra",
        "tool": "Acra",
        "dsn": {
            "host": os.environ.get("ACRA_HOST", "127.0.0.1"),
            "port": int(os.environ.get("ACRA_PORT", "9393")),
            "dbname": os.environ.get("ACRA_DB", "acra_db"),
            "user": os.environ.get("ACRA_USER", "acrauser"),
            "password": os.environ.get("ACRA_PASSWORD", "acra_password123"),
        },
        "containers": ["acra-server", "postgres-acra"],
    },
    {
        "name": "pgcrypto",
        "tool": "pgcrypto",
        "dsn": {
            "host": os.environ.get("PGCRYPTO_HOST", "127.0.0.1"),
            "port": int(os.environ.get("PGCRYPTO_PORT", "5435")),
            "dbname": os.environ.get("PGCRYPTO_DB", "pgcrypto_db"),
            "user": os.environ.get("PGCRYPTO_USER", "pgcrypto"),
            "password": os.environ.get("PGCRYPTO_PASSWORD", "pgcrypto_pass"),
        },
        "containers": ["postgres-pgcrypto"],
        "encryption_key": "my_secret_encryption_key_2024",  # 用于 pgcrypto 加密
    },
]

OPERATIONS = [
    {"operation": "写入", "encryption": "标准", "fn": "benchmark_insert"},
    {"operation": "读取", "encryption": "标准", "fn": "benchmark_read_by_id"},
    {"operation": "读取", "encryption": "可搜索", "fn": "benchmark_searchable"},
]


def log(msg: str) -> None:
    print(f"[benchmark] {msg}")


@contextmanager
def get_connection(dsn: dict):
    conn = psycopg2.connect(**dsn, connect_timeout=5)
    try:
        yield conn
    finally:
        conn.close()


def ensure_schema(conn, use_pgcrypto=False) -> None:
    with conn, conn.cursor() as cur:
        if use_pgcrypto:
            # pgcrypto 模式: name 和 email 使用 BYTEA 存储加密数据
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS benchmark_data (
                    id SERIAL PRIMARY KEY,
                    name BYTEA NOT NULL,
                    email BYTEA NOT NULL,
                    searchable TEXT NOT NULL
                );
                """
            )
        else:
            # 标准模式: 所有字段使用 TEXT
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS benchmark_data (
                    id SERIAL PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL,
                    searchable TEXT NOT NULL
                );
                """
            )


def ensure_dataset(
    conn, target_rows: int = READ_SAMPLE_SET, encryption_key=None
) -> int:
    with conn.cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM benchmark_data;")
        count = cur.fetchone()[0]
        needed = max(0, target_rows - count)
        if needed:
            log(f"Seeding {needed} rows")
            prefixes = SEARCH_PREFIXES
            for _ in range(needed):
                name = "user_" + "".join(random.choices(string.ascii_lowercase, k=8))
                email = name + "@example.com"
                prefix = random.choice(prefixes)
                searchable = f"{prefix}-{random.randint(1000,9999)}"
                if encryption_key:  # pgcrypto 模式
                    cur.execute(
                        "INSERT INTO benchmark_data (name, email, searchable) VALUES (encrypt_text(%s, %s), encrypt_text(%s, %s), %s)",
                        (name, encryption_key, email, encryption_key, searchable),
                    )
                else:  # 标准模式
                    cur.execute(
                        "INSERT INTO benchmark_data (name, email, searchable) VALUES (%s, %s, %s)",
                        (name, email, searchable),
                    )
        conn.commit()
        return count + needed


def collect_ids(conn, sample_size: int = 500):
    with conn.cursor() as cur:
        cur.execute(
            "SELECT id FROM benchmark_data ORDER BY id DESC LIMIT %s;", (sample_size,)
        )
        rows = cur.fetchall()
    return [row[0] for row in rows]


class CpuSampler:
    def __init__(self, services, interval=0.3):  # 缩短采样间隔到0.3秒，更频繁采样
        self.services = services
        self.interval = interval
        self.samples = []
        self._stop_event = threading.Event()
        self.thread = None

    def _resolve_containers(self):
        resolved = []
        for svc in self.services:
            try:
                output = (
                    subprocess.check_output(
                        ["docker", "compose", "ps", "-q", svc],
                        cwd=PROJECT_ROOT,
                        stderr=subprocess.DEVNULL,
                    )
                    .decode()
                    .strip()
                )
                if output:
                    resolved.extend(output.splitlines())
            except subprocess.CalledProcessError:
                continue
        return resolved

    def _collect(self, containers):
        if not containers:
            return
        try:
            cmd = [
                "docker",
                "stats",
                "--no-stream",
                "--format",
                "{{.Container}},{{.CPUPerc}}",
                *containers,
            ]
            output = (
                subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode().strip()
            )
        except subprocess.CalledProcessError:
            return
        total = 0.0
        for line in output.splitlines():
            try:
                _, cpu_str = line.split(",", 1)
                cpu_value = cpu_str.strip().rstrip("%")
                total += float(cpu_value)
            except ValueError:
                continue
        self.samples.append(total)

    def _run(self):
        containers = self._resolve_containers()
        while not self._stop_event.is_set():
            self._collect(containers)
            time.sleep(self.interval)

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self._stop_event.set()
        if self.thread:
            self.thread.join()

    def average(self):
        return statistics.mean(self.samples) if self.samples else None


def benchmark_insert(conn, encryption_key=None):
    latencies = []
    with conn.cursor() as cur:
        for _ in range(SAMPLES):
            name = "user_" + "".join(random.choices(string.ascii_lowercase, k=8))
            email = name + "@example.com"
            searchable = (
                random.choice(SEARCH_PREFIXES) + f"-{random.randint(1000,9999)}"
            )
            start = time.perf_counter()
            if encryption_key:  # pgcrypto 模式
                cur.execute(
                    "INSERT INTO benchmark_data (name, email, searchable) VALUES (encrypt_text(%s, %s), encrypt_text(%s, %s), %s)",
                    (name, encryption_key, email, encryption_key, searchable),
                )
            else:  # 标准模式
                cur.execute(
                    "INSERT INTO benchmark_data (name, email, searchable) VALUES (%s, %s, %s)",
                    (name, email, searchable),
                )
            conn.commit()
            latencies.append((time.perf_counter() - start) * 1000)
    return latencies


def benchmark_read_by_id(conn, ids=None, encryption_key=None):
    latencies = []
    ids = ids or collect_ids(conn)
    if not ids:
        return latencies
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        for _ in range(SAMPLES):
            target = random.choice(ids)
            start = time.perf_counter()
            if encryption_key:  # pgcrypto 模式 - 解密
                cur.execute(
                    "SELECT id, decrypt_text(name, %s) as name, decrypt_text(email, %s) as email, searchable FROM benchmark_data WHERE id = %s",
                    (encryption_key, encryption_key, target),
                )
            else:  # 标准模式
                cur.execute("SELECT * FROM benchmark_data WHERE id = %s", (target,))
            cur.fetchone()
            latencies.append((time.perf_counter() - start) * 1000)
    return latencies


def benchmark_searchable(conn):
    latencies = []
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        for _ in range(SAMPLES):
            prefix = random.choice(SEARCH_PREFIXES)
            pattern = f"{prefix}%"
            start = time.perf_counter()
            cur.execute(
                "SELECT * FROM benchmark_data WHERE searchable LIKE %s LIMIT 10",
                (pattern,),
            )
            cur.fetchall()
            latencies.append((time.perf_counter() - start) * 1000)
    return latencies


def run_benchmark(env, operation_key, ids_cache=None, clear_cache=False):
    fn = globals()[operation_key]
    encryption_key = env.get("encryption_key")  # 获取 pgcrypto 密钥
    use_pgcrypto = encryption_key is not None
    with get_connection(env["dsn"]) as conn:
        conn.autocommit = False
        if clear_cache:
            # 清空表以避免缓存影响，每个环境第一次测试时执行
            with conn.cursor() as cur:
                cur.execute("DROP TABLE IF EXISTS benchmark_data;")
            conn.commit()
        ensure_schema(conn, use_pgcrypto=use_pgcrypto)
        ensure_dataset(conn, encryption_key=encryption_key)
        if operation_key == "benchmark_read_by_id" and ids_cache is not None:
            latencies = fn(conn, ids_cache, encryption_key=encryption_key)
        elif operation_key in ["benchmark_insert", "benchmark_read_by_id"]:
            latencies = fn(conn, encryption_key=encryption_key)
        else:
            latencies = fn(conn)
    return latencies


def measure_environment(env):
    results = {}
    ids_cache = None
    is_first_op = True
    for op in OPERATIONS:
        sampler = CpuSampler(env["containers"])
        sampler.start()
        time.sleep(0.5)  # 等待采样器启动并开始收集数据
        try:
            if op["fn"] == "benchmark_read_by_id":
                latencies = run_benchmark(
                    env, op["fn"], ids_cache, clear_cache=is_first_op
                )
                if latencies and ids_cache is None:
                    with get_connection(env["dsn"]) as conn:
                        ids_cache = collect_ids(conn)
            else:
                latencies = run_benchmark(
                    env, op["fn"], ids_cache, clear_cache=is_first_op
                )
            is_first_op = False  # 只在第一个操作时清空表
        except Exception as exc:  # pylint: disable=broad-except
            sampler.stop()
            log(f"{env['tool']} {op['operation']} failed: {exc}")
            results[(op["operation"], op["encryption"])] = {
                "latencies": None,
                "cpu": None,
            }
            continue
        time.sleep(1.0)  # 确保采样器在停止前能采集足够样本
        sampler.stop()
        cpu_avg = sampler.average()
        results[(op["operation"], op["encryption"])] = {
            "latencies": latencies,
            "cpu": cpu_avg,
        }
    return results


def aggregate(latencies):
    if not latencies:
        return None
    return statistics.mean(latencies)


def main():
    baseline_data = None
    aggregated_results = []

    for env in ENVIRONMENTS:
        log(f"Running {env['tool']} benchmarks")
        measurements = measure_environment(env)
        if env["name"] == "baseline":
            baseline_data = measurements
            continue
        aggregated_results.append((env, measurements))

    if baseline_data is None:
        raise RuntimeError(
            "Baseline measurements missing; ensure baseline environment succeeded"
        )

    baseline_metrics = {}
    for key, payload in baseline_data.items():
        baseline_metrics[key] = {
            "latency": aggregate(payload["latencies"]),
            "cpu": payload["cpu"],
        }

    rows = []
    for env, measurements in aggregated_results:
        for op in OPERATIONS:
            key = (op["operation"], op["encryption"])
            measurement = measurements.get(key, {})
            latency_enc = aggregate(measurement.get("latencies"))
            cpu_enc = measurement.get("cpu")
            base = baseline_metrics.get(key, {"latency": None, "cpu": None})
            latency_base = base["latency"]
            cpu_base = base["cpu"]
            latency_overhead = None
            if latency_base and latency_enc:
                latency_overhead = ((latency_enc - latency_base) / latency_base) * 100
            cpu_overhead = None
            if cpu_base and cpu_enc:
                cpu_overhead = (
                    ((cpu_enc - cpu_base) / cpu_base) * 100 if cpu_base else None
                )

            rows.append(
                {
                    "工具": env["tool"],
                    "数据库": "PostgreSQL",
                    "操作类型": op["operation"],
                    "加密类型": op["encryption"],
                    "Baseline延迟 (ms)": (
                        round(latency_base, 2) if latency_base else None
                    ),
                    "加密后延迟 (ms)": round(latency_enc, 2) if latency_enc else None,
                    "延迟开销 (%)": (
                        round(latency_overhead, 2)
                        if latency_overhead is not None
                        else None
                    ),
                    "CPU开销 (%)": (
                        round(cpu_overhead, 2) if cpu_overhead is not None else None
                    ),
                }
            )

    output_dir = PROJECT_ROOT / "results"
    output_dir.mkdir(exist_ok=True)
    output_path = output_dir / "encryption_benchmark.csv"

    headers = [
        "工具",
        "数据库",
        "操作类型",
        "加密类型",
        "Baseline延迟 (ms)",
        "加密后延迟 (ms)",
        "延迟开销 (%)",
        "CPU开销 (%)",
    ]
    with output_path.open("w", encoding="utf-8") as f:
        f.write(",".join(headers) + "\n")
        for row in rows:
            f.write(
                ",".join("" if row[h] is None else str(row[h]) for h in headers) + "\n"
            )

    log(f"Results saved to {output_path}")


if __name__ == "__main__":
    main()
