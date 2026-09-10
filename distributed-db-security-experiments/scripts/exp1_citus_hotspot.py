#!/usr/bin/env python3
"""Run PostgreSQL+Citus distributed extension comparison for experiment 1."""

from __future__ import annotations

import argparse
import csv
import random
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path
from queue import Queue
from typing import Dict, Iterable, List, Optional

import psycopg2


SCENARIOS = {"citus_uniform": 0.0, "citus_hot70": 0.70, "citus_hot90": 0.90}
OPERATIONS = (("select", 0.70), ("update", 0.20), ("insert", 0.10))
HOT_KEY = 3000
CONTAINERS = [
    "exp1_citus_coordinator",
    "exp1_citus_worker_0",
    "exp1_citus_worker_1",
    "exp1_citus_worker_2",
]


@dataclass(frozen=True)
class CitusRequest:
    run_id: int
    request_id: int
    scenario: str
    operation: str
    item_id: int
    user_id: int
    is_hot: bool
    hot_fraction: float


@dataclass
class CitusResult:
    run_id: int
    timestamp: str
    start_ts: float
    end_ts: float
    system: str
    scenario: str
    defense: str
    request_id: int
    operation: str
    item_id: int
    user_id: int
    is_hot: bool
    hot_fraction: float
    success: bool
    error: str
    latency_ms: float
    rows: int


class ConnectionPool:
    def __init__(self, dsn: str, size: int, statement_timeout_ms: int) -> None:
        self._queue: Queue = Queue(maxsize=size)
        dsn = f"{dsn} options='-c statement_timeout={statement_timeout_ms}'"
        for _ in range(size):
            conn = psycopg2.connect(dsn)
            conn.autocommit = True
            self._queue.put(conn)

    def acquire(self):
        return self._queue.get(timeout=5)

    def release(self, conn) -> None:
        self._queue.put(conn)

    def close(self) -> None:
        while not self._queue.empty():
            self._queue.get_nowait().close()


class ResourceSampler:
    def __init__(self, run_id: int, scenario: str, interval_s: float = 0.5) -> None:
        self.run_id = run_id
        self.scenario = scenario
        self.interval_s = interval_s
        self.samples: List[Dict[str, object]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=10)

    def _run(self) -> None:
        while not self._stop.is_set():
            self.samples.extend(fetch_resource_sample(self.run_id, self.scenario))
            self._stop.wait(self.interval_s)


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    raw_dir = root / "results" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    if args.clean:
        compose(args.compose_file, ["down", "-v"], root)
    if args.start_services:
        try:
            compose(args.compose_file, ["up", "-d"], root)
        except subprocess.CalledProcessError as exc:
            print(
                "[citus-exp1] Citus services did not start. The most common cause in this environment is that "
                "the Citus Docker image is not cached and the registry mirror times out while pulling it. "
                "Preload a Citus image on the server or rerun with CITUS_IMAGE=<cached-image:tag>.",
                file=sys.stderr,
                flush=True,
            )
            return exc.returncode

    dsn = make_dsn(args.host, args.port, args.database, args.user, args.password)
    wait_for_citus(dsn, args.wait_timeout)

    all_results: List[Dict[str, object]] = []
    all_samples: List[Dict[str, object]] = []
    all_placements: List[Dict[str, object]] = []

    for run_id in range(1, args.runs + 1):
        print(f"[citus-exp1] run_id={run_id}/{args.runs}", flush=True)
        prepare_schema(dsn, args.shard_count)
        for scenario in split_arg(args.scenarios, SCENARIOS.keys()):
            all_placements.extend(fetch_placement_observations(dsn, run_id, scenario, "before"))
            specs = build_workload(run_id, scenario, args.requests, args.seed + run_id * 100000)
            pool = ConnectionPool(dsn, args.connection_pool_size, args.statement_timeout_ms)
            sampler = ResourceSampler(run_id, scenario, args.sample_interval_s)
            sampler.start()
            started = time.time()
            try:
                print(
                    f"[citus-exp1] run_id={run_id} scenario={scenario} "
                    f"requests={len(specs)} concurrency={args.concurrency}",
                    flush=True,
                )
                results = run_workload(pool, specs, args.concurrency)
            finally:
                sampler.stop()
                pool.close()
            elapsed = time.time() - started
            successes = sum(1 for result in results if result.success)
            print(
                f"[citus-exp1] done run_id={run_id} scenario={scenario} "
                f"elapsed={elapsed:.2f}s success={successes}/{len(results)}",
                flush=True,
            )
            all_results.extend(asdict(result) for result in results)
            all_samples.extend(sampler.samples)
            all_placements.extend(fetch_placement_observations(dsn, run_id, scenario, "after"))

    write_csv(raw_dir / "exp1_citus_hotspot_requests.csv", all_results)
    write_csv(raw_dir / "exp1_citus_resource_samples.csv", all_samples)
    write_csv(raw_dir / "exp1_citus_shard_placements.csv", all_placements)
    print(f"[citus-exp1] wrote Citus raw CSV files under {raw_dir}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5437)
    parser.add_argument("--database", default="expdb")
    parser.add_argument("--user", default="expuser")
    parser.add_argument("--password", default="exp_pass_123")
    parser.add_argument("--requests", type=int, default=900)
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--concurrency", type=int, default=96)
    parser.add_argument("--connection-pool-size", type=int, default=96)
    parser.add_argument("--statement-timeout-ms", type=int, default=5000)
    parser.add_argument("--sample-interval-s", type=float, default=0.5)
    parser.add_argument("--seed", type=int, default=20260512)
    parser.add_argument("--wait-timeout", type=float, default=180.0)
    parser.add_argument("--shard-count", type=int, default=32)
    parser.add_argument("--compose-file", default="docker-compose.citus.yml")
    parser.add_argument("--scenarios", default=",".join(SCENARIOS.keys()))
    parser.add_argument("--start-services", action="store_true")
    parser.add_argument("--clean", action="store_true")
    return parser.parse_args()


def compose(compose_file: str, args: List[str], cwd: Path) -> None:
    cmd = ["docker", "compose", "-f", compose_file, *args]
    print("[compose]", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=str(cwd), check=True)


def make_dsn(host: str, port: int, database: str, user: str, password: str) -> str:
    return f"host={host} port={port} dbname={database} user={user} password={password}"


def split_arg(raw: str, allowed: Iterable[str]) -> List[str]:
    allowed_set = set(allowed)
    values = [part.strip() for part in raw.split(",") if part.strip()]
    unknown = [value for value in values if value not in allowed_set]
    if unknown:
        raise SystemExit(f"unknown values: {unknown}; allowed={sorted(allowed_set)}")
    return values


def wait_for_citus(dsn: str, timeout_s: float) -> None:
    deadline = time.time() + timeout_s
    last_error = ""
    while time.time() < deadline:
        try:
            conn = psycopg2.connect(dsn)
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute("SELECT version()")
                print(f"[citus-exp1] connected: {cur.fetchone()[0]}", flush=True)
            conn.close()
            return
        except Exception as exc:
            last_error = str(exc)
            time.sleep(2)
    raise RuntimeError(f"Citus coordinator did not become ready within {timeout_s}s: {last_error}")


def prepare_schema(dsn: str, shard_count: int) -> None:
    conn = psycopg2.connect(dsn)
    conn.autocommit = True
    with conn.cursor() as cur:
        cur.execute("CREATE EXTENSION IF NOT EXISTS citus")
        try_execute(cur, "SELECT citus_set_coordinator_host('citus-coordinator', 5432)")
        for worker in ["citus-worker-0", "citus-worker-1", "citus-worker-2"]:
            cur.execute("SELECT count(*) FROM pg_dist_node WHERE nodename = %s", (worker,))
            if cur.fetchone()[0] == 0:
                cur.execute("SELECT citus_add_node(%s, 5432)", (worker,))
        cur.execute("SET citus.shard_count = %s", (shard_count,))
        cur.execute("DROP TABLE IF EXISTS citus_events")
        cur.execute("DROP TABLE IF EXISTS citus_items")
        cur.execute(
            """
            CREATE TABLE citus_items (
                item_id INTEGER PRIMARY KEY,
                stock INTEGER NOT NULL DEFAULT 100000,
                version INTEGER NOT NULL DEFAULT 0,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE citus_events (
                event_id BIGSERIAL,
                item_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                payload TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
            )
            """
        )
        cur.execute("SELECT create_distributed_table('citus_items', 'item_id')")
        cur.execute("SELECT create_distributed_table('citus_events', 'item_id')")
        cur.execute(
            """
            INSERT INTO citus_items(item_id, stock, version)
            SELECT gs, 100000, 0
            FROM generate_series(1, 30000) AS gs
            """
        )
    conn.close()


def try_execute(cur, sql: str) -> None:
    try:
        cur.execute(sql)
    except Exception as exc:
        print(f"[citus-exp1] warning: {sql}: {exc}", flush=True)


def build_workload(run_id: int, scenario: str, requests: int, seed: int) -> List[CitusRequest]:
    rng = random.Random(seed + sum(ord(ch) for ch in scenario))
    hot_fraction = SCENARIOS[scenario]
    specs: List[CitusRequest] = []
    for request_id in range(requests):
        is_hot = hot_fraction > 0 and rng.random() < hot_fraction
        item_id = HOT_KEY if is_hot else rng.randint(1, 30000)
        specs.append(
            CitusRequest(
                run_id=run_id,
                request_id=request_id,
                scenario=scenario,
                operation=choose_operation(rng),
                item_id=item_id,
                user_id=rng.randint(1, 100000),
                is_hot=is_hot,
                hot_fraction=hot_fraction,
            )
        )
    return specs


def choose_operation(rng: random.Random) -> str:
    marker = rng.random()
    cumulative = 0.0
    for operation, weight in OPERATIONS:
        cumulative += weight
        if marker <= cumulative:
            return operation
    return OPERATIONS[-1][0]


def run_workload(pool: ConnectionPool, specs: List[CitusRequest], concurrency: int) -> List[CitusResult]:
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(execute_request, pool, spec) for spec in specs]
        return [future.result() for future in as_completed(futures)]


def execute_request(pool: ConnectionPool, spec: CitusRequest) -> CitusResult:
    started = time.time()
    success = False
    error = ""
    rows = 0
    conn = None
    try:
        conn = pool.acquire()
        with conn.cursor() as cur:
            if spec.operation == "select":
                cur.execute("SELECT stock, version FROM citus_items WHERE item_id = %s", (spec.item_id,))
                rows = cur.rowcount
                cur.fetchall()
            elif spec.operation == "update":
                cur.execute(
                    """
                    UPDATE citus_items
                    SET stock = stock + 1,
                        version = version + 1,
                        updated_at = clock_timestamp()
                    WHERE item_id = %s
                    """,
                    (spec.item_id,),
                )
                rows = cur.rowcount
            elif spec.operation == "insert":
                cur.execute(
                    "INSERT INTO citus_events(item_id, user_id, payload) VALUES (%s, %s, %s)",
                    (spec.item_id, spec.user_id, f"{spec.scenario}:{spec.request_id}"),
                )
                rows = cur.rowcount
            success = True
    except Exception as exc:
        error = type(exc).__name__
    finally:
        if conn is not None:
            pool.release(conn)
    ended = time.time()
    return CitusResult(
        run_id=spec.run_id,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ended)),
        start_ts=started,
        end_ts=ended,
        system="PostgreSQL+Citus",
        scenario=spec.scenario,
        defense="citus_native",
        request_id=spec.request_id,
        operation=spec.operation,
        item_id=spec.item_id,
        user_id=spec.user_id,
        is_hot=spec.is_hot,
        hot_fraction=spec.hot_fraction,
        success=success,
        error=error,
        latency_ms=(ended - started) * 1000.0,
        rows=rows,
    )


def fetch_placement_observations(dsn: str, run_id: int, scenario: str, phase: str) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    conn = psycopg2.connect(dsn)
    conn.autocommit = True
    with conn.cursor() as cur:
        hot_shard_id = ""
        try:
            cur.execute("SELECT get_shard_id_for_distribution_column('citus_items', %s)", (HOT_KEY,))
            hot_shard_id = str(cur.fetchone()[0])
        except Exception as exc:
            print(f"[citus-exp1] hotspot shard lookup warning: {exc}", flush=True)
        cur.execute(
            """
            SELECT s.shardid,
                   n.nodename,
                   n.nodeport,
                   (s.shardid::text = %s) AS is_hotspot_shard
            FROM pg_dist_shard s
            JOIN pg_dist_placement p ON p.shardid = s.shardid
            JOIN pg_dist_node n ON n.groupid = p.groupid
            WHERE s.logicalrelid = 'citus_items'::regclass
            ORDER BY s.shardid, n.nodename
            """,
            (hot_shard_id,),
        )
        for shard_id, node_name, node_port, is_hotspot in cur.fetchall():
            rows.append(
                {
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    "ts": time.time(),
                    "run_id": run_id,
                    "system": "PostgreSQL+Citus",
                    "scenario": scenario,
                    "phase": phase,
                    "relation": "citus_items",
                    "shard_id": shard_id,
                    "node_name": node_name,
                    "node_port": node_port,
                    "is_hotspot_shard": bool(is_hotspot),
                    "hot_key": HOT_KEY,
                }
            )
    conn.close()
    return rows


def fetch_resource_sample(run_id: int, scenario: str) -> List[Dict[str, object]]:
    stats = docker_stats(CONTAINERS)
    rows: List[Dict[str, object]] = []
    for name in CONTAINERS:
        item = stats.get(name, {})
        rows.append(
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "ts": time.time(),
                "run_id": run_id,
                "system": "PostgreSQL+Citus",
                "scenario": scenario,
                "component": "coordinator" if name.endswith("coordinator") else "worker",
                "container": name,
                "cpu_percent": item.get("cpu_percent"),
                "memory_mb": item.get("memory_mb"),
            }
        )
    return rows


def docker_stats(names: List[str]) -> Dict[str, Dict[str, float]]:
    cmd = ["docker", "stats", "--no-stream", "--format", "{{.Name}},{{.CPUPerc}},{{.MemUsage}}", *names]
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=8)
    except Exception:
        return {}
    rows: Dict[str, Dict[str, float]] = {}
    for line in proc.stdout.splitlines():
        parts = line.split(",", 2)
        if len(parts) != 3:
            continue
        rows[parts[0]] = {"cpu_percent": parse_percent(parts[1]), "memory_mb": parse_mem_mb(parts[2])}
    return rows


def parse_percent(raw: str) -> Optional[float]:
    try:
        return float(raw.strip().rstrip("%"))
    except Exception:
        return None


def parse_mem_mb(raw: str) -> Optional[float]:
    try:
        left = raw.split("/", 1)[0].strip()
        unit = "".join(ch for ch in left if ch.isalpha())
        value = float("".join(ch for ch in left if ch.isdigit() or ch == "."))
        if unit.lower().startswith("gi"):
            return value * 1024.0
        if unit.lower().startswith("ki"):
            return value / 1024.0
        return value
    except Exception:
        return None


def write_csv(path: Path, rows: List[Dict[str, object]]) -> None:
    if not rows:
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


if __name__ == "__main__":
    sys.exit(main())
