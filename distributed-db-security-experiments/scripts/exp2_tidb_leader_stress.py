#!/usr/bin/env python3
"""Run experiment 2: TiDB Leader stress and perturbation recovery.

The script uses normal SQL traffic against a controlled TiDB cluster. It first
locates the TiKV container that currently hosts the hot Region Leader, then
injects bounded CPU pressure or pauses that container for a bounded interval.
This is an availability/recovery evaluation, not a product vulnerability test.
"""

from __future__ import annotations

import argparse
import csv
import itertools
import json
import math
import random
import re
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path
from queue import Queue
from typing import Dict, Iterable, List, Optional, Tuple

import pymysql


SCENARIOS = {
    "baseline": {"perturbation": "none", "limited": False},
    "leader_cpu_stress": {"perturbation": "cpu", "limited": False},
    # Keep the legacy scenario identifier so the published raw CSV files remain
    # directly comparable. The injected fault is a TiKV container pause.
    "leader_network_perturbation": {"perturbation": "container_pause", "limited": False},
    "leader_cpu_stress_limited": {"perturbation": "cpu", "limited": True},
}

OPERATIONS = (("select", 0.70), ("update", 0.20), ("insert", 0.10))
TIKV_CONTAINERS = ["exp1_tidb_tikv0", "exp1_tidb_tikv1", "exp1_tidb_tikv2"]
TIKV_HOST_TO_CONTAINER = {
    "tikv0": "exp1_tidb_tikv0",
    "tikv1": "exp1_tidb_tikv1",
    "tikv2": "exp1_tidb_tikv2",
}


@dataclass(frozen=True)
class ScenarioContext:
    run_id: int
    scenario: str
    start_ts: float
    baseline_s: float
    perturb_s: float
    recovery_s: float
    target_region_id: str
    target_store_id: str
    target_container: str
    perturbation: str
    limited: bool

    @property
    def total_s(self) -> float:
        return self.baseline_s + self.perturb_s + self.recovery_s


@dataclass(frozen=True)
class TidbLeaderRequest:
    run_id: int
    scenario: str
    request_id: int
    operation: str
    item_id: int
    user_id: int
    is_hot: bool
    target_region_id: str
    target_store_id: str
    target_container: str


@dataclass
class TidbLeaderResult:
    run_id: int
    timestamp: str
    start_ts: float
    end_ts: float
    relative_s: float
    phase: str
    system: str
    scenario: str
    mitigation: str
    perturbation: str
    request_id: int
    operation: str
    item_id: int
    user_id: int
    is_hot: bool
    target_region_id: str
    target_store_id: str
    target_container: str
    success: bool
    error: str
    latency_ms: float
    rows: int
    baseline_s: float
    perturb_s: float
    recovery_s: float


class ConnectionPool:
    def __init__(self, size: int, host: str, port: int, user: str, database: str, timeout_s: float) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.database = database
        self.timeout_s = timeout_s
        self._queue: Queue = Queue(maxsize=size)
        for _ in range(size):
            self._queue.put(self._new_connection())

    def _new_connection(self):
        return pymysql.connect(
            host=self.host,
            port=self.port,
            user=self.user,
            database=self.database,
            autocommit=True,
            connect_timeout=self.timeout_s,
            read_timeout=self.timeout_s,
            write_timeout=self.timeout_s,
            charset="utf8mb4",
        )

    def acquire(self):
        return self._queue.get(timeout=max(self.timeout_s, 1.0))

    def release(self, conn) -> None:
        self._queue.put(conn)

    def close(self) -> None:
        while not self._queue.empty():
            try:
                self._queue.get_nowait().close()
            except Exception:
                pass


class ResourceSampler:
    def __init__(self, ctx: ScenarioContext, interval_s: float) -> None:
        self.ctx = ctx
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
            ts = time.time()
            phase = phase_for_elapsed(self.ctx, ts - self.ctx.start_ts)
            stats = docker_stats(TIKV_CONTAINERS)
            for name in TIKV_CONTAINERS:
                item = stats.get(name, {})
                self.samples.append(
                    {
                        "timestamp": iso_ts(ts),
                        "ts": ts,
                        "relative_s": ts - self.ctx.start_ts,
                        "run_id": self.ctx.run_id,
                        "system": "TiDB",
                        "scenario": self.ctx.scenario,
                        "phase": phase,
                        "component": "TiKV",
                        "container": name,
                        "target_container": self.ctx.target_container,
                        "is_target_leader": name == self.ctx.target_container,
                        "cpu_percent": item.get("cpu_percent"),
                        "memory_mb": item.get("memory_mb"),
                    }
                )
            self._stop.wait(self.interval_s)


class LeaderObserver:
    def __init__(
        self,
        ctx: ScenarioContext,
        host: str,
        port: int,
        user: str,
        database: str,
        table: str,
        hot_key: int,
        interval_s: float,
    ) -> None:
        self.ctx = ctx
        self.host = host
        self.port = port
        self.user = user
        self.database = database
        self.table = table
        self.hot_key = hot_key
        self.interval_s = interval_s
        self.rows: List[Dict[str, object]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=10)

    def _run(self) -> None:
        while not self._stop.is_set():
            ts = time.time()
            self.rows.append(
                fetch_hot_leader_observation(
                    self.host,
                    self.port,
                    self.user,
                    self.database,
                    self.table,
                    self.hot_key,
                    self.ctx,
                    ts,
                )
            )
            self._stop.wait(self.interval_s)


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    raw_dir = root / "results" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    if args.clean:
        compose(args.compose_file, ["down", "-v"], root)
    if args.start_services:
        compose(args.compose_file, ["up", "-d"], root)

    wait_for_tidb(args.host, args.port, args.wait_timeout)

    all_results: List[Dict[str, object]] = []
    all_samples: List[Dict[str, object]] = []
    all_leaders: List[Dict[str, object]] = []
    all_events: List[Dict[str, object]] = []
    scenario_names = split_arg(args.scenarios, SCENARIOS.keys())

    for run_id in range(1, args.runs + 1):
        print(f"[tidb-exp2] run_id={run_id}/{args.runs}", flush=True)
        for scenario in scenario_names:
            prepare_schema(args)
            target = discover_hot_region(args)
            ctx = ScenarioContext(
                run_id=run_id,
                scenario=scenario,
                start_ts=time.time(),
                baseline_s=args.baseline_s,
                perturb_s=args.perturb_s,
                recovery_s=args.recovery_s,
                target_region_id=target["region_id"],
                target_store_id=target["leader_store_id"],
                target_container=target["leader_container"],
                perturbation=SCENARIOS[scenario]["perturbation"],
                limited=bool(SCENARIOS[scenario]["limited"]),
            )
            print(
                f"[tidb-exp2] run_id={run_id} scenario={scenario} "
                f"hot_region={ctx.target_region_id} leader_store={ctx.target_store_id} "
                f"target={ctx.target_container}",
                flush=True,
            )

            concurrency = args.limited_concurrency if ctx.limited else args.concurrency
            pool_size = max(concurrency, args.connection_pool_size if not ctx.limited else args.limited_concurrency)
            pool = ConnectionPool(pool_size, args.host, args.port, args.user, args.database, args.sql_timeout_s)
            sampler = ResourceSampler(ctx, args.sample_interval_s)
            observer = LeaderObserver(
                ctx,
                args.host,
                args.port,
                args.user,
                args.database,
                args.items_table,
                args.hot_key,
                args.leader_sample_interval_s,
            )
            event_rows: List[Dict[str, object]] = []
            perturb_thread = threading.Thread(
                target=run_perturbation_schedule,
                args=(args, ctx, event_rows),
                daemon=True,
            )

            sampler.start()
            observer.start()
            perturb_thread.start()
            try:
                results = run_workload(args, ctx, pool, concurrency)
            finally:
                perturb_thread.join(timeout=max(args.perturb_s + 10, 20))
                cleanup_perturbation(ctx.target_container)
                sampler.stop()
                observer.stop()
                pool.close()

            all_results.extend(asdict(result) for result in results)
            all_samples.extend(sampler.samples)
            all_leaders.extend(observer.rows)
            all_events.extend(event_rows)
            success_count = sum(1 for result in results if result.success)
            print(
                f"[tidb-exp2] done run_id={run_id} scenario={scenario} "
                f"requests={len(results)} success={success_count}",
                flush=True,
            )
            time.sleep(args.cooldown_s)

    write_csv(raw_dir / "exp2_tidb_leader_requests.csv", all_results)
    write_csv(raw_dir / "exp2_tidb_tikv_resource_samples.csv", all_samples)
    write_csv(raw_dir / "exp2_tidb_leader_observations.csv", all_leaders)
    write_csv(raw_dir / "exp2_tidb_perturbation_events.csv", all_events)
    print(f"[tidb-exp2] wrote TiDB experiment 2 raw CSV files under {raw_dir}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4000)
    parser.add_argument("--user", default="root")
    parser.add_argument("--database", default="exp2_tidb")
    parser.add_argument("--items-table", default="exp2_leader_items")
    parser.add_argument("--events-table", default="exp2_leader_events")
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--baseline-s", type=float, default=4.0)
    parser.add_argument("--perturb-s", type=float, default=6.0)
    parser.add_argument("--recovery-s", type=float, default=6.0)
    parser.add_argument("--cooldown-s", type=float, default=2.0)
    parser.add_argument("--concurrency", type=int, default=48)
    parser.add_argument("--limited-concurrency", type=int, default=20)
    parser.add_argument("--connection-pool-size", type=int, default=48)
    parser.add_argument("--sample-interval-s", type=float, default=0.5)
    parser.add_argument("--leader-sample-interval-s", type=float, default=1.0)
    parser.add_argument("--sql-timeout-s", type=float, default=3.0)
    parser.add_argument("--wait-timeout", type=float, default=180.0)
    parser.add_argument("--seed", type=int, default=20260513)
    parser.add_argument("--hot-key", type=int, default=3000)
    parser.add_argument("--hot-key-count", type=int, default=5)
    parser.add_argument("--hot-fraction", type=float, default=0.85)
    parser.add_argument("--max-item-id", type=int, default=12000)
    parser.add_argument("--regions", type=int, default=6)
    parser.add_argument("--schema-settle-s", type=float, default=4.0)
    parser.add_argument("--cpu-workers", type=int, default=2)
    parser.add_argument("--compose-file", default="docker-compose.tidb.yml")
    parser.add_argument("--scenarios", default=",".join(SCENARIOS.keys()))
    parser.add_argument("--start-services", action="store_true")
    parser.add_argument("--clean", action="store_true")
    return parser.parse_args()


def compose(compose_file: str, args: List[str], cwd: Path) -> None:
    cmd = ["docker", "compose", "-f", compose_file, *args]
    print("[compose]", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=str(cwd), check=True)


def split_arg(raw: str, allowed: Iterable[str]) -> List[str]:
    allowed_set = set(allowed)
    values = [part.strip() for part in raw.split(",") if part.strip()]
    unknown = [value for value in values if value not in allowed_set]
    if unknown:
        raise SystemExit(f"unknown values: {unknown}; allowed={sorted(allowed_set)}")
    return values


def wait_for_tidb(host: str, port: int, timeout_s: float) -> None:
    deadline = time.time() + timeout_s
    last_error = ""
    while time.time() < deadline:
        try:
            conn = pymysql.connect(host=host, port=port, user="root", connect_timeout=3, autocommit=True)
            with conn.cursor() as cur:
                cur.execute("SELECT VERSION()")
                print(f"[tidb-exp2] connected: {cur.fetchone()[0]}", flush=True)
            conn.close()
            return
        except Exception as exc:
            last_error = str(exc)
            time.sleep(2)
    raise RuntimeError(f"TiDB did not become ready within {timeout_s}s: {last_error}")


def prepare_schema(args: argparse.Namespace) -> None:
    conn = pymysql.connect(host=args.host, port=args.port, user=args.user, autocommit=True, connect_timeout=5)
    with conn.cursor() as cur:
        cur.execute(f"CREATE DATABASE IF NOT EXISTS {args.database}")
        cur.execute(f"USE {args.database}")
        cur.execute(f"DROP TABLE IF EXISTS {args.events_table}")
        cur.execute(f"DROP TABLE IF EXISTS {args.items_table}")
        cur.execute(
            f"""
            CREATE TABLE {args.items_table} (
                item_id BIGINT PRIMARY KEY,
                stock BIGINT NOT NULL DEFAULT 100000,
                version BIGINT NOT NULL DEFAULT 0,
                pad VARCHAR(64) NOT NULL DEFAULT ''
            )
            """
        )
        cur.execute(
            f"""
            CREATE TABLE {args.events_table} (
                event_id BIGINT PRIMARY KEY AUTO_RANDOM,
                item_id BIGINT NOT NULL,
                user_id BIGINT NOT NULL,
                payload VARCHAR(128),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        try:
            cur.execute(f"SPLIT TABLE {args.items_table} BETWEEN (0) AND ({args.max_item_id}) REGIONS {args.regions}")
        except Exception as exc:
            print(f"[tidb-exp2] split warning: {exc}", flush=True)
        rows = [(item_id, 100000, 0, "seed") for item_id in range(1, args.max_item_id + 1)]
        for offset in range(0, len(rows), 1000):
            cur.executemany(
                f"INSERT INTO {args.items_table}(item_id, stock, version, pad) VALUES (%s, %s, %s, %s)",
                rows[offset : offset + 1000],
            )
    conn.close()
    time.sleep(args.schema_settle_s)


def discover_hot_region(args: argparse.Namespace) -> Dict[str, str]:
    regions = fetch_table_regions(args.host, args.port, args.user, args.database, args.items_table)
    stores = fetch_store_map()
    selected = select_region_for_key(regions, args.hot_key) if regions else {}
    if not selected and regions:
        selected = regions[0]
    store_id = clean_id(selected.get("leader_store_id", "")) if selected else ""
    leader_container = stores.get(store_id, "")
    if not leader_container:
        leader_container = TIKV_CONTAINERS[0]
    return {
        "region_id": clean_id(selected.get("region_id", "")) if selected else "",
        "leader_store_id": store_id,
        "leader_container": leader_container,
    }


def fetch_table_regions(host: str, port: int, user: str, database: str, table: str) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    conn = pymysql.connect(host=host, port=port, user=user, database=database, autocommit=True, connect_timeout=5)
    try:
        with conn.cursor() as cur:
            cur.execute(f"SHOW TABLE {table} REGIONS")
            columns = [desc[0].lower() for desc in cur.description]
            for values in cur.fetchall():
                record = dict(zip(columns, values))
                rows.append(
                    {
                        "region_id": first(record, ["region_id", "region id"]),
                        "start_key": first(record, ["start_key", "start key"]),
                        "end_key": first(record, ["end_key", "end key"]),
                        "leader_id": first(record, ["leader_id", "leader id"]),
                        "leader_store_id": first(record, ["leader_store_id", "leader store id"]),
                        "peers": first(record, ["peers"]),
                    }
                )
    finally:
        conn.close()
    return rows


def select_region_for_key(regions: List[Dict[str, object]], key: int) -> Dict[str, object]:
    for region in regions:
        start = parse_region_key_bound(str(region.get("start_key", "")), -math.inf)
        end = parse_region_key_bound(str(region.get("end_key", "")), math.inf)
        if start <= key < end:
            return region
    return regions[0] if regions else {}


def parse_region_key_bound(text: str, default: float) -> float:
    match = re.search(r"_r_(\d+)", text)
    if match:
        return float(match.group(1))
    return default


def fetch_store_map() -> Dict[str, str]:
    try:
        with urllib.request.urlopen("http://127.0.0.1:2379/pd/api/v1/stores", timeout=3) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return {}
    mapping: Dict[str, str] = {}
    for item in payload.get("stores", []):
        store = item.get("store", {})
        store_id = clean_id(store.get("id", ""))
        address = str(store.get("address", ""))
        host = address.split(":", 1)[0]
        container = TIKV_HOST_TO_CONTAINER.get(host)
        if store_id and container:
            mapping[store_id] = container
    return mapping


def first(record: Dict[str, object], keys: List[str]) -> object:
    for key in keys:
        if key in record:
            return record[key]
    return ""


def run_workload(
    args: argparse.Namespace,
    ctx: ScenarioContext,
    pool: ConnectionPool,
    concurrency: int,
) -> List[TidbLeaderResult]:
    results: List[TidbLeaderResult] = []
    results_lock = threading.Lock()
    counter = itertools.count()
    deadline = ctx.start_ts + ctx.total_s

    def worker(worker_id: int) -> None:
        rng = random.Random(args.seed + ctx.run_id * 100000 + worker_id * 1000 + sum(ord(ch) for ch in ctx.scenario))
        while time.time() < deadline:
            request_id = next(counter)
            spec = build_request(args, ctx, request_id, rng)
            result = execute_request(args, ctx, pool, spec)
            with results_lock:
                results.append(result)
            if ctx.limited:
                time.sleep(0.005)

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(worker, worker_id) for worker_id in range(concurrency)]
        for future in futures:
            future.result()
    return results


def build_request(
    args: argparse.Namespace,
    ctx: ScenarioContext,
    request_id: int,
    rng: random.Random,
) -> TidbLeaderRequest:
    is_hot = rng.random() < args.hot_fraction
    if is_hot:
        item_id = args.hot_key + rng.randrange(args.hot_key_count)
    else:
        item_id = rng.randint(1, args.max_item_id)
    return TidbLeaderRequest(
        run_id=ctx.run_id,
        scenario=ctx.scenario,
        request_id=request_id,
        operation=choose_operation(rng),
        item_id=item_id,
        user_id=rng.randint(1, 1000000),
        is_hot=is_hot,
        target_region_id=ctx.target_region_id,
        target_store_id=ctx.target_store_id,
        target_container=ctx.target_container,
    )


def choose_operation(rng: random.Random) -> str:
    marker = rng.random()
    cumulative = 0.0
    for operation, weight in OPERATIONS:
        cumulative += weight
        if marker <= cumulative:
            return operation
    return OPERATIONS[-1][0]


def execute_request(
    args: argparse.Namespace,
    ctx: ScenarioContext,
    pool: ConnectionPool,
    spec: TidbLeaderRequest,
) -> TidbLeaderResult:
    started = time.time()
    success = False
    error = ""
    rows = 0
    conn = None
    try:
        conn = pool.acquire()
        with conn.cursor() as cur:
            if spec.operation == "select":
                cur.execute(f"SELECT stock, version FROM {args.items_table} WHERE item_id=%s", (spec.item_id,))
                rows = cur.rowcount
                cur.fetchall()
            elif spec.operation == "update":
                cur.execute(
                    f"""
                    UPDATE {args.items_table}
                    SET stock = stock + 1, version = version + 1
                    WHERE item_id=%s
                    """,
                    (spec.item_id,),
                )
                rows = cur.rowcount
            elif spec.operation == "insert":
                cur.execute(
                    f"INSERT INTO {args.events_table}(item_id, user_id, payload) VALUES (%s, %s, %s)",
                    (spec.item_id, spec.user_id, f"{spec.scenario}:{spec.request_id}"),
                )
                rows = cur.rowcount
            success = True
    except Exception as exc:
        error = type(exc).__name__
    finally:
        if conn is not None:
            try:
                pool.release(conn)
            except Exception:
                pass
    ended = time.time()
    relative_s = ended - ctx.start_ts
    return TidbLeaderResult(
        run_id=spec.run_id,
        timestamp=iso_ts(ended),
        start_ts=started,
        end_ts=ended,
        relative_s=relative_s,
        phase=phase_for_elapsed(ctx, relative_s),
        system="TiDB",
        scenario=spec.scenario,
        mitigation="client_limited" if ctx.limited else "tidb_native",
        perturbation=ctx.perturbation,
        request_id=spec.request_id,
        operation=spec.operation,
        item_id=spec.item_id,
        user_id=spec.user_id,
        is_hot=spec.is_hot,
        target_region_id=spec.target_region_id,
        target_store_id=spec.target_store_id,
        target_container=spec.target_container,
        success=success,
        error=error,
        latency_ms=(ended - started) * 1000.0,
        rows=rows,
        baseline_s=ctx.baseline_s,
        perturb_s=ctx.perturb_s,
        recovery_s=ctx.recovery_s,
    )


def phase_for_elapsed(ctx: ScenarioContext, elapsed_s: float) -> str:
    if ctx.perturbation == "none":
        return "normal"
    if elapsed_s < ctx.baseline_s:
        return "normal"
    if elapsed_s < ctx.baseline_s + ctx.perturb_s:
        return "perturbation"
    return "recovery"


def run_perturbation_schedule(args: argparse.Namespace, ctx: ScenarioContext, events: List[Dict[str, object]]) -> None:
    if ctx.perturbation == "none":
        return
    delay = max(ctx.start_ts + ctx.baseline_s - time.time(), 0)
    time.sleep(delay)
    start_ts = time.time()
    method = ""
    success = False
    error = ""
    if ctx.perturbation == "cpu":
        method, success, error = start_cpu_stress(ctx.target_container, args.cpu_workers)
    elif ctx.perturbation == "container_pause":
        method, success, error = start_container_pause(ctx.target_container)
    events.append(event_row(ctx, "start", method, success, error, start_ts))
    time.sleep(ctx.perturb_s)
    stop_ts = time.time()
    stop_success = True
    stop_error = ""
    try:
        if ctx.perturbation == "cpu":
            stop_cpu_stress(ctx.target_container)
        elif ctx.perturbation == "container_pause":
            stop_container_pause(ctx.target_container)
    except Exception as exc:
        stop_success = False
        stop_error = str(exc)
    events.append(event_row(ctx, "stop", method, stop_success, stop_error, stop_ts))


def event_row(
    ctx: ScenarioContext,
    event: str,
    method: str,
    success: bool,
    error: str,
    ts: float,
) -> Dict[str, object]:
    return {
        "timestamp": iso_ts(ts),
        "ts": ts,
        "relative_s": ts - ctx.start_ts,
        "run_id": ctx.run_id,
        "system": "TiDB",
        "scenario": ctx.scenario,
        "event": event,
        "perturbation": ctx.perturbation,
        "method": method,
        "target_store_id": ctx.target_store_id,
        "target_container": ctx.target_container,
        "success": success,
        "error": error,
    }


def start_cpu_stress(container: str, workers: int) -> Tuple[str, bool, str]:
    cleanup_perturbation(container)
    script = (
        "rm -f /tmp/exp2_cpu_pids; "
        "i=0; "
        f"while [ $i -lt {workers} ]; do "
        "(while :; do :; done) & echo $! >> /tmp/exp2_cpu_pids; "
        "i=$((i+1)); "
        "done"
    )
    proc = subprocess.run(["docker", "exec", "-d", container, "sh", "-c", script], capture_output=True, text=True)
    return "shell_busy_loop", proc.returncode == 0, proc.stderr.strip()


def stop_cpu_stress(container: str) -> None:
    script = "if [ -f /tmp/exp2_cpu_pids ]; then xargs -r kill < /tmp/exp2_cpu_pids; rm -f /tmp/exp2_cpu_pids; fi"
    subprocess.run(["docker", "exec", container, "sh", "-c", script], check=False, capture_output=True, text=True, timeout=8)


def start_container_pause(container: str) -> Tuple[str, bool, str]:
    cleanup_perturbation(container)
    proc = subprocess.run(["docker", "pause", container], capture_output=True, text=True, timeout=8)
    return "docker_pause", proc.returncode == 0, proc.stderr.strip()


def stop_container_pause(container: str) -> None:
    subprocess.run(["docker", "unpause", container], check=False, capture_output=True, text=True, timeout=8)


def cleanup_perturbation(container: str) -> None:
    try:
        stop_cpu_stress(container)
    except Exception:
        pass
    try:
        subprocess.run(["docker", "unpause", container], check=False, capture_output=True, text=True, timeout=8)
    except Exception:
        pass


def fetch_hot_leader_observation(
    host: str,
    port: int,
    user: str,
    database: str,
    table: str,
    hot_key: int,
    ctx: ScenarioContext,
    ts: float,
) -> Dict[str, object]:
    error = ""
    region_id = ""
    leader_store_id = ""
    leader_container = ""
    leader_store_ids = ""
    try:
        regions = fetch_table_regions(host, port, user, database, table)
        selected = select_region_for_key(regions, hot_key)
        region_id = clean_id(selected.get("region_id", ""))
        leader_store_id = clean_id(selected.get("leader_store_id", ""))
        leader_store_ids = ",".join(sorted({clean_id(row.get("leader_store_id", "")) for row in regions if row}))
        leader_container = fetch_store_map().get(leader_store_id, "")
    except Exception as exc:
        error = type(exc).__name__
    return {
        "timestamp": iso_ts(ts),
        "ts": ts,
        "relative_s": ts - ctx.start_ts,
        "run_id": ctx.run_id,
        "system": "TiDB",
        "scenario": ctx.scenario,
        "phase": phase_for_elapsed(ctx, ts - ctx.start_ts),
        "target_region_id": ctx.target_region_id,
        "target_store_id": ctx.target_store_id,
        "target_container": ctx.target_container,
        "hot_region_id": region_id,
        "hot_leader_store_id": leader_store_id,
        "hot_leader_container": leader_container,
        "leader_changed": bool(leader_store_id and leader_store_id != ctx.target_store_id),
        "leader_store_ids": leader_store_ids,
        "error": error,
    }


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
            return value * 1024
        if unit.lower().startswith("ki"):
            return value / 1024
        return value
    except Exception:
        return None


def clean_id(value: object) -> str:
    text = str(value)
    if text.endswith(".0"):
        text = text[:-2]
    return text


def iso_ts(ts: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts))


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
