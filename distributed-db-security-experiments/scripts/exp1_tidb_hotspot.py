#!/usr/bin/env python3
"""Run TiDB comparison for experiment 1.

This script intentionally uses normal SQL traffic. The hotspot is created by
skewing requests toward a narrow primary-key range so that TiDB exposes the
corresponding Region/Leader behavior.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from pathlib import Path
from queue import Queue
from typing import Dict, Iterable, List, Optional

import pymysql


SCENARIOS = {"tidb_uniform": 0.0, "tidb_hot70": 0.70, "tidb_hot90": 0.90}
OPERATIONS = (("select", 0.70), ("update", 0.20), ("insert", 0.10))
HOT_KEYS = [3000, 3001, 3002, 3003, 3004]
TIKV_CONTAINERS = ["exp1_tidb_tikv0", "exp1_tidb_tikv1", "exp1_tidb_tikv2"]


@dataclass(frozen=True)
class TidbRequest:
    run_id: int
    request_id: int
    scenario: str
    operation: str
    item_id: int
    user_id: int
    is_hot: bool
    hot_fraction: float


@dataclass
class TidbResult:
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
    def __init__(self, size: int, host: str, port: int, user: str, database: str) -> None:
        self._queue: Queue = Queue(maxsize=size)
        for _ in range(size):
            conn = pymysql.connect(
                host=host,
                port=port,
                user=user,
                database=database,
                autocommit=True,
                connect_timeout=5,
                read_timeout=5,
                write_timeout=5,
                charset="utf8mb4",
            )
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
            self.samples.extend(fetch_tikv_stats(self.run_id, self.scenario))
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
    all_regions: List[Dict[str, object]] = []
    scenario_names = split_arg(args.scenarios, SCENARIOS.keys())

    for run_id in range(1, args.runs + 1):
        print(f"[tidb-exp1] run_id={run_id}/{args.runs}", flush=True)
        prepare_schema(args.host, args.port, args.user, args.database)
        for scenario in scenario_names:
            specs = build_workload(run_id, scenario, args.requests, args.seed + run_id * 100000)
            all_regions.extend(
                fetch_region_observations(args.host, args.port, args.user, args.database, run_id, scenario, "before")
            )
            sampler = ResourceSampler(run_id, scenario, args.sample_interval_s)
            pool = ConnectionPool(args.connection_pool_size, args.host, args.port, args.user, args.database)
            sampler.start()
            started = time.time()
            try:
                print(
                    f"[tidb-exp1] run_id={run_id} scenario={scenario} "
                    f"requests={len(specs)} concurrency={args.concurrency}",
                    flush=True,
                )
                results = run_workload(pool, specs, args.concurrency)
            finally:
                sampler.stop()
                pool.close()
            elapsed = time.time() - started
            success_count = sum(1 for result in results if result.success)
            print(
                f"[tidb-exp1] done run_id={run_id} scenario={scenario} elapsed={elapsed:.2f}s "
                f"success={success_count}/{len(results)}",
                flush=True,
            )
            all_results.extend(asdict(result) for result in results)
            all_samples.extend(sampler.samples)
            all_regions.extend(
                fetch_region_observations(args.host, args.port, args.user, args.database, run_id, scenario, "after")
            )

    write_csv(raw_dir / "exp1_tidb_hotspot_requests.csv", all_results)
    write_csv(raw_dir / "exp1_tidb_tikv_resource_samples.csv", all_samples)
    write_csv(raw_dir / "exp1_tidb_region_observations.csv", all_regions)
    print(f"[tidb-exp1] wrote TiDB raw CSV files under {raw_dir}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=4000)
    parser.add_argument("--user", default="root")
    parser.add_argument("--database", default="exp1_tidb")
    parser.add_argument("--requests", type=int, default=900)
    parser.add_argument("--runs", type=int, default=1)
    parser.add_argument("--concurrency", type=int, default=96)
    parser.add_argument("--connection-pool-size", type=int, default=96)
    parser.add_argument("--sample-interval-s", type=float, default=0.5)
    parser.add_argument("--seed", type=int, default=20260512)
    parser.add_argument("--wait-timeout", type=float, default=180.0)
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
                print(f"[tidb-exp1] connected: {cur.fetchone()[0]}", flush=True)
            conn.close()
            return
        except Exception as exc:
            last_error = str(exc)
            time.sleep(2)
    raise RuntimeError(f"TiDB did not become ready within {timeout_s}s: {last_error}")


def prepare_schema(host: str, port: int, user: str, database: str) -> None:
    conn = pymysql.connect(host=host, port=port, user=user, autocommit=True, connect_timeout=5)
    with conn.cursor() as cur:
        cur.execute(f"CREATE DATABASE IF NOT EXISTS {database}")
        cur.execute(f"USE {database}")
        cur.execute("DROP TABLE IF EXISTS exp1_tidb_events")
        cur.execute("DROP TABLE IF EXISTS exp1_tidb_items")
        cur.execute(
            """
            CREATE TABLE exp1_tidb_items (
                item_id BIGINT PRIMARY KEY,
                stock BIGINT NOT NULL DEFAULT 100000,
                version BIGINT NOT NULL DEFAULT 0,
                pad VARCHAR(64) NOT NULL DEFAULT ''
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE exp1_tidb_events (
                event_id BIGINT PRIMARY KEY AUTO_RANDOM,
                item_id BIGINT NOT NULL,
                user_id BIGINT NOT NULL,
                payload VARCHAR(128),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        try:
            cur.execute("SPLIT TABLE exp1_tidb_items BETWEEN (0) AND (30000) REGIONS 9")
            cur.execute("SCATTER TABLE exp1_tidb_items")
        except Exception as exc:
            print(f"[tidb-exp1] split/scatter warning: {exc}", flush=True)
        rows = [(item_id, 100000, 0, "seed") for item_id in range(1, 30001)]
        for offset in range(0, len(rows), 1000):
            cur.executemany(
                "INSERT INTO exp1_tidb_items(item_id, stock, version, pad) VALUES (%s, %s, %s, %s)",
                rows[offset : offset + 1000],
            )
    conn.close()
    time.sleep(8)


def build_workload(run_id: int, scenario: str, requests: int, seed: int) -> List[TidbRequest]:
    rng = random.Random(seed + sum(ord(ch) for ch in scenario))
    hot_fraction = SCENARIOS[scenario]
    specs: List[TidbRequest] = []
    for request_id in range(requests):
        is_hot = hot_fraction > 0 and rng.random() < hot_fraction
        item_id = rng.choice(HOT_KEYS) if is_hot else rng.randint(1, 30000)
        specs.append(
            TidbRequest(
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


def run_workload(pool: ConnectionPool, specs: List[TidbRequest], concurrency: int) -> List[TidbResult]:
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(execute_request, pool, spec) for spec in specs]
        return [future.result() for future in as_completed(futures)]


def execute_request(pool: ConnectionPool, spec: TidbRequest) -> TidbResult:
    started = time.time()
    success = False
    error = ""
    rows = 0
    conn = None
    try:
        conn = pool.acquire()
        with conn.cursor() as cur:
            if spec.operation == "select":
                cur.execute("SELECT stock, version FROM exp1_tidb_items WHERE item_id=%s", (spec.item_id,))
                rows = cur.rowcount
                cur.fetchall()
            elif spec.operation == "update":
                cur.execute(
                    """
                    UPDATE exp1_tidb_items
                    SET stock = stock + 1, version = version + 1
                    WHERE item_id=%s
                    """,
                    (spec.item_id,),
                )
                rows = cur.rowcount
            elif spec.operation == "insert":
                cur.execute(
                    "INSERT INTO exp1_tidb_events(item_id, user_id, payload) VALUES (%s, %s, %s)",
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
    return TidbResult(
        run_id=spec.run_id,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ended)),
        start_ts=started,
        end_ts=ended,
        system="TiDB",
        scenario=spec.scenario,
        defense="tidb_native",
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


def fetch_tikv_stats(run_id: int, scenario: str) -> List[Dict[str, object]]:
    stats = docker_stats(TIKV_CONTAINERS)
    rows = []
    for name in TIKV_CONTAINERS:
        item = stats.get(name, {})
        rows.append(
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "ts": time.time(),
                "run_id": run_id,
                "system": "TiDB",
                "scenario": scenario,
                "component": "TiKV",
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
            return value * 1024
        if unit.lower().startswith("ki"):
            return value / 1024
        return value
    except Exception:
        return None


def fetch_region_observations(
    host: str,
    port: int,
    user: str,
    database: str,
    run_id: int,
    scenario: str,
    phase: str,
) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    conn = pymysql.connect(host=host, port=port, user=user, database=database, autocommit=True, connect_timeout=5)
    try:
        with conn.cursor() as cur:
            cur.execute("SHOW TABLE exp1_tidb_items REGIONS")
            columns = [desc[0] for desc in cur.description]
            for values in cur.fetchall():
                record = dict(zip(columns, values))
                rows.append(normalize_region_record(record, run_id, scenario, phase))
    except Exception as exc:
        rows.append(
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "ts": time.time(),
                "run_id": run_id,
                "system": "TiDB",
                "scenario": scenario,
                "phase": phase,
                "region_id": "",
                "leader_store_id": "",
                "leader_id": "",
                "peers": "",
                "start_key": "",
                "end_key": "",
                "written_bytes": "",
                "read_bytes": "",
                "approximate_size_mb": "",
                "error": str(exc),
            }
        )
    finally:
        conn.close()
    rows.extend(fetch_pd_hot_regions(run_id, scenario, phase))
    return rows


def normalize_region_record(record: Dict[str, object], run_id: int, scenario: str, phase: str) -> Dict[str, object]:
    lower = {str(key).lower(): value for key, value in record.items()}
    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "ts": time.time(),
        "run_id": run_id,
        "system": "TiDB",
        "scenario": scenario,
        "phase": phase,
        "region_id": first(lower, ["region_id", "region id"]),
        "leader_store_id": first(lower, ["leader_store_id", "leader store id"]),
        "leader_id": first(lower, ["leader_id", "leader id"]),
        "peers": first(lower, ["peers"]),
        "start_key": first(lower, ["start_key", "start key"]),
        "end_key": first(lower, ["end_key", "end key"]),
        "written_bytes": first(lower, ["written_bytes", "written bytes"]),
        "read_bytes": first(lower, ["read_bytes", "read bytes"]),
        "approximate_size_mb": first(lower, ["approximate_size(mb)", "approximate_size", "approximate size"]),
        "error": "",
    }


def first(record: Dict[str, object], keys: List[str]) -> object:
    for key in keys:
        if key in record:
            return record[key]
    return ""


def fetch_pd_hot_regions(run_id: int, scenario: str, phase: str) -> List[Dict[str, object]]:
    rows = []
    for kind in ["write", "read"]:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:2379/pd/api/v1/hotspot/regions/{kind}", timeout=3) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            rows.append(
                {
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    "ts": time.time(),
                    "run_id": run_id,
                    "system": "TiDB",
                    "scenario": scenario,
                    "phase": f"{phase}_pd_hot_{kind}",
                    "region_id": "",
                    "leader_store_id": "",
                    "leader_id": "",
                    "peers": json.dumps(payload, ensure_ascii=False)[:2000],
                    "start_key": "",
                    "end_key": "",
                    "written_bytes": "",
                    "read_bytes": "",
                    "approximate_size_mb": "",
                    "error": "",
                }
            )
        except Exception as exc:
            rows.append(
                {
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                    "ts": time.time(),
                    "run_id": run_id,
                    "system": "TiDB",
                    "scenario": scenario,
                    "phase": f"{phase}_pd_hot_{kind}",
                    "region_id": "",
                    "leader_store_id": "",
                    "leader_id": "",
                    "peers": "",
                    "start_key": "",
                    "end_key": "",
                    "written_bytes": "",
                    "read_bytes": "",
                    "approximate_size_mb": "",
                    "error": str(exc),
                }
            )
    return rows


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
