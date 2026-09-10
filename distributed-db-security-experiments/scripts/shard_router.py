#!/usr/bin/env python3
"""Routing and defense primitives for experiment 1.

The router intentionally models legitimate application traffic. Every request is
syntactically normal SQL, so the experiment measures data-distribution pressure
rather than SQL-injection detection. Experiment 1 compares a public deterministic
route with an obfuscated route that hides the key-to-shard mapping.
"""

from __future__ import annotations

import os
import hashlib
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Tuple

import psycopg2
from psycopg2 import pool


SHARD_COUNT = 3
CONTAINER_NAMES = {
    0: "exp1_pg_shard_0",
    1: "exp1_pg_shard_1",
    2: "exp1_pg_shard_2",
}


@dataclass(frozen=True)
class RequestSpec:
    request_id: int
    scenario: str
    defense: str
    operation: str
    item_id: int
    user_id: int
    is_hot: bool
    hot_fraction: float
    db_sleep_ms: float


@dataclass
class RequestResult:
    timestamp: str
    start_ts: float
    end_ts: float
    scenario: str
    defense: str
    request_id: int
    operation: str
    item_id: int
    user_id: int
    is_hot: bool
    hot_fraction: float
    target_shard: int
    physical_shard: str
    success: bool
    error: str
    latency_ms: float
    rows: int


class PoolTimeout(RuntimeError):
    pass


class RateLimited(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ConnectionManager:
    def __init__(
        self,
        shard_id: int,
        dsn: str,
        max_connections: int,
        statement_timeout_ms: int,
    ) -> None:
        self.shard_id = shard_id
        dsn_with_timeout = f"{dsn} options='-c statement_timeout={statement_timeout_ms}'"
        self._pool = pool.ThreadedConnectionPool(1, max_connections, dsn_with_timeout)
        self._slots = threading.BoundedSemaphore(max_connections)

    def acquire(self, timeout_s: float):
        if not self._slots.acquire(timeout=timeout_s):
            raise PoolTimeout(f"pool_timeout_shard_{self.shard_id}")
        try:
            conn = self._pool.getconn()
            conn.autocommit = True
            return conn
        except Exception:
            self._slots.release()
            raise

    def release(self, conn) -> None:
        try:
            self._pool.putconn(conn)
        finally:
            self._slots.release()

    def close(self) -> None:
        self._pool.closeall()


class DefenseController:
    def __init__(
        self,
        defense: str,
        hot_keys: Iterable[int],
        shard_limit: int = 36,
        hot_key_limit: int = 2,
        queue_hot_limit: int = 12,
        traffic_control_limit: int = 30,
    ) -> None:
        self.defense = defense
        self.hot_keys = set(hot_keys)
        self._shard_limits = {
            shard_id: threading.BoundedSemaphore(shard_limit)
            for shard_id in range(SHARD_COUNT)
        }
        self._traffic_control_limits = {
            shard_id: threading.BoundedSemaphore(traffic_control_limit)
            for shard_id in range(SHARD_COUNT)
        }
        self._hot_key_limit = hot_key_limit
        self._hot_key_lock = threading.Lock()
        self._hot_key_sems: Dict[int, threading.BoundedSemaphore] = {}
        self._queue_hot_limit = threading.BoundedSemaphore(queue_hot_limit)

    def before(self, spec: RequestSpec, target_shard: int) -> Tuple[str, Optional[Tuple[str, object]]]:
        if self.defense in {"deterministic", "obfuscated", "baseline"}:
            return "db", None

        if self.defense == "obfuscated_control":
            sem = self._traffic_control_limits[target_shard]
            if not sem.acquire(timeout=0.250):
                raise RateLimited("traffic_control")
            return "db", ("semaphore", sem)

        if self.defense == "shard_limit":
            sem = self._shard_limits[target_shard]
            if not sem.acquire(timeout=0.015):
                raise RateLimited("shard_limit")
            return "db", ("semaphore", sem)

        if self.defense == "hot_key_limit":
            if spec.item_id in self.hot_keys:
                sem = self._hot_key_semaphore(spec.item_id)
                if not sem.acquire(timeout=0.010):
                    raise RateLimited("hot_key_limit")
                return "db", ("semaphore", sem)
            return "db", None

        if self.defense == "queue_isolation":
            if spec.is_hot and spec.operation == "select":
                return "cache", None
            if spec.is_hot:
                if not self._queue_hot_limit.acquire(timeout=0.250):
                    raise RateLimited("hot_queue_full")
                return "db", ("semaphore", self._queue_hot_limit)
            return "db", None

        raise ValueError(f"unknown defense: {self.defense}")

    def after(self, token: Optional[Tuple[str, object]]) -> None:
        if token and token[0] == "semaphore":
            token[1].release()

    def _hot_key_semaphore(self, item_id: int) -> threading.BoundedSemaphore:
        with self._hot_key_lock:
            sem = self._hot_key_sems.get(item_id)
            if sem is None:
                sem = threading.BoundedSemaphore(self._hot_key_limit)
                self._hot_key_sems[item_id] = sem
            return sem


class ShardRouter:
    def __init__(
        self,
        dsns: List[str],
        defense: str,
        hot_keys: Iterable[int],
        max_connections_per_shard: int = 24,
        statement_timeout_ms: int = 1200,
        pool_timeout_s: float = 1.0,
        route_salt: str = "chapter3-obfuscated-routing",
        virtual_buckets: int = 64,
        traffic_control_limit: int = 30,
    ) -> None:
        self.defense = defense
        self.pool_timeout_s = pool_timeout_s
        self.route_salt = route_salt
        self.virtual_buckets = max(virtual_buckets, SHARD_COUNT)
        self.bucket_to_shard = [bucket % SHARD_COUNT for bucket in range(self.virtual_buckets)]
        self.route_strategy = "obfuscated" if defense in {"obfuscated", "obfuscated_control"} else "deterministic"
        self.managers = [
            ConnectionManager(i, dsn, max_connections_per_shard, statement_timeout_ms)
            for i, dsn in enumerate(dsns)
        ]
        self.defense_controller = DefenseController(defense, hot_keys, traffic_control_limit=traffic_control_limit)

    def route(self, item_id: int) -> int:
        if self.route_strategy == "obfuscated":
            return self.obfuscated_route(item_id)
        return self.deterministic_route(item_id)

    @staticmethod
    def deterministic_route(item_id: int) -> int:
        return item_id % SHARD_COUNT

    def obfuscated_route(self, item_id: int) -> int:
        digest = hashlib.sha256(f"{self.route_salt}:{item_id}".encode()).digest()
        bucket = digest[0] % self.virtual_buckets
        return self.bucket_to_shard[bucket]

    def execute(self, spec: RequestSpec) -> RequestResult:
        target_shard = self.route(spec.item_id)
        started = time.time()
        physical_shard = f"shard-{target_shard}"
        success = False
        error = ""
        rows = 0
        token = None
        try:
            action, token = self.defense_controller.before(spec, target_shard)
            if action == "cache":
                physical_shard = "cache"
                rows = 1
                success = True
                return self._result(started, spec, target_shard, physical_shard, success, error, rows)

            manager = self.managers[target_shard]
            conn = manager.acquire(timeout_s=self.pool_timeout_s)
            try:
                rows = self._execute_sql(conn, spec)
                success = True
            finally:
                manager.release(conn)
        except RateLimited as exc:
            error = exc.reason
        except PoolTimeout as exc:
            error = str(exc)
        except psycopg2.errors.QueryCanceled:
            error = "statement_timeout"
        except Exception as exc:
            error = type(exc).__name__
        finally:
            self.defense_controller.after(token)

        return self._result(started, spec, target_shard, physical_shard, success, error, rows)

    def _execute_sql(self, conn, spec: RequestSpec) -> int:
        sleep_s = max(spec.db_sleep_ms, 0.0) / 1000.0
        with conn.cursor() as cur:
            if spec.operation == "select":
                cur.execute(
                    """
                    WITH delay AS (SELECT pg_sleep(%s))
                    SELECT stock, version
                    FROM items, delay
                    WHERE item_id = %s
                    """,
                    (sleep_s, spec.item_id),
                )
                return cur.rowcount

            if spec.operation == "update":
                cur.execute(
                    """
                    WITH delay AS (SELECT pg_sleep(%s))
                    UPDATE items
                    SET stock = stock + 1,
                        version = version + 1,
                        updated_at = clock_timestamp()
                    FROM delay
                    WHERE item_id = %s
                    RETURNING stock, version
                    """,
                    (sleep_s, spec.item_id),
                )
                return cur.rowcount

            if spec.operation == "insert":
                cur.execute(
                    """
                    WITH delay AS (SELECT pg_sleep(%s))
                    INSERT INTO request_events(item_id, user_id, payload)
                    SELECT %s, %s, %s
                    FROM delay
                    RETURNING event_id
                    """,
                    (
                        sleep_s,
                        spec.item_id,
                        spec.user_id,
                        f"{spec.scenario}:{spec.defense}:{spec.request_id}",
                    ),
                )
                return cur.rowcount

        raise ValueError(f"unknown operation: {spec.operation}")

    def _result(
        self,
        started: float,
        spec: RequestSpec,
        target_shard: int,
        physical_shard: str,
        success: bool,
        error: str,
        rows: int,
    ) -> RequestResult:
        ended = time.time()
        return RequestResult(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ended)),
            start_ts=started,
            end_ts=ended,
            scenario=spec.scenario,
            defense=spec.defense,
            request_id=spec.request_id,
            operation=spec.operation,
            item_id=spec.item_id,
            user_id=spec.user_id,
            is_hot=spec.is_hot,
            hot_fraction=spec.hot_fraction,
            target_shard=target_shard,
            physical_shard=physical_shard,
            success=success,
            error=error,
            latency_ms=(ended - started) * 1000.0,
            rows=rows,
        )

    def close(self) -> None:
        for manager in self.managers:
            manager.close()


def default_dsns(host: str = "127.0.0.1") -> List[str]:
    user = os.getenv("EXP1_PG_USER", "expuser")
    password = os.getenv("EXP1_PG_PASSWORD", "exp_pass_123")
    dbname = os.getenv("EXP1_PG_DB", "expdb")
    ports = [5540, 5541, 5542]
    return [
        f"host={host} port={port} dbname={dbname} user={user} password={password}"
        for port in ports
    ]


def wait_for_shards(dsns: List[str], timeout_s: float = 90.0) -> None:
    deadline = time.time() + timeout_s
    remaining = set(range(len(dsns)))
    while remaining and time.time() < deadline:
        for shard_id in list(remaining):
            try:
                conn = psycopg2.connect(dsns[shard_id])
                conn.close()
                remaining.remove(shard_id)
            except Exception:
                pass
        if remaining:
            time.sleep(1.0)
    if remaining:
        raise RuntimeError(f"PostgreSQL shards not ready: {sorted(remaining)}")


def fetch_resource_sample(dsns: List[str], scenario: str, defense: str) -> List[Dict[str, object]]:
    docker_stats = _docker_stats()
    samples: List[Dict[str, object]] = []
    for shard_id, dsn in enumerate(dsns):
        connections = None
        active = None
        try:
            conn = psycopg2.connect(dsn)
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    """
                    SELECT count(*)::int,
                           count(*) FILTER (WHERE state = 'active')::int
                    FROM pg_stat_activity
                    WHERE datname = current_database()
                    """
                )
                connections, active = cur.fetchone()
            conn.close()
        except Exception:
            pass

        container_name = CONTAINER_NAMES[shard_id]
        stats = docker_stats.get(container_name, {})
        samples.append(
            {
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "ts": time.time(),
                "scenario": scenario,
                "defense": defense,
                "shard": shard_id,
                "container": container_name,
                "cpu_percent": stats.get("cpu_percent"),
                "memory_mb": stats.get("memory_mb"),
                "connections": connections,
                "active_transactions": active,
            }
        )
    return samples


def _docker_stats() -> Dict[str, Dict[str, float]]:
    names = [CONTAINER_NAMES[i] for i in range(SHARD_COUNT)]
    cmd = [
        "docker",
        "stats",
        "--no-stream",
        "--format",
        "{{.Name}},{{.CPUPerc}},{{.MemUsage}}",
        *names,
    ]
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=8)
    except Exception:
        return {}
    stats: Dict[str, Dict[str, float]] = {}
    for line in proc.stdout.splitlines():
        parts = line.split(",", 2)
        if len(parts) != 3:
            continue
        name, cpu_raw, mem_raw = parts
        stats[name] = {
            "cpu_percent": _parse_percent(cpu_raw),
            "memory_mb": _parse_mem_mb(mem_raw),
        }
    return stats


def _parse_percent(raw: str) -> Optional[float]:
    try:
        return float(raw.strip().rstrip("%"))
    except Exception:
        return None


def _parse_mem_mb(raw: str) -> Optional[float]:
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
