#!/usr/bin/env python3
"""Run experiment 3: cross-shard front-running window simulation.

This is a controlled mechanism simulation on three PostgreSQL shards:

* shard-0: user eligibility check
* shard-1: inventory deduction
* shard-2: order confirmation/audit

The victim transaction arrives first but is delayed between user check and
inventory deduction. The attacker arrives later and tries to commit inventory
first. Defenses are implemented at the routing/coordination layer.
"""

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
from typing import Dict, Iterable, List, Optional

import psycopg2
from psycopg2 import pool

from shard_router import default_dsns, wait_for_shards


DEFENSES = ["baseline", "global_sequence", "occ", "conflict_key_queue", "two_phase_commit"]
DEFENSE_INDEX = {name: idx for idx, name in enumerate(DEFENSES)}


@dataclass(frozen=True)
class TxnSpec:
    run_id: int
    seed: int
    defense: str
    pair_id: int
    txn_id: str
    actor: str
    item_id: int
    user_id: int
    arrival_rank: int
    global_seq: int
    victim_window_ms: float
    attacker_entry_delay_ms: float
    user_check_ms: float


@dataclass
class TxnResult:
    run_id: int
    seed: int
    timestamp: str
    start_ts: float
    end_ts: float
    scenario: str
    defense: str
    pair_id: int
    txn_id: str
    actor: str
    item_id: int
    user_id: int
    arrival_rank: int
    global_seq: int
    success: bool
    rollback: bool
    error: str
    user_check_start_ts: float
    user_check_end_ts: float
    inventory_start_ts: float
    inventory_commit_ts: Optional[float]
    order_commit_ts: Optional[float]
    latency_ms: float
    wait_ms: float
    stock_after: Optional[int]
    version_after: Optional[int]


class PgPools:
    def __init__(self, dsns: List[str], maxconn: int) -> None:
        self._pools = [pool.ThreadedConnectionPool(1, maxconn, dsn) for dsn in dsns]

    def acquire(self, shard_id: int, autocommit: bool = True):
        conn = self._pools[shard_id].getconn()
        conn.autocommit = autocommit
        return conn

    def release(self, shard_id: int, conn) -> None:
        self._pools[shard_id].putconn(conn)

    def close(self) -> None:
        for pg_pool in self._pools:
            pg_pool.closeall()


class GlobalSequenceController:
    def __init__(self, item_to_first_seq: Dict[int, int]) -> None:
        self._expected = dict(item_to_first_seq)
        self._condition = threading.Condition()

    def wait_turn(self, item_id: int, seq: int) -> float:
        started = time.time()
        with self._condition:
            while self._expected.get(item_id, seq) != seq:
                self._condition.wait(timeout=0.05)
        return (time.time() - started) * 1000.0

    def mark_done(self, item_id: int, seq: int) -> None:
        with self._condition:
            if self._expected.get(item_id) == seq:
                self._expected[item_id] = seq + 1
            self._condition.notify_all()


class OccController:
    def __init__(self, item_to_pending_seqs: Dict[int, List[int]]) -> None:
        self._pending = {item_id: sorted(seqs) for item_id, seqs in item_to_pending_seqs.items()}
        self._lock = threading.Lock()

    def can_commit(self, item_id: int, seq: int) -> bool:
        with self._lock:
            pending = self._pending.get(item_id, [])
            return bool(pending) and pending[0] == seq

    def mark_done(self, item_id: int, seq: int) -> None:
        with self._lock:
            pending = self._pending.get(item_id, [])
            if seq in pending:
                pending.remove(seq)


class ConflictKeyQueue:
    def __init__(self, item_ids: Iterable[int]) -> None:
        self._locks = {item_id: threading.Lock() for item_id in item_ids}

    def acquire(self, item_id: int) -> tuple[threading.Lock, float]:
        started = time.time()
        lock = self._locks[item_id]
        lock.acquire()
        return lock, (time.time() - started) * 1000.0


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    raw_dir = root / "results" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    if args.clean:
        compose(args.compose_file, ["down", "-v"], root)
    if args.start_services:
        compose(args.compose_file, ["up", "-d"], root)

    dsns = default_dsns(args.host)
    wait_for_shards(dsns, timeout_s=args.wait_timeout)

    all_txns: List[Dict[str, object]] = []
    all_pairs: List[Dict[str, object]] = []
    defense_names = split_arg(args.defenses, DEFENSES)

    for run_id in range(1, args.runs + 1):
        print(f"[exp3] run_id={run_id}/{args.runs}", flush=True)
        for defense in defense_names:
            seed = args.seed + run_id * 100000 + DEFENSE_INDEX[defense] * 1000
            rng = random.Random(seed)
            specs = build_specs(args, run_id, seed, defense, rng)
            prepare_schema(dsns, args, specs)
            pools = PgPools(dsns, maxconn=args.pool_size)
            item_ids = sorted({spec.item_id for spec in specs})
            global_controller = GlobalSequenceController({item_id: item_id_to_victim_seq(specs, item_id) for item_id in item_ids})
            occ_controller = OccController(item_to_pending_seqs(specs))
            queue = ConflictKeyQueue(item_ids)
            print(
                f"[exp3] run_id={run_id} defense={defense} pairs={args.pairs} "
                f"concurrency={args.concurrency}",
                flush=True,
            )
            started = time.time()
            try:
                results = run_workload(args, pools, specs, global_controller, occ_controller, queue)
            finally:
                pools.close()
            elapsed = time.time() - started
            pair_rows = build_pair_rows(results, args.initial_stock)
            all_txns.extend(asdict(result) for result in results)
            all_pairs.extend(pair_rows)
            front_runs = sum(1 for row in pair_rows if row["front_run_success"])
            print(
                f"[exp3] done run_id={run_id} defense={defense} elapsed={elapsed:.2f}s "
                f"front_run={front_runs}/{len(pair_rows)}",
                flush=True,
            )

    write_csv(raw_dir / "exp3_cross_shard_transactions.csv", all_txns)
    write_csv(raw_dir / "exp3_cross_shard_pairs.csv", all_pairs)
    print(f"[exp3] wrote experiment 3 raw CSV files under {raw_dir}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--pairs", type=int, default=120, help="victim/attacker pairs per defense and run")
    parser.add_argument("--concurrency", type=int, default=64)
    parser.add_argument("--pool-size", type=int, default=96)
    parser.add_argument("--initial-stock", type=int, default=2)
    parser.add_argument("--victim-window-ms", type=float, default=60.0)
    parser.add_argument("--attacker-entry-delay-ms", type=float, default=8.0)
    parser.add_argument("--user-check-ms", type=float, default=1.5)
    parser.add_argument("--seed", type=int, default=20260514)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--compose-file", default="docker-compose.postgres-shards.yml")
    parser.add_argument("--wait-timeout", type=float, default=120.0)
    parser.add_argument("--defenses", default=",".join(DEFENSES))
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


def build_specs(
    args: argparse.Namespace,
    run_id: int,
    seed: int,
    defense: str,
    rng: random.Random,
) -> List[TxnSpec]:
    specs: List[TxnSpec] = []
    base_item_id = 700000 + run_id * 100000 + DEFENSE_INDEX[defense] * 10000
    base_user_id = 900000 + run_id * 100000 + DEFENSE_INDEX[defense] * 10000
    for pair_id in range(args.pairs):
        item_id = base_item_id + pair_id
        victim_seq = pair_id * 2
        attacker_seq = victim_seq + 1
        jitter = rng.uniform(-0.15, 0.15)
        victim_window_ms = max(args.victim_window_ms * (1 + jitter), 1.0)
        specs.append(
            TxnSpec(
                run_id=run_id,
                seed=seed,
                defense=defense,
                pair_id=pair_id,
                txn_id=f"r{run_id}-{defense}-p{pair_id}-victim",
                actor="victim",
                item_id=item_id,
                user_id=base_user_id + pair_id * 2,
                arrival_rank=0,
                global_seq=victim_seq,
                victim_window_ms=victim_window_ms,
                attacker_entry_delay_ms=args.attacker_entry_delay_ms,
                user_check_ms=args.user_check_ms,
            )
        )
        specs.append(
            TxnSpec(
                run_id=run_id,
                seed=seed,
                defense=defense,
                pair_id=pair_id,
                txn_id=f"r{run_id}-{defense}-p{pair_id}-attacker",
                actor="attacker",
                item_id=item_id,
                user_id=base_user_id + pair_id * 2 + 1,
                arrival_rank=1,
                global_seq=attacker_seq,
                victim_window_ms=victim_window_ms,
                attacker_entry_delay_ms=args.attacker_entry_delay_ms,
                user_check_ms=args.user_check_ms,
            )
        )
    return specs


def item_id_to_victim_seq(specs: List[TxnSpec], item_id: int) -> int:
    return min(spec.global_seq for spec in specs if spec.item_id == item_id)


def item_to_pending_seqs(specs: List[TxnSpec]) -> Dict[int, List[int]]:
    rows: Dict[int, List[int]] = {}
    for spec in specs:
        rows.setdefault(spec.item_id, []).append(spec.global_seq)
    return rows


def prepare_schema(dsns: List[str], args: argparse.Namespace, specs: List[TxnSpec]) -> None:
    user_rows = [(spec.user_id, True, 0) for spec in specs]
    item_rows = sorted({(spec.item_id, args.initial_stock, 0) for spec in specs})
    execute_statements(
        dsns[0],
        [
            """
            CREATE TABLE IF NOT EXISTS exp3_users (
                user_id INTEGER PRIMARY KEY,
                eligible BOOLEAN NOT NULL,
                version INTEGER NOT NULL DEFAULT 0
            )
            """,
            "TRUNCATE exp3_users",
        ],
    )
    execute_many(dsns[0], "INSERT INTO exp3_users(user_id, eligible, version) VALUES (%s, %s, %s)", user_rows)
    execute_statements(
        dsns[1],
        [
            """
            CREATE TABLE IF NOT EXISTS exp3_inventory (
                item_id INTEGER PRIMARY KEY,
                stock INTEGER NOT NULL,
                version INTEGER NOT NULL DEFAULT 0,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
            )
            """,
            "TRUNCATE exp3_inventory",
        ],
    )
    execute_many(dsns[1], "INSERT INTO exp3_inventory(item_id, stock, version) VALUES (%s, %s, %s)", item_rows)
    execute_statements(
        dsns[2],
        [
            """
            CREATE TABLE IF NOT EXISTS exp3_orders (
                order_id BIGSERIAL PRIMARY KEY,
                run_id INTEGER NOT NULL,
                defense TEXT NOT NULL,
                pair_id INTEGER NOT NULL,
                txn_id TEXT NOT NULL,
                actor TEXT NOT NULL,
                item_id INTEGER NOT NULL,
                user_id INTEGER NOT NULL,
                global_seq INTEGER NOT NULL,
                status TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
            )
            """,
            "TRUNCATE exp3_orders",
        ],
    )


def execute_statements(dsn: str, statements: List[str]) -> None:
    conn = psycopg2.connect(dsn)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            for statement in statements:
                cur.execute(statement)
    finally:
        conn.close()


def execute_many(dsn: str, statement: str, rows: List[tuple]) -> None:
    conn = psycopg2.connect(dsn)
    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.executemany(statement, rows)
    finally:
        conn.close()


def run_workload(
    args: argparse.Namespace,
    pools: PgPools,
    specs: List[TxnSpec],
    global_controller: GlobalSequenceController,
    occ_controller: OccController,
    queue: ConflictKeyQueue,
) -> List[TxnResult]:
    results: List[TxnResult] = []
    with ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = [
            executor.submit(execute_transaction, pools, spec, global_controller, occ_controller, queue)
            for spec in specs
        ]
        for future in as_completed(futures):
            results.append(future.result())
    return results


def execute_transaction(
    pools: PgPools,
    spec: TxnSpec,
    global_controller: GlobalSequenceController,
    occ_controller: OccController,
    queue: ConflictKeyQueue,
) -> TxnResult:
    if spec.actor == "attacker":
        time.sleep(spec.attacker_entry_delay_ms / 1000.0)

    started = time.time()
    user_check_start = 0.0
    user_check_end = 0.0
    inventory_start = 0.0
    inventory_commit: Optional[float] = None
    order_commit: Optional[float] = None
    wait_ms = 0.0
    success = False
    rollback = False
    error = ""
    stock_after: Optional[int] = None
    version_after: Optional[int] = None
    queue_lock = None
    mark_global_done = False
    mark_occ_done = False

    try:
        if spec.defense == "conflict_key_queue":
            queue_lock, queue_wait = queue.acquire(spec.item_id)
            wait_ms += queue_wait

        user_check_start = time.time()
        if not check_user(pools, spec):
            rollback = True
            error = "user_not_eligible"
            return build_result(
                spec,
                started,
                user_check_start,
                time.time(),
                inventory_start,
                inventory_commit,
                order_commit,
                success,
                rollback,
                error,
                wait_ms,
                stock_after,
                version_after,
            )
        time.sleep(spec.user_check_ms / 1000.0)
        user_check_end = time.time()

        if spec.defense == "two_phase_commit":
            inventory_start = time.time()
            ok, stock_after, version_after = execute_two_phase_inventory(pools, spec)
            inventory_commit = time.time() if ok else None
            if ok:
                success = True
                order_commit = write_order(pools, spec, "committed")
            else:
                rollback = True
                error = "out_of_stock"
                write_order(pools, spec, "rolled_back")
            return build_result(
                spec,
                started,
                user_check_start,
                user_check_end,
                inventory_start,
                inventory_commit,
                order_commit,
                success,
                rollback,
                error,
                wait_ms,
                stock_after,
                version_after,
            )

        if spec.actor == "victim":
            time.sleep(spec.victim_window_ms / 1000.0)

        if spec.defense == "global_sequence":
            wait_ms += global_controller.wait_turn(spec.item_id, spec.global_seq)
            mark_global_done = True

        if spec.defense == "occ":
            mark_occ_done = True
            if not occ_controller.can_commit(spec.item_id, spec.global_seq):
                rollback = True
                error = "occ_conflict_later_arrival"
                write_order(pools, spec, "rolled_back")
                return build_result(
                    spec,
                    started,
                    user_check_start,
                    user_check_end,
                    time.time(),
                    inventory_commit,
                    order_commit,
                    success,
                    rollback,
                    error,
                    wait_ms,
                    stock_after,
                    version_after,
                )

        inventory_start = time.time()
        ok, stock_after, version_after = decrement_inventory(pools, spec)
        inventory_commit = time.time() if ok else None
        if ok:
            success = True
            order_commit = write_order(pools, spec, "committed")
        else:
            rollback = True
            error = "out_of_stock"
            write_order(pools, spec, "rolled_back")

    except Exception as exc:
        rollback = True
        error = type(exc).__name__
        try:
            write_order(pools, spec, "error")
        except Exception:
            pass
    finally:
        if mark_global_done:
            global_controller.mark_done(spec.item_id, spec.global_seq)
        if mark_occ_done:
            occ_controller.mark_done(spec.item_id, spec.global_seq)
        if queue_lock is not None:
            queue_lock.release()

    return build_result(
        spec,
        started,
        user_check_start,
        user_check_end,
        inventory_start,
        inventory_commit,
        order_commit,
        success,
        rollback,
        error,
        wait_ms,
        stock_after,
        version_after,
    )


def check_user(pools: PgPools, spec: TxnSpec) -> bool:
    conn = pools.acquire(0)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT eligible FROM exp3_users WHERE user_id=%s", (spec.user_id,))
            row = cur.fetchone()
            return bool(row and row[0])
    finally:
        pools.release(0, conn)


def decrement_inventory(pools: PgPools, spec: TxnSpec) -> tuple[bool, Optional[int], Optional[int]]:
    conn = pools.acquire(1)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE exp3_inventory
                SET stock = stock - 1,
                    version = version + 1,
                    updated_at = clock_timestamp()
                WHERE item_id=%s AND stock > 0
                RETURNING stock, version
                """,
                (spec.item_id,),
            )
            row = cur.fetchone()
            if not row:
                return False, None, None
            return True, int(row[0]), int(row[1])
    finally:
        pools.release(1, conn)


def execute_two_phase_inventory(pools: PgPools, spec: TxnSpec) -> tuple[bool, Optional[int], Optional[int]]:
    conn = pools.acquire(1, autocommit=False)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT stock, version FROM exp3_inventory WHERE item_id=%s FOR UPDATE", (spec.item_id,))
            row = cur.fetchone()
            if spec.actor == "victim":
                time.sleep(spec.victim_window_ms / 1000.0)
            if not row or int(row[0]) <= 0:
                conn.rollback()
                return False, None, None
            cur.execute(
                """
                UPDATE exp3_inventory
                SET stock = stock - 1,
                    version = version + 1,
                    updated_at = clock_timestamp()
                WHERE item_id=%s
                RETURNING stock, version
                """,
                (spec.item_id,),
            )
            updated = cur.fetchone()
        conn.commit()
        return True, int(updated[0]), int(updated[1])
    except Exception:
        conn.rollback()
        raise
    finally:
        pools.release(1, conn)


def write_order(pools: PgPools, spec: TxnSpec, status: str) -> float:
    conn = pools.acquire(2)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO exp3_orders(run_id, defense, pair_id, txn_id, actor, item_id, user_id, global_seq, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING extract(epoch from created_at)
                """,
                (
                    spec.run_id,
                    spec.defense,
                    spec.pair_id,
                    spec.txn_id,
                    spec.actor,
                    spec.item_id,
                    spec.user_id,
                    spec.global_seq,
                    status,
                ),
            )
            return float(cur.fetchone()[0])
    finally:
        pools.release(2, conn)


def build_result(
    spec: TxnSpec,
    started: float,
    user_check_start: float,
    user_check_end: float,
    inventory_start: float,
    inventory_commit: Optional[float],
    order_commit: Optional[float],
    success: bool,
    rollback: bool,
    error: str,
    wait_ms: float,
    stock_after: Optional[int],
    version_after: Optional[int],
) -> TxnResult:
    ended = time.time()
    return TxnResult(
        run_id=spec.run_id,
        seed=spec.seed,
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ended)),
        start_ts=started,
        end_ts=ended,
        scenario="cross_shard_frontrun",
        defense=spec.defense,
        pair_id=spec.pair_id,
        txn_id=spec.txn_id,
        actor=spec.actor,
        item_id=spec.item_id,
        user_id=spec.user_id,
        arrival_rank=spec.arrival_rank,
        global_seq=spec.global_seq,
        success=success,
        rollback=rollback,
        error=error,
        user_check_start_ts=user_check_start,
        user_check_end_ts=user_check_end,
        inventory_start_ts=inventory_start,
        inventory_commit_ts=inventory_commit,
        order_commit_ts=order_commit if success else None,
        latency_ms=(ended - started) * 1000.0,
        wait_ms=wait_ms,
        stock_after=stock_after,
        version_after=version_after,
    )


def build_pair_rows(results: List[TxnResult], initial_stock: int) -> List[Dict[str, object]]:
    by_pair: Dict[int, Dict[str, TxnResult]] = {}
    for result in results:
        by_pair.setdefault(result.pair_id, {})[result.actor] = result
    rows: List[Dict[str, object]] = []
    for pair_id, actors in sorted(by_pair.items()):
        victim = actors.get("victim")
        attacker = actors.get("attacker")
        if victim is None or attacker is None:
            continue
        committed = [item for item in [victim, attacker] if item.success]
        committed_count = len(committed)
        front_run = bool(
            attacker.success
            and (
                not victim.success
                or (
                    attacker.inventory_commit_ts is not None
                    and victim.inventory_commit_ts is not None
                    and attacker.inventory_commit_ts < victim.inventory_commit_ts
                )
            )
        )
        order_violation = bool(
            attacker.success
            and victim.success
            and attacker.order_commit_ts is not None
            and victim.order_commit_ts is not None
            and attacker.order_commit_ts < victim.order_commit_ts
        )
        consistency_violation = bool(front_run or order_violation)
        rows.append(
            {
                "run_id": victim.run_id,
                "seed": victim.seed,
                "scenario": victim.scenario,
                "defense": victim.defense,
                "pair_id": pair_id,
                "item_id": victim.item_id,
                "victim_txn_id": victim.txn_id,
                "attacker_txn_id": attacker.txn_id,
                "victim_success": victim.success,
                "attacker_success": attacker.success,
                "victim_latency_ms": victim.latency_ms,
                "attacker_latency_ms": attacker.latency_ms,
                "victim_inventory_commit_ts": victim.inventory_commit_ts,
                "attacker_inventory_commit_ts": attacker.inventory_commit_ts,
                "victim_order_commit_ts": victim.order_commit_ts,
                "attacker_order_commit_ts": attacker.order_commit_ts,
                "front_run_success": front_run,
                "order_violation": order_violation,
                "consistency_violation": consistency_violation,
                "rollback_count": int(victim.rollback) + int(attacker.rollback),
                "committed_count": committed_count,
                "final_stock_estimated": initial_stock - committed_count,
                "oversell": committed_count > initial_stock,
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
