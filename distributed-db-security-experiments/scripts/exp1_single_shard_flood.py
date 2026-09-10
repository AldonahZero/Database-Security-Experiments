#!/usr/bin/env python3
"""Run experiment 1: deterministic routing attack and obfuscated routing defense."""

from __future__ import annotations

import argparse
import csv
import os
import random
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from shard_router import (
    RequestSpec,
    ShardRouter,
    default_dsns,
    fetch_resource_sample,
    wait_for_shards,
)


SCENARIOS: Dict[str, float] = {
    "uniform": 0.0,
    "hot70": 0.70,
    "hot90": 0.90,
}

DEFENSES = ["deterministic", "obfuscated", "obfuscated_control"]
OPERATIONS = (("select", 0.70), ("update", 0.20), ("insert", 0.10))
TARGET_SHARD_KEYS = list(range(3000, 12000, 3))


class ResourceSampler:
    def __init__(self, dsns: List[str], run_id: int, scenario: str, defense: str, interval_s: float = 0.5) -> None:
        self.dsns = dsns
        self.run_id = run_id
        self.scenario = scenario
        self.defense = defense
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
            samples = fetch_resource_sample(self.dsns, self.scenario, self.defense)
            for sample in samples:
                sample["run_id"] = self.run_id
            self.samples.extend(samples)
            self._stop.wait(self.interval_s)


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[1]
    raw_dir = root / args.out_dir
    raw_dir.mkdir(parents=True, exist_ok=True)

    if args.clean:
        compose(args.compose_file, ["down", "-v"], root)
    if args.start_services:
        compose(args.compose_file, ["up", "-d"], root)

    dsns = default_dsns(args.host)
    wait_for_shards(dsns, timeout_s=args.wait_timeout)

    request_csv = raw_dir / "exp1_single_shard_flood_requests.csv"
    resource_csv = raw_dir / "exp1_shard_resource_samples.csv"
    all_results = []
    all_samples = []

    scenario_names = split_arg(args.scenarios, SCENARIOS.keys())
    defense_names = split_arg(args.defenses, DEFENSES)

    for run_id in range(1, args.runs + 1):
        print(f"[exp1] run_id={run_id}/{args.runs}", flush=True)
        for scenario in scenario_names:
            for defense in defense_names:
                specs = build_workload(
                    scenario=scenario,
                    defense=defense,
                    requests=args.requests,
                    db_sleep_ms=args.db_sleep_ms,
                    seed=args.seed + run_id * 100000 + len(all_results),
                )
                print(
                    f"[exp1] run_id={run_id} scenario={scenario} defense={defense} "
                    f"requests={len(specs)} concurrency={args.concurrency}",
                    flush=True,
                )
                router = ShardRouter(
                    dsns=dsns,
                    defense=defense,
                    hot_keys=TARGET_SHARD_KEYS,
                    max_connections_per_shard=args.max_connections_per_shard,
                    statement_timeout_ms=args.statement_timeout_ms,
                    pool_timeout_s=args.pool_timeout_s,
                    route_salt=args.route_salt,
                    virtual_buckets=args.virtual_buckets,
                    traffic_control_limit=args.traffic_control_limit,
                )
                sampler = ResourceSampler(dsns, run_id, scenario, defense, interval_s=args.sample_interval_s)
                sampler.start()
                started = time.time()
                try:
                    results = run_workload(router, specs, args.concurrency, defense)
                finally:
                    sampler.stop()
                    router.close()
                elapsed = time.time() - started
                successes = sum(1 for result in results if result.success)
                print(
                    f"[exp1] done run_id={run_id} scenario={scenario} defense={defense} "
                    f"elapsed={elapsed:.2f}s success={successes}/{len(results)}",
                    flush=True,
                )
                for result in results:
                    row = asdict(result)
                    row["run_id"] = run_id
                    all_results.append(row)
                all_samples.extend(sampler.samples)

    write_csv(request_csv, all_results)
    write_csv(resource_csv, all_samples)
    print(f"[exp1] wrote {request_csv}")
    print(f"[exp1] wrote {resource_csv}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requests", type=int, default=900, help="requests per scenario/defense pair")
    parser.add_argument("--runs", type=int, default=1, help="independent repetitions per scenario/defense pair")
    parser.add_argument("--concurrency", type=int, default=96, help="client worker concurrency")
    parser.add_argument("--db-sleep-ms", type=float, default=12.0, help="simulated per-query service time")
    parser.add_argument("--max-connections-per-shard", type=int, default=36)
    parser.add_argument("--traffic-control-limit", type=int, default=30)
    parser.add_argument("--statement-timeout-ms", type=int, default=1200)
    parser.add_argument("--pool-timeout-s", type=float, default=1.0)
    parser.add_argument("--sample-interval-s", type=float, default=0.5)
    parser.add_argument("--route-salt", default="chapter3-obfuscated-routing")
    parser.add_argument("--virtual-buckets", type=int, default=64)
    parser.add_argument("--seed", type=int, default=20260511)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--out-dir", default="results/raw")
    parser.add_argument("--compose-file", default="docker-compose.postgres-shards.yml")
    parser.add_argument("--wait-timeout", type=float, default=120.0)
    parser.add_argument("--scenarios", default=",".join(SCENARIOS.keys()))
    parser.add_argument("--defenses", default=",".join(DEFENSES))
    parser.add_argument("--start-services", action="store_true", help="run docker compose up -d first")
    parser.add_argument("--clean", action="store_true", help="run docker compose down -v before starting")
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


def build_workload(
    scenario: str,
    defense: str,
    requests: int,
    db_sleep_ms: float,
    seed: int,
) -> List[RequestSpec]:
    rng = random.Random(seed)
    hot_fraction = SCENARIOS[scenario]
    specs: List[RequestSpec] = []
    for request_id in range(requests):
        is_hot = hot_fraction > 0 and rng.random() < hot_fraction
        if is_hot:
            item_id = rng.choice(TARGET_SHARD_KEYS)
        elif scenario == "uniform":
            item_id = rng.randint(1, 9000)
        else:
            item_id = non_target_key(rng)
        specs.append(
            RequestSpec(
                request_id=request_id,
                scenario=scenario,
                defense=defense,
                operation=choose_operation(rng),
                item_id=item_id,
                user_id=rng.randint(1, 100000),
                is_hot=is_hot,
                hot_fraction=hot_fraction,
                db_sleep_ms=db_sleep_ms,
            )
        )
    return specs


def non_target_key(rng: random.Random) -> int:
    shard = rng.choice([1, 2])
    base = rng.randint(1, 3000) * 3
    return base + shard


def choose_operation(rng: random.Random) -> str:
    marker = rng.random()
    cumulative = 0.0
    for operation, weight in OPERATIONS:
        cumulative += weight
        if marker <= cumulative:
            return operation
    return OPERATIONS[-1][0]


def run_workload(
    router: ShardRouter,
    specs: List[RequestSpec],
    concurrency: int,
    defense: str,
):
    if defense != "queue_isolation":
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = [executor.submit(router.execute, spec) for spec in specs]
            return [future.result() for future in as_completed(futures)]

    hot_specs = [spec for spec in specs if spec.is_hot]
    normal_specs = [spec for spec in specs if not spec.is_hot]
    hot_workers = max(8, min(24, concurrency // 4))
    normal_workers = max(8, concurrency - hot_workers)
    results = []
    with ThreadPoolExecutor(max_workers=hot_workers) as hot_executor, ThreadPoolExecutor(
        max_workers=normal_workers
    ) as normal_executor:
        futures = [hot_executor.submit(router.execute, spec) for spec in hot_specs]
        futures.extend(normal_executor.submit(router.execute, spec) for spec in normal_specs)
        for future in as_completed(futures):
            results.append(future.result())
    return results


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
