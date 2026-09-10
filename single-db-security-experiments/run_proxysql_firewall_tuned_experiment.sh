#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$ROOT/docker-compose.proxysql-firewall.yml"
PROJECT="${PROXYSQL_COMPOSE_PROJECT:-proxysql-firewall-tuned}"

cd "$ROOT"

echo "Starting tuned PostgreSQL 13 + ProxySQL 3.0.11 experiment"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --build --force-recreate

export PROXYSQL_COMPOSE_PROJECT="$PROJECT"
export PROXYSQL_REPEATS="1"
python3 "$ROOT/attack-scripts/proxysql_firewall_tuned_experiment.py"

echo "Results: $ROOT/results/proxysql_firewall_tuned"
