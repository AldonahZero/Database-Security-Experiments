#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$ROOT/docker-compose.proxysql-firewall.yml"
PROJECT="${PROXYSQL_COMPOSE_PROJECT:-proxysql-firewall-local}"

cd "$ROOT"

echo "Starting isolated PostgreSQL 13 + ProxySQL 3.0.11 project: $PROJECT"
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" down --volumes --remove-orphans
docker compose -p "$PROJECT" -f "$COMPOSE_FILE" up -d --build

export PROXYSQL_COMPOSE_PROJECT="$PROJECT"
export PROXYSQL_REPEATS="5"
python3 "$ROOT/attack-scripts/proxysql_firewall_experiment.py"

echo "Results: $ROOT/results/proxysql_firewall"
