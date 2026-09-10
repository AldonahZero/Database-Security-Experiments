# Database Security Experiments

[Chinese README](README_ZH.md)

## Requirements

- Docker
- Docker Compose plugin
- Python 3 for host-side helper scripts

## Single-Database Deployment

### PostgreSQL RBAC after credential compromise

From `single-db-security-experiments`, with host Python 3 and `psycopg2` installed:

```bash
docker compose up -d --no-deps postgres-db && until docker compose exec -T postgres-db pg_isready -U youruser -d juiceshop_db; do sleep 1; done && python3 attack-scripts/rbac_access_control.py
```

```bash
cd single-db-security-experiments
docker compose up -d
```

Run the attack client:

```bash
docker compose exec attack-client bash
```

Run the default automated attack workflow:

```bash
docker compose exec attack-client python3 /root/attack-scripts/automate_attacks.py
```

Run detection-log parsing inside the started environment:

```bash
python3 attack-scripts/detect_metrics.py
```

Start only the encryption-related services:

```bash
docker compose up -d postgres-acra acra-server postgres-pgcrypto
```

Run host-side helper scripts from the same directory:

```bash
python3 attack-scripts/benchmark_encryption.py
python3 attack-scripts/test_encryption_protection.py
python3 attack-scripts/test_volume_leakage.py
python3 attack-scripts/test_acra_improvement_simple.py
```

Inspect script options:

```bash
python3 attack-scripts/benchmark_encryption.py --help
python3 attack-scripts/detect_metrics.py --help
docker compose exec attack-client python3 /root/attack-scripts/automate_attacks.py --help
```

Stop the single-database stack:

```bash
docker compose down
```

## Distributed Deployment

```bash
cd distributed-db-security-experiments
```

Start the PostgreSQL shard stack:

```bash
docker compose -f docker-compose.postgres-shards.yml up -d
```

Run PostgreSQL shard scripts:

```bash
python3 scripts/exp1_single_shard_flood.py
python3 scripts/exp3_cross_shard_frontrun_sim.py
```

Start the Citus stack:

```bash
docker compose -f docker-compose.citus.yml up -d
```

Run the Citus script:

```bash
python3 scripts/exp1_citus_hotspot.py
```

Start the TiDB stack:

```bash
docker compose -f docker-compose.tidb.yml up -d
```

Run TiDB scripts:

```bash
python3 scripts/exp1_tidb_hotspot.py
python3 scripts/exp2_tidb_leader_stress.py
```

Each distributed script can also start its own compose stack:

```bash
python3 scripts/exp1_single_shard_flood.py --start-services
python3 scripts/exp1_citus_hotspot.py --start-services
python3 scripts/exp1_tidb_hotspot.py --start-services
```

Regenerate derived tables and figures:

```bash
python3 scripts/analyze_results.py
python3 scripts/render_fig8_distributed_risks.py
```

Stop a distributed stack by using the same compose file with `down`:

```bash
docker compose -f docker-compose.postgres-shards.yml down
docker compose -f docker-compose.citus.yml down
docker compose -f docker-compose.tidb.yml down
```
