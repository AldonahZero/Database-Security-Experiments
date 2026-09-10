# 数据库安全实验

[English README](README.md)

## 环境要求

- Docker
- Docker Compose 插件
- Python 3，用于运行宿主机侧辅助脚本

## 普通单库实验部署

### PostgreSQL RBAC：凭证失陷后的权限约束

在 `single-db-security-experiments` 目录执行（宿主机需 Python 3 和 `psycopg2`）：

```bash
docker compose up -d --no-deps postgres-db && until docker compose exec -T postgres-db pg_isready -U youruser -d juiceshop_db; do sleep 1; done && python3 attack-scripts/rbac_access_control.py
```

```bash
cd single-db-security-experiments
docker compose up -d
```

进入攻击客户端：

```bash
docker compose exec attack-client bash
```

运行默认自动化攻击流程：

```bash
docker compose exec attack-client python3 /root/attack-scripts/automate_attacks.py
```

解析检测日志：

```bash
python3 attack-scripts/detect_metrics.py
```

只启动加密相关服务：

```bash
docker compose up -d postgres-acra acra-server postgres-pgcrypto
```

宿主机侧辅助脚本在同一目录运行：

```bash
python3 attack-scripts/benchmark_encryption.py
python3 attack-scripts/test_encryption_protection.py
python3 attack-scripts/test_volume_leakage.py
python3 attack-scripts/test_acra_improvement_simple.py
```

查看脚本参数：

```bash
python3 attack-scripts/benchmark_encryption.py --help
python3 attack-scripts/detect_metrics.py --help
docker compose exec attack-client python3 /root/attack-scripts/automate_attacks.py --help
```

停止普通单库实验环境：

```bash
docker compose down
```

## 分布式实验部署

```bash
cd distributed-db-security-experiments
```

启动 PostgreSQL 分片环境：

```bash
docker compose -f docker-compose.postgres-shards.yml up -d
```

运行 PostgreSQL 分片脚本：

```bash
python3 scripts/exp1_single_shard_flood.py
python3 scripts/exp3_cross_shard_frontrun_sim.py
```

启动 Citus 环境：

```bash
docker compose -f docker-compose.citus.yml up -d
```

运行 Citus 脚本：

```bash
python3 scripts/exp1_citus_hotspot.py
```

启动 TiDB 环境：

```bash
docker compose -f docker-compose.tidb.yml up -d
```

运行 TiDB 脚本：

```bash
python3 scripts/exp1_tidb_hotspot.py
python3 scripts/exp2_tidb_leader_stress.py
```

分布式脚本也可以自行启动对应 Compose 环境：

```bash
python3 scripts/exp1_single_shard_flood.py --start-services
python3 scripts/exp1_citus_hotspot.py --start-services
python3 scripts/exp1_tidb_hotspot.py --start-services
```

重新生成派生表格和图：

```bash
python3 scripts/analyze_results.py
python3 scripts/render_fig8_distributed_risks.py
```

停止分布式环境时，对相同 Compose 文件执行 `down`：

```bash
docker compose -f docker-compose.postgres-shards.yml down
docker compose -f docker-compose.citus.yml down
docker compose -f docker-compose.tidb.yml down
```
