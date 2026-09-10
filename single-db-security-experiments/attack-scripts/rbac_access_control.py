#!/usr/bin/env python3
"""Isolated post-compromise RBAC test; run from the host with psycopg2."""
import argparse
import csv
import json
import os
from pathlib import Path
import secrets
import statistics
import time

import psycopg2
from psycopg2 import sql
from benchmark_encryption import CpuSampler, ENVIRONMENTS

ROOT = Path(__file__).resolve().parents[1]
OPS = [
    ('normal_select', 'legitimate', 'SELECT * FROM rbac_access_test.normal_data'),
    ('sensitive_select', 'unauthorized_read', 'SELECT * FROM rbac_access_test.sensitive_data'),
    ('sensitive_update', 'unauthorized_write', "UPDATE rbac_access_test.sensitive_data SET value='changed' WHERE id=1"),
    ('sensitive_delete', 'unauthorized_delete', 'DELETE FROM rbac_access_test.sensitive_data WHERE id=1'),
    ('privilege_escalation', 'privilege_escalation', 'CREATE ROLE rbac_access_probe NOLOGIN'),
]


def classify(exc):
    # PostgreSQL insufficient_privilege, never syntax/missing-table/connection errors.
    return 'permission_denied' if isinstance(exc, psycopg2.Error) and exc.pgcode == '42501' else 'error'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attempts', type=int, default=500)
    parser.add_argument('--output-dir', type=Path, default=ROOT / 'results')
    args = parser.parse_args()
    if args.attempts < 100:
        parser.error('at least 100 attempts per operation are required')
    args.output_dir.mkdir(parents=True, exist_ok=True)
    paths = [args.output_dir / ('rbac_access_control_' + name) for name in
             ('test.csv', 'summary.md', 'raw.csv', 'metadata.json')]
    if any(p.exists() for p in paths):
        parser.error('output already exists; choose a fresh --output-dir to preserve history')
    dsn = dict(ENVIRONMENTS[0]['dsn'])
    admin = psycopg2.connect(**dsn, connect_timeout=5)
    admin.autocommit = True
    connections = []
    created = False
    rows, raw = [], []
    meta = {'started_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'attempts_per_operation': args.attempts, 'operations': OPS,
            'latency_scope': 'execute and fetch, excluding connect/reset/rollback; errors included',
            'cpu_scope': 'docker stats for postgres-db per configuration, includes reset and rollback',
            'permission_denied_sqlstate': '42501'}
    try:
        with admin.cursor() as cur:
            cur.execute('SHOW server_version_num')
            assert 130000 <= int(cur.fetchone()[0]) < 140000, 'PostgreSQL 13 required'
            cur.execute('SELECT version()')
            meta['server_version'] = cur.fetchone()[0]
            cur.execute("SELECT rolname FROM pg_roles WHERE rolname IN ('privileged_user','limited_user','rbac_access_probe')")
            assert not cur.fetchall(), 'test role name collision; refusing to modify existing roles'
            cur.execute("SELECT 1 FROM pg_namespace WHERE nspname='rbac_access_test'")
            assert not cur.fetchall(), 'test schema already exists; refusing to overwrite'
            admin.autocommit = False
            passwords = {r: secrets.token_urlsafe(24) for r in ('privileged_user', 'limited_user')}
            for role, password in passwords.items():
                cur.execute(sql.SQL('CREATE ROLE {} LOGIN NOSUPERUSER NOCREATEDB NOINHERIT NOREPLICATION NOBYPASSRLS {} PASSWORD %s').format(
                    sql.Identifier(role), sql.SQL('CREATEROLE' if role == 'privileged_user' else 'NOCREATEROLE')), (password,))
            cur.execute('CREATE SCHEMA rbac_access_test')
            cur.execute('REVOKE ALL ON SCHEMA rbac_access_test FROM PUBLIC')
            cur.execute('CREATE TABLE rbac_access_test.normal_data(id integer PRIMARY KEY, value text)')
            cur.execute('CREATE TABLE rbac_access_test.sensitive_data(id integer PRIMARY KEY, value text)')
            cur.execute('REVOKE ALL ON ALL TABLES IN SCHEMA rbac_access_test FROM PUBLIC')
            cur.execute('GRANT USAGE ON SCHEMA rbac_access_test TO privileged_user, limited_user')
            cur.execute('GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA rbac_access_test TO privileged_user')
            cur.execute('GRANT SELECT ON rbac_access_test.normal_data TO limited_user')
            admin.commit()
            created = True
            admin.autocommit = True
            cur.execute("SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolinherit, rolreplication, rolbypassrls FROM pg_roles WHERE rolname IN ('privileged_user','limited_user') ORDER BY rolname")
            meta['role_attributes'] = cur.fetchall()
            cur.execute("SELECT grantee, table_name, privilege_type FROM information_schema.role_table_grants WHERE table_schema='rbac_access_test' AND grantee IN ('privileged_user','limited_user') ORDER BY 1,2,3")
            meta['table_grants'] = cur.fetchall()
        for config, role in [('privileged', 'privileged_user'), ('rbac_min_privilege', 'limited_user')]:
            conn = psycopg2.connect(**dict(dsn, user=role, password=passwords[role]), connect_timeout=5)
            connections.append(conn)
            with conn.cursor() as cur:
                cur.execute('SELECT current_user')
                assert cur.fetchone()[0] == role
            conn.rollback()
            sampler = CpuSampler(['postgres-db'])
            sampler.start()
            try:
                for name, kind, statement in OPS:
                    observations = []
                    for attempt in range(1, args.attempts + 1):
                        # Reset only our synthetic tables before EVERY attempt, outside timing.
                        with admin.cursor() as cur:
                            cur.execute("TRUNCATE rbac_access_test.normal_data, rbac_access_test.sensitive_data; INSERT INTO rbac_access_test.normal_data VALUES (1,'normal'); INSERT INTO rbac_access_test.sensitive_data VALUES (1,'secret')")
                        outcome, code, message = 'success', '', ''
                        started = time.perf_counter_ns()
                        try:
                            with conn.cursor() as cur:
                                cur.execute(statement)
                                if cur.description:
                                    result = cur.fetchall()
                                    assert result == [(1, 'normal' if name == 'normal_select' else 'secret')], 'unexpected query result'
                                elif name in ('sensitive_update', 'sensitive_delete'):
                                    assert cur.rowcount == 1, 'expected one affected row'
                        except Exception as exc:
                            outcome = classify(exc)
                            code = getattr(exc, 'pgcode', '') or ''
                            message = str(exc).strip()
                        elapsed = (time.perf_counter_ns() - started) / 1e6
                        conn.rollback()  # Undo successful writes AND CREATE ROLE; clear aborted transactions.
                        item = dict(config=config, operation=name, attempt=attempt, outcome=outcome,
                                    sqlstate=code, message=message, latency_ms=elapsed)
                        observations.append(item)
                        raw.append(item)
                    count = lambda outcome: sum(o['outcome'] == outcome for o in observations)
                    rows.append(dict(config=config, operation=name, operation_type=kind, attempts=args.attempts,
                                     success_count=count('success'), success_rate=100 * count('success') / args.attempts,
                                     permission_denied_count=count('permission_denied'), error_count=count('error'),
                                     avg_latency_ms=statistics.mean(o['latency_ms'] for o in observations)))
            finally:
                sampler.stop()
            meta[config + '_cpu_samples'] = sampler.samples
            for row in rows:
                if row['config'] == config:
                    row['avg_cpu_percent'] = sampler.average()
        # Negative controls prove that unrelated SQL/connection errors are not RBAC blocks.
        controls = []
        for query in ('SELEC 1', 'SELECT * FROM rbac_access_test.nonexistent_table'):
            try:
                with connections[1].cursor() as cur:
                    cur.execute(query)
            except psycopg2.Error as exc:
                controls.append({'sqlstate': exc.pgcode, 'classification': classify(exc)})
            finally:
                connections[1].rollback()
        controls.append({'classification': classify(psycopg2.OperationalError('connection failure control'))})
        assert len(controls) == 3 and all(c['classification'] == 'error' for c in controls)
        meta['negative_controls'] = controls
    finally:
        for conn in connections:
            conn.close()
        admin.rollback()
        admin.autocommit = True
        if created:
            with admin.cursor() as cur:
                cur.execute('DROP SCHEMA rbac_access_test CASCADE')
                cur.execute('DROP ROLE privileged_user, limited_user')
        admin.close()
    for path, items in ((paths[0], rows), (paths[2], raw)):
        with path.open('w', newline='', encoding='utf-8') as handle:
            writer = csv.DictWriter(handle, fieldnames=list(items[0]))
            writer.writeheader()
            writer.writerows(items)
    meta['validation_passed'] = all(r['error_count'] == 0 and
        (r['success_count'] == args.attempts if r['config'] == 'privileged' or r['operation'] == 'normal_select'
         else r['permission_denied_count'] == args.attempts) for r in rows)
    paths[3].write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding='utf-8')
    lines = ['# PostgreSQL RBAC 凭证失陷后访问约束实验', '',
             '每角色每操作重复 %d 次；成功率单位为 %%；仅 SQLSTATE 42501 计为权限拒绝。' % args.attempts,
             'privileged_user: 两表 SELECT/INSERT/UPDATE/DELETE + CREATEROLE；limited_user: 仅 normal_data SELECT；两者均有测试 schema USAGE，均非超级用户。',
             '角色仍继承数据库默认 PUBLIC 权限；最小权限结论限定于此独立测试 schema。',
             '每次请求前重置测试表，执行后回滚；独立 TCP 账号连接。结束时删除本次创建的测试 schema 和角色。',
             'CPU 为每组完整测试阶段 docker stats 均值（含重置/回滚），不是单条 SQL 的 CPU 开销。',
             '延迟包含失败响应，排除连接、重置及回滚；拒绝响应较快不能解释为正常业务性能提升。',
             '本实验不评估或声称 RBAC 阻止 Hydra 密码破解。', '',
             '|配置|正常查询成功率 %|越权读取 %|越权修改 %|越权删除 %|创建角色成功率 %|平均响应 ms|CPU %|其他错误|',
             '|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    means = []
    for config in ('privileged', 'rbac_min_privilege'):
        group = [r for r in rows if r['config'] == config]
        mean = statistics.mean(r['avg_latency_ms'] for r in group)
        means.append(mean)
        cpu = group[0]['avg_cpu_percent']
        lines.append('|%s|%s|%.6f|%s|%d|' % (config, '|'.join('%.2f' % r['success_rate'] for r in group), mean,
                     'N/A' if cpu is None else '%.4f' % cpu, sum(r['error_count'] for r in group)))
    lines += ['', '平均响应延迟变化：%.6f ms (%.2f%%)。' % (means[1]-means[0], 100*(means[1]/means[0]-1)),
              '权限验证通过：%s。逐次 SQLSTATE、消息和延迟见 raw.csv；权限快照、CPU 原始样本及负向对照见 metadata.json。' % meta['validation_passed']]
    paths[1].write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print('\n'.join(lines))
    if not meta['validation_passed']:
        raise SystemExit('RBAC validation failed; inspect raw results, do not claim successful protection')


if __name__ == '__main__':
    main()
