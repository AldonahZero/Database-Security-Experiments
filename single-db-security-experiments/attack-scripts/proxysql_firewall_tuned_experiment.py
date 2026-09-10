#!/usr/bin/env python3
"""Evaluate a small, generic rule extension with one request per unique SQL.

The 317-corpus result is preserved in ``results/proxysql_firewall_317``.  This
entry point uses a separate Compose project and results directory.  It keeps
the original basic/obfuscated corpus, replaces a deterministic subset of the
legitimate CALLs with the harmless ``sensitive_proc_audit`` procedure, and
uses only structural ProxySQL rules.  The audit procedure is a real
hard-negative: its name shares a prefix with the sensitive procedure but it
updates only ``call_marker``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import proxysql_firewall_experiment as base  # noqa: E402
import proxysql_firewall_317_experiment as corpus  # noqa: E402


RESULTS_DIR = base.ROOT / "results" / "proxysql_firewall_tuned"
RULE_IDS = (10, 11, 20)
AUDIT_STRIDE = 10


TUNED_RULE_SQL = """
DELETE FROM pgsql_query_rules;
DELETE FROM pgsql_users;
DELETE FROM pgsql_servers;
INSERT INTO pgsql_servers (hostgroup_id, hostname, port, status, comment)
VALUES (10, 'postgres-db', 5432, 'ONLINE', 'PostgreSQL 13 tuned firewall backend');
INSERT INTO pgsql_users
    (username, password, active, default_hostgroup, frontend, backend, comment)
VALUES
    ('youruser', 'password123', 1, 10, 1, 1, 'ProxySQL tuned firewall test user');
UPDATE global_variables SET variable_value='youruser'
 WHERE variable_name='pgsql-monitor_username';
UPDATE global_variables SET variable_value='password123'
 WHERE variable_name='pgsql-monitor_password';
UPDATE global_variables SET variable_value='juiceshop_db'
 WHERE variable_name='pgsql-monitor_dbname';
LOAD PGSQL SERVERS TO RUNTIME;
SAVE PGSQL SERVERS TO DISK;
LOAD PGSQL USERS TO RUNTIME;
SAVE PGSQL USERS TO DISK;
LOAD PGSQL VARIABLES TO RUNTIME;
SAVE PGSQL VARIABLES TO DISK;
INSERT INTO pgsql_query_rules
    (rule_id, active, match_pattern, re_modifiers, error_msg, apply, comment)
VALUES
    (10, 1,
     'id[[:space:]]*=[[:space:]]*0[[:space:]]*(/[*][^*]*[*]/[[:space:]]*)*(OR|UNION)',
     'CASELESS', 'ProxySQL formal: tuned SQL injection pattern blocked', 1,
     'direct OR/UNION structure'),
    (11, 1,
     'id[^;]*=[^;]*0[^;]*(OR|UNION)',
     'CASELESS', 'ProxySQL formal: tuned zero-id structural variant blocked', 1,
     'zero-id OR/UNION structural variants'),
    (20, 1,
     'CALL[^;]*sensitive_proc[^;]*[(]',
     'CASELESS', 'ProxySQL formal: tuned sensitive procedure family blocked', 1,
     'sensitive procedure-name family');
LOAD PGSQL QUERY RULES TO RUNTIME;
SAVE PGSQL QUERY RULES TO DISK;
""".strip()


def build_dataset() -> list[dict[str, str]]:
    """Reuse the validated 317 corpus with legitimate CALL hard-negatives."""

    dataset = corpus.build_dataset()
    legitimate_calls = [
        row for row in dataset
        if row["scene"] == "stored_procedure_call" and row["label"] == "legitimate"
    ]
    if len(legitimate_calls) != corpus.TARGET_PER_LABEL:
        raise AssertionError("expected 317 legitimate CALL samples")
    for index, row in enumerate(legitimate_calls):
        if index % AUDIT_STRIDE == 0:
            row["sql"] = row["sql"].replace("safe_proc", "sensitive_proc_audit")

    canonical = [corpus.canonical_sql(row["sql"]) for row in dataset]
    if len(dataset) != 6 * corpus.TARGET_PER_LABEL or len(set(canonical)) != len(dataset):
        raise AssertionError("tuned dataset lost global canonical uniqueness")
    if not any("sensitive_proc_audit" in row["sql"] for row in legitimate_calls):
        raise AssertionError("CALL hard-negative procedure was not added")
    return dataset


def main() -> int:
    base.RESULTS = RESULTS_DIR
    base.REPEATS = 1
    base.PROJECT = os.environ.get("PROXYSQL_COMPOSE_PROJECT", "proxysql-firewall-tuned")
    base.RULE_SQL = TUNED_RULE_SQL
    base.RULE_IDS = RULE_IDS
    base.generate_basic = corpus.generate_basic
    base.generate_obfuscated = corpus.generate_obfuscated
    base.generate_calls = corpus.generate_calls
    base.build_dataset = build_dataset
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
