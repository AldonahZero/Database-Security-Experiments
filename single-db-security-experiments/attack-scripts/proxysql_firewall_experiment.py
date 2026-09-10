#!/usr/bin/env python3
"""Reproducible PostgreSQL 13 + ProxySQL 3.0.11 firewall experiment.

The runner deliberately keeps the baseline and protected paths separate:
baseline-api -> PostgreSQL and firewall-api -> ProxySQL -> PostgreSQL.  It
configures one fixed pgsql_query_rules policy, runs a smoke test, freezes the
policy/dataset hashes, and only then runs the 600-unique-sample evaluation.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import requests


ROOT = Path(__file__).resolve().parents[1]
COMPOSE_FILE = ROOT / "docker-compose.proxysql-firewall.yml"
PROJECT = os.environ.get("PROXYSQL_COMPOSE_PROJECT", "proxysql-firewall-local")
RESULTS = ROOT / "results" / "proxysql_firewall"
BASELINE_URL = os.environ.get("PROXYSQL_BASELINE_URL", "http://127.0.0.1:18080")
FIREWALL_URL = os.environ.get("PROXYSQL_FIREWALL_URL", "http://127.0.0.1:18081")
REPEATS = int(os.environ.get("PROXYSQL_REPEATS", "5"))
REQUEST_TIMEOUT = float(os.environ.get("PROXYSQL_REQUEST_TIMEOUT", "20"))

POSTGRES_IMAGE = "postgres:13"
PROXYSQL_IMAGE = "proxysql/proxysql:3.0.11"
EXPECTED_PROXY_DIGEST = (
    "sha256:0e95d1b7cc32f1de7923ffbf6cc4ba658874a6f6a6b7c2cdfdc6444304c13caf"
)


RULE_SQL = """
DELETE FROM pgsql_query_rules;
DELETE FROM pgsql_users;
DELETE FROM pgsql_servers;
INSERT INTO pgsql_servers (hostgroup_id, hostname, port, status, comment)
VALUES (10, 'postgres-db', 5432, 'ONLINE', 'PostgreSQL 13 firewall backend');
INSERT INTO pgsql_users
    (username, password, active, default_hostgroup, frontend, backend, comment)
VALUES
    ('youruser', 'password123', 1, 10, 1, 1, 'ProxySQL firewall test user');
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
     'CASELESS', 'ProxySQL formal: SQL injection pattern blocked', 1,
     'structural OR/UNION'),
    (20, 1,
     'CALL[[:space:]]+public[.][[:space:]]*sensitive_proc[[:space:]]*[(]',
     'CASELESS', 'ProxySQL formal: sensitive procedure blocked', 1,
     'sensitive procedure CALL');
LOAD PGSQL QUERY RULES TO RUNTIME;
SAVE PGSQL QUERY RULES TO DISK;
""".strip()

RULE_IDS = (10, 20)


def run_cmd(args: list[str], check: bool = True, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(args)}\n{result.stdout}")
    return result


def compose(*args: str, check: bool = True, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return run_cmd(
        ["docker", "compose", "-p", PROJECT, "-f", str(COMPOSE_FILE), *args],
        check=check,
        timeout=timeout,
    )


def service_container(service: str) -> str:
    value = compose("ps", "-q", service).stdout.strip().splitlines()
    if not value:
        raise RuntimeError(f"no running container for compose service {service}")
    return value[0].strip()


def mysql_admin(script: str, check: bool = True) -> str:
    cid = service_container("proxysql")
    result = run_cmd(
        [
            "docker",
            "exec",
            cid,
            "mysql",
            "-N",
            "-B",
            "-h127.0.0.1",
            "-P6032",
            "-uadmin",
            "-padmin",
            "-e",
            script,
        ],
        check=check,
        timeout=60,
    )
    return result.stdout


def wait_for_http(url: str, seconds: int = 90) -> None:
    deadline = time.monotonic() + seconds
    last = ""
    while time.monotonic() < deadline:
        try:
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                return
            last = f"HTTP {response.status_code}: {response.text[:200]}"
        except Exception as exc:  # startup is expected to fail briefly
            last = str(exc)
        time.sleep(1)
    raise RuntimeError(f"service did not become ready: {url}; last={last}")


def request_json(base_url: str, endpoint: str, **params: str) -> tuple[dict[str, Any], int, float, str]:
    started = time.perf_counter()
    try:
        response = requests.get(
            base_url + endpoint,
            params=params,
            timeout=REQUEST_TIMEOUT,
        )
        elapsed = (time.perf_counter() - started) * 1000
        try:
            body = response.json()
        except ValueError:
            body = {"ok": False, "error": response.text[:2000]}
        return body, response.status_code, elapsed, response.url
    except requests.exceptions.ConnectionError as exc:
        return {"ok": False, "error_type": "connection_error", "error": str(exc)}, 0, (time.perf_counter() - started) * 1000, ""
    except requests.exceptions.Timeout as exc:
        return {"ok": False, "error_type": "connection_error", "error": str(exc)}, 0, (time.perf_counter() - started) * 1000, ""


def classify_error(body: dict[str, Any], status: int) -> str:
    explicit = str(body.get("error_type", ""))
    if explicit:
        return explicit
    text = str(body.get("error", "")).lower()
    if "proxysql formal:" in text:
        return "firewall_deny"
    if status == 0:
        return "connection_error"
    if "syntax error" in text:
        return "sql_syntax_error"
    if "protocol" in text:
        return "protocol_error"
    if status >= 500:
        return "backend_error"
    return "none" if status < 400 else "application_error"


def _sample(sample_id: str, scene: str, label: str, sql: str, endpoint: str = "/pg/query") -> dict[str, Any]:
    return {
        "sample_id": sample_id,
        "scene": scene,
        "label": label,
        "endpoint": endpoint,
        "sql": sql,
    }


def _query(select_sql: str, fragment: str) -> str:
    return f"{select_sql} WHERE id = {fragment};"


def generate_basic() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    malicious: list[dict[str, Any]] = []
    legitimate: list[dict[str, Any]] = []
    select_sql = "SELECT id, username, secret FROM vuln_users"
    for i in range(1, 101):
        if i <= 20:
            fragment = f"0 OR {i}={i}"
        elif i <= 35:
            fragment = f"0 OR ({i}={i})"
        elif i <= 50:
            fragment = f"0 UNION ALL SELECT {i}, 'inj{i}', 'leak{i}'"
        elif i <= 62:
            fragment = f"0 UNION SELECT {i}, 'inj{i}', 'leak{i}'"
        elif i <= 72:
            fragment = f"(0) OR {i}={i}"
        elif i <= 82:
            fragment = f"0 + 0 OR {i}={i}"
        elif i <= 92:
            fragment = f"0::integer OR {i}={i}"
        elif i <= 97:
            fragment = f"0 OR EXISTS (SELECT 1 FROM vuln_users WHERE id = {(i % 3) + 1} /* exists-{i} */)"
        else:
            fragment = f"0 UNION ALL SELECT {i}, (SELECT username FROM vuln_users WHERE id=1), 'nested{i}'"
        malicious.append(_sample(f"basic_malicious_{i:03d}", "basic_sql_injection", "malicious", _query(select_sql, fragment)))

    templates = [
        lambda i: _query(select_sql, str((i % 3) + 1)),
        lambda i: _query(select_sql, f"({(i % 3) + 1})"),
        lambda i: _query(select_sql, f"{(i % 3) + 1} + 0"),
        lambda i: _query(select_sql, f"CAST({(i % 3) + 1} AS integer)"),
        lambda i: _query(select_sql, f"CASE WHEN {i}={i} THEN 1 ELSE 2 END"),
        lambda i: _query(select_sql, f"COALESCE(NULL, {(i % 3) + 1})"),
        lambda i: _query(select_sql, f"GREATEST({(i % 3) + 1}, 1)"),
        lambda i: _query(select_sql, f"(SELECT MIN(id) FROM vuln_users) + {(i % 2)}"),
        lambda i: f"{select_sql} WHERE id IN ({(i % 3) + 1});",
        lambda i: f"{select_sql} WHERE id BETWEEN {(i % 3) + 1} AND {(i % 3) + 2};",
    ]
    for i in range(1, 71):
        sql = templates[(i - 1) % len(templates)](i)
        # Keep the SQL semantically identical while making every request text
        # unique; this prevents a repeated template from being counted as a
        # different unique sample.
        sql = sql[:-1] + f" /* legitimate-basic-{i} */;"
        legitimate.append(_sample(f"basic_legitimate_{i:03d}", "basic_sql_injection", "legitimate", sql))
    # Hard negatives: valid, false conditions whose surface begins with the rule's id=0 OR form.
    for i in range(71, 81):
        spacing = " " * (i - 70)
        sql = _query(select_sql, f"0{spacing}OR{spacing}1=0 /* legitimate-{i} */")
        legitimate.append(_sample(f"basic_legitimate_{i:03d}", "basic_sql_injection", "legitimate", sql))
    for i in range(81, 91):
        sql = (
            "SELECT v.id, v.username, v.secret FROM vuln_users AS v "
            f"JOIN (SELECT {(i % 3) + 1} AS id) AS q ON q.id=v.id "
            f"/* join-{i} */;"
        )
        legitimate.append(_sample(f"basic_legitimate_{i:03d}", "basic_sql_injection", "legitimate", sql))
    for i in range(91, 101):
        sql = (
            f"SELECT 1 AS id, 'union_value_{i}' AS username, 'normal' AS secret "
            f"UNION ALL SELECT 2, 'second_{i}', 'normal';"
        )
        legitimate.append(_sample(f"basic_legitimate_{i:03d}", "basic_sql_injection", "legitimate", sql))
    return malicious, legitimate


def generate_obfuscated() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    malicious: list[dict[str, Any]] = []
    legitimate: list[dict[str, Any]] = []
    select_sql = "SELECT id, username, secret FROM vuln_users"
    fragments: list[str] = []
    for i in range(1, 21):
        fragments.append(f"0/**/OR/**/{i}={i}")
    for i in range(21, 36):
        fragments.append(f"0 /* c{i} */ OR /* d{i} */ ({i}={i})")
    for i in range(36, 51):
        fragments.append(f"0\tOR\t({i}={i})")
    for i in range(51, 61):
        fragments.append(f"0\nOR\n{i}={i}")
    for i in range(61, 71):
        fragments.append(f"0 UNION/**/ALL/**/SELECT {i}, 'obf{i}', 'leak{i}'")
    for i in range(71, 81):
        fragments.append(f"0 union all select {i}, 'obf{i}', 'leak{i}'")
    for i in range(81, 91):
        fragments.append(f"(0) /*p{i}*/ OR ({i}={i})")
    for i in range(91, 101):
        fragments.append(f"0 + 0/**/oR/**/({i}={i})")
    for i, fragment in enumerate(fragments, 1):
        malicious.append(_sample(f"obfuscated_malicious_{i:03d}", "obfuscated_sql_injection", "malicious", _query(select_sql, fragment)))

    # Fully valid hard negatives with comments/case/boolean structure.  The first
    # ten intentionally contain a false OR branch, so a rule that blindly rejects
    # every OR has measurable false positives.
    for i in range(1, 31):
        sql = (
            f"SeLeCt id, username, secret FROM vuln_users "
            f"WHERE (id = {(i % 3) + 1} AND {i}={i}) /* benign-obf-{i} */;"
        )
        legitimate.append(_sample(f"obfuscated_legitimate_{i:03d}", "obfuscated_sql_injection", "legitimate", sql))
    for i in range(31, 51):
        sql = (
            "SELECT id, username, secret FROM vuln_users\n"
            f"WHERE id = {(i % 3) + 1}\tAND username <> 'nobody' -- benign-{i}\n;"
        )
        legitimate.append(_sample(f"obfuscated_legitimate_{i:03d}", "obfuscated_sql_injection", "legitimate", sql))
    for i in range(51, 61):
        sql = (
            f"SELECT id, username, secret FROM vuln_users WHERE id IN ({(i % 3) + 1}) "
            f"AND ('UNION value {i}' LIKE '%UNION%' OR 'x'='y');"
        )
        legitimate.append(_sample(f"obfuscated_legitimate_{i:03d}", "obfuscated_sql_injection", "legitimate", sql))
    for i in range(61, 71):
        sql = (
            "SELECT v.id, v.username, v.secret FROM vuln_users v "
            f"WHERE EXISTS (SELECT 1 FROM vuln_users q WHERE q.id=v.id AND q.id={(i % 3) + 1}) "
            f"AND CASE WHEN {i}={i} THEN TRUE ELSE FALSE END;"
        )
        legitimate.append(_sample(f"obfuscated_legitimate_{i:03d}", "obfuscated_sql_injection", "legitimate", sql))
    for i in range(71, 81):
        sql = (
            f"SELECT 1 AS id, 'OR literal {i}' AS username, 'SELECT literal' AS secret "
            f"UNION SELECT 2, 'normal {i}', 'UNION is a value';"
        )
        legitimate.append(_sample(f"obfuscated_legitimate_{i:03d}", "obfuscated_sql_injection", "legitimate", sql))
    for i in range(81, 91):
        sql = (
            f"SELECT id, username, secret FROM vuln_users WHERE ((id={(i % 3) + 1}) "
            f"AND (id IS NOT NULL)) AND (id BETWEEN 1 AND 3) /* nested-{i} */;"
        )
        legitimate.append(_sample(f"obfuscated_legitimate_{i:03d}", "obfuscated_sql_injection", "legitimate", sql))
    for i in range(91, 101):
        sql = (
            f"SELECT id, username, secret FROM vuln_users WHERE id=0 OR {i}={i-1} "
            f"/* false benign branch {i} */;"
        )
        legitimate.append(_sample(f"obfuscated_legitimate_{i:03d}", "obfuscated_sql_injection", "legitimate", sql))
    return malicious, legitimate


def generate_calls() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    malicious: list[dict[str, Any]] = []
    legitimate: list[dict[str, Any]] = []
    for i in range(1, 101):
        variants = [
            f"CALL public.sensitive_proc({i});",
            f"CALL PUBLIC.sensitive_proc({i});",
            f"CALL public.sensitive_proc( {i} );",
            f"CALL\npublic.sensitive_proc({i});",
            f"CALL /* call-{i} */ public.sensitive_proc({i});",
            f"CALL public./* name-{i} */sensitive_proc({i});",
            f"CALL public.\"sensitive_proc\"({i});",
            f"call public.sensitive_proc(({i}));",
            f"CALL public.sensitive_proc({i} /* argument-{i} */);",
            f"CALL public.sensitive_proc(CAST({i} AS integer));",
        ]
        # Offset the first formal sample so the exact smoke payload
        # ``CALL public.sensitive_proc(1);`` is not reused in the evaluation
        # corpus.
        sql = variants[i % len(variants)]
        malicious.append(_sample(f"call_malicious_{i:03d}", "stored_procedure_call", "malicious", sql, "/pg/call"))
    for i in range(1, 101):
        variants = [
            f"CALL public.safe_proc({i});",
            f"CALL PUBLIC.safe_proc({i});",
            f"CALL public.safe_proc( {i} );",
            f"CALL\npublic.safe_proc({i});",
            f"CALL /* legitimate-{i} */ public.safe_proc({i});",
            f"CALL public./* safe-name-{i} */safe_proc({i});",
            f"CALL public.\"safe_proc\"({i});",
            f"call public.safe_proc(({i}));",
            f"CALL public.safe_proc({i} /* safe-argument-{i} */);",
            f"CALL public.safe_proc(CAST({i} AS integer));",
        ]
        # Offset the first formal sample so the exact smoke payload
        # ``CALL public.safe_proc(1);`` is not reused in the evaluation corpus.
        sql = variants[i % len(variants)]
        legitimate.append(_sample(f"call_legitimate_{i:03d}", "stored_procedure_call", "legitimate", sql, "/pg/call"))
    return malicious, legitimate


def build_dataset() -> list[dict[str, Any]]:
    samples: list[dict[str, Any]] = []
    for generator in (generate_basic, generate_obfuscated, generate_calls):
        malicious, legitimate = generator()
        if len(malicious) != 100 or len(legitimate) != 100:
            raise AssertionError("each scene must have exactly 100 malicious and 100 legitimate samples")
        samples.extend(malicious)
        samples.extend(legitimate)
    if len(samples) != 600 or len({sample["sql"] for sample in samples}) != 600:
        raise AssertionError("dataset does not contain 600 unique SQL texts")
    return samples


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def snapshot_rules() -> tuple[str, list[dict[str, Any]]]:
    rule_id_list = ",".join(str(rule_id) for rule_id in RULE_IDS)
    query = (
        "SELECT rule_id,active,match_pattern,re_modifiers,error_msg,apply,comment "
        f"FROM pgsql_query_rules WHERE rule_id IN ({rule_id_list}) ORDER BY rule_id"
    )
    raw = mysql_admin(query)
    rows: list[dict[str, Any]] = []
    for line in raw.splitlines():
        fields = line.split("\t")
        if len(fields) < 7:
            continue
        rows.append(
            {
                "rule_id": fields[0],
                "active": fields[1],
                "match_pattern": fields[2],
                "re_modifiers": fields[3],
                "error_msg": fields[4],
                "apply": fields[5],
                "comment": fields[6],
            }
        )
    canonical = "".join(
        "\t".join(
            row[key]
            for key in ("rule_id", "active", "match_pattern", "re_modifiers", "error_msg", "apply", "comment")
        )
        + "\n"
        for row in rows
    )
    return sha256_bytes(canonical.encode("utf-8")), rows


def read_stats() -> list[dict[str, Any]]:
    rule_id_list = ",".join(str(rule_id) for rule_id in RULE_IDS)
    query = (
        "SELECT rule_id,hits FROM stats_pgsql_query_rules "
        f"WHERE rule_id IN ({rule_id_list}) ORDER BY rule_id"
    )
    raw = mysql_admin(query, check=False)
    rows = []
    for line in raw.splitlines():
        fields = line.split("\t")
        if len(fields) >= 2 and fields[0].isdigit():
            rows.append({"rule_id": int(fields[0]), "hits": int(fields[1])})
    return rows


def smoke_test() -> dict[str, Any]:
    ordinary, ordinary_status, _, _ = request_json(
        FIREWALL_URL,
        "/pg/query",
        sql="SELECT id, username, secret FROM vuln_users WHERE id=1;",
    )
    baseline_safe, baseline_safe_status, _, _ = request_json(
        BASELINE_URL, "/pg/reset"
    )
    protected_safe_reset, protected_safe_reset_status, _, _ = request_json(
        FIREWALL_URL, "/pg/reset"
    )
    safe_body, safe_status, _, _ = request_json(
        FIREWALL_URL, "/pg/call", sql="CALL public.safe_proc(1);"
    )
    baseline_sensitive_reset, _, _, _ = request_json(BASELINE_URL, "/pg/reset")
    baseline_sensitive, baseline_sensitive_status, _, _ = request_json(
        BASELINE_URL, "/pg/call", sql="CALL public.sensitive_proc(1);"
    )
    protected_sensitive_reset, _, _, _ = request_json(FIREWALL_URL, "/pg/reset")
    protected_sensitive, protected_sensitive_status, _, _ = request_json(
        FIREWALL_URL, "/pg/call", sql="CALL public.sensitive_proc(1);"
    )
    protected_state, protected_state_status, _, _ = request_json(FIREWALL_URL, "/pg/state")
    stats_before_after = read_stats()
    safe_marker = int(safe_body.get("state", {}).get("call_marker", 0)) if safe_body.get("ok") else 0
    baseline_sensitive_marker = int(baseline_sensitive.get("state", {}).get("sensitive_marker", 0)) if baseline_sensitive.get("ok") else 0
    protected_sensitive_marker = int(protected_sensitive.get("state", {}).get("sensitive_marker", 0)) if isinstance(protected_sensitive.get("state"), dict) else -1
    firewall_blocked = classify_error(protected_sensitive, protected_sensitive_status) == "firewall_deny"
    result = {
        "ordinary_sql_status": ordinary_status,
        "ordinary_sql_ok": bool(ordinary.get("ok")),
        "baseline_safe_reset_status": baseline_safe_status,
        "protected_safe_reset_status": protected_safe_reset_status,
        "safe_call_status": safe_status,
        "safe_call_ok": bool(safe_body.get("ok")),
        "safe_call_marker": safe_marker,
        "baseline_sensitive_status": baseline_sensitive_status,
        "baseline_sensitive_ok": bool(baseline_sensitive.get("ok")),
        "baseline_sensitive_marker": baseline_sensitive_marker,
        "protected_sensitive_status": protected_sensitive_status,
        "protected_sensitive_error_type": classify_error(protected_sensitive, protected_sensitive_status),
        "protected_sensitive_firewall_blocked": firewall_blocked,
        "protected_sensitive_marker": protected_sensitive_marker,
        "protected_state_status": protected_state_status,
        "protected_state": protected_state,
        "rule_stats_after_smoke": stats_before_after,
        "reset_responses_ok": all(
            body.get("ok")
            for body in (baseline_safe, protected_safe_reset, baseline_sensitive_reset, protected_sensitive_reset)
        ),
    }
    if not (
        result["ordinary_sql_ok"]
        and result["safe_call_ok"]
        and safe_marker >= 1
        and result["baseline_sensitive_ok"]
        and baseline_sensitive_marker >= 1
        and firewall_blocked
        and protected_sensitive_marker == 0
    ):
        raise RuntimeError("ProxySQL smoke test failed; refusing to run formal dataset: " + json.dumps(result, ensure_ascii=False))
    return result


def error_for_row(body: dict[str, Any], status: int) -> str:
    return classify_error(body, status)


def run_stage(samples: list[dict[str, Any]], base_url: str, stage: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    session = requests.Session()
    for index, sample in enumerate(samples, 1):
        if sample["endpoint"] == "/pg/call":
            reset_body, reset_status, reset_latency, reset_url = request_json(base_url, "/pg/reset")
            if reset_status != 200 or not reset_body.get("ok"):
                raise RuntimeError(f"marker reset failed for {sample['sample_id']}: {reset_body}")
        for repeat in range(1, REPEATS + 1):
            body, status, latency, url = request_json(base_url, sample["endpoint"], sql=sample["sql"])
            err = error_for_row(body, status)
            state = body.get("state") if isinstance(body.get("state"), dict) else {}
            row = {
                "stage": stage,
                "sample_id": sample["sample_id"],
                "scene": sample["scene"],
                "label": sample["label"],
                "endpoint": sample["endpoint"],
                "repeat_index": repeat,
                "http_status": status,
                "ok": bool(body.get("ok")) and status == 200,
                "error_type": err,
                "error": str(body.get("error", ""))[:1000],
                "latency_ms": round(latency, 6),
                "firewall_blocked": err == "firewall_deny",
                "backend_executed": False,
                "attack_success": False,
                "row_count": body.get("row_count", ""),
                "call_marker": state.get("call_marker", ""),
                "sensitive_marker": state.get("sensitive_marker", ""),
                "url": url,
            }
            if sample["label"] == "malicious":
                if sample["scene"] in ("basic_sql_injection", "obfuscated_sql_injection"):
                    try:
                        row_count = int(body.get("row_count", 0))
                    except (TypeError, ValueError):
                        row_count = 0
                    # OR payloads return several fixture rows; UNION payloads
                    # intentionally return one injected row because id=0 has no
                    # baseline match.  Detect the latter from the fixture values
                    # (ids > 3 or the explicit inj/obf marker), not from HTTP.
                    result_rows = body.get("rows") if isinstance(body.get("rows"), list) else []
                    injected_row = any(
                        isinstance(item, dict)
                        and (
                            int(item.get("id", 0) or 0) > 3
                            or str(item.get("username", "")).startswith(("inj", "obf"))
                            or str(item.get("secret", "")).startswith("leak")
                        )
                        for item in result_rows
                    )
                    row["backend_executed"] = bool(row["ok"] and (row_count > 1 or injected_row))
                    row["attack_success"] = row["backend_executed"]
                else:
                    try:
                        sensitive_marker = int(state.get("sensitive_marker", 0))
                    except (TypeError, ValueError):
                        sensitive_marker = 0
                    row["backend_executed"] = sensitive_marker > 0
                    row["attack_success"] = row["backend_executed"]
            else:
                row["backend_executed"] = bool(row["ok"])
            rows.append(row)
        if index % 25 == 0 or index == len(samples):
            print(f"{stage}: {index}/{len(samples)} unique samples", flush=True)
    return rows


def aggregate_metrics(samples: list[dict[str, Any]], baseline_rows: list[dict[str, Any]], firewall_rows: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    by_sample = {sample["sample_id"]: sample for sample in samples}
    base_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    fw_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in baseline_rows:
        base_by_id[row["sample_id"]].append(row)
    for row in firewall_rows:
        fw_by_id[row["sample_id"]].append(row)
    unique_rows: list[dict[str, Any]] = []
    request_rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    summary: dict[str, Any] = {}
    for scene in ("basic_sql_injection", "obfuscated_sql_injection", "stored_procedure_call"):
        scene_samples = [sample for sample in samples if sample["scene"] == scene]
        counts = Counter()
        req_counts = Counter()
        parser_counts = Counter()
        unstable = 0
        invalid_malicious = []
        invalid_legitimate = []
        for sample in scene_samples:
            sid = sample["sample_id"]
            b_rows = base_by_id[sid]
            f_rows = fw_by_id[sid]
            baseline_valid = all(bool(row["ok"]) for row in b_rows)
            baseline_attack_success = sample["label"] == "legitimate" or all(bool(row["attack_success"]) for row in b_rows)
            eligible = baseline_valid and baseline_attack_success
            if not eligible:
                target = invalid_malicious if sample["label"] == "malicious" else invalid_legitimate
                target.append({"sample_id": sid, "reason": "baseline_invalid_or_expected_effect_missing"})
            classifications: list[str] = []
            for row in f_rows:
                if row["error_type"] in ("parser_error", "protocol_error", "connection_error", "sql_syntax_error", "application_error", "backend_error"):
                    classification = "error"
                    parser_counts[row["error_type"]] += 1
                    errors.append({**row, "classification": classification})
                elif sample["label"] == "malicious":
                    classification = "TP" if row["firewall_blocked"] and not row["attack_success"] else ("FN" if row["attack_success"] else "error")
                    if classification == "error":
                        errors.append({**row, "classification": classification})
                else:
                    classification = "FP" if row["firewall_blocked"] else ("TN" if row["ok"] else "error")
                    if classification == "error":
                        errors.append({**row, "classification": classification})
                classifications.append(classification)
                if eligible and classification in ("TP", "FN", "FP", "TN"):
                    req_counts[classification] += 1
                    request_rows.append({**row, "classification": classification, "eligible": True})
            if len(set(classifications)) > 1:
                unstable += 1
            if eligible:
                # A unique is classified only when every repeat has a conclusive
                # outcome.  Any parser/transport/backend error remains separate.
                if sample["label"] == "malicious":
                    if all(c == "TP" for c in classifications):
                        unique_class = "TP"
                    elif any(c == "FN" for c in classifications):
                        unique_class = "FN"
                    else:
                        unique_class = "error"
                else:
                    if any(c == "FP" for c in classifications):
                        unique_class = "FP"
                    elif all(c == "TN" for c in classifications):
                        unique_class = "TN"
                    else:
                        unique_class = "error"
                if unique_class in ("TP", "FN", "FP", "TN"):
                    counts[unique_class] += 1
                else:
                    errors.append({"sample_id": sid, "scene": scene, "classification": "error", "error_type": "mixed_or_inconclusive"})
                unique_rows.append(
                    {
                        "sample_id": sid,
                        "scene": scene,
                        "label": sample["label"],
                        "baseline_valid": baseline_valid,
                        "baseline_attack_success": baseline_attack_success,
                        "eligible": eligible,
                        "classification": unique_class,
                        "repeat_classifications": ",".join(classifications),
                        "stable": len(set(classifications)) == 1,
                    }
                )
        tpr_den = counts["TP"] + counts["FN"]
        fpr_den = counts["FP"] + counts["TN"]
        req_tpr_den = req_counts["TP"] + req_counts["FN"]
        req_fpr_den = req_counts["FP"] + req_counts["TN"]
        summary[scene] = {
            "scene": scene,
            "malicious_unique": sum(s["label"] == "malicious" for s in scene_samples),
            "legitimate_unique": sum(s["label"] == "legitimate" for s in scene_samples),
            "eligible_malicious_unique": sum(s["label"] == "malicious" and r.get("eligible") for s, r in ((by_sample[u["sample_id"]], u) for u in unique_rows if u["scene"] == scene)),
            "eligible_legitimate_unique": sum(s["label"] == "legitimate" and r.get("eligible") for s, r in ((by_sample[u["sample_id"]], u) for u in unique_rows if u["scene"] == scene)),
            "repeats": REPEATS,
            "TP": counts["TP"],
            "FN": counts["FN"],
            "FP": counts["FP"],
            "TN": counts["TN"],
            "TPR": (counts["TP"] / tpr_den) if tpr_den else None,
            "FPR": (counts["FP"] / fpr_den) if fpr_den else None,
            "request_TP": req_counts["TP"],
            "request_FN": req_counts["FN"],
            "request_FP": req_counts["FP"],
            "request_TN": req_counts["TN"],
            "request_TPR": (req_counts["TP"] / req_tpr_den) if req_tpr_den else None,
            "request_FPR": (req_counts["FP"] / req_fpr_den) if req_fpr_den else None,
            "parser_errors": parser_counts["parser_error"],
            "protocol_errors": parser_counts["protocol_error"],
            "connection_errors": parser_counts["connection_error"],
            "sql_syntax_errors": parser_counts["sql_syntax_error"],
            "other_errors": sum(parser_counts[k] for k in parser_counts if k not in {"parser_error", "protocol_error", "connection_error", "sql_syntax_error"}),
            "unstable_unique_requests": unstable,
            "baseline_invalid_malicious": invalid_malicious,
            "baseline_invalid_legitimate": invalid_legitimate,
        }
    return unique_rows, request_rows, errors, summary


def save_environment(rule_hash: str, dataset_hash: str) -> None:
    pg_inspect = run_cmd(["docker", "image", "inspect", POSTGRES_IMAGE, "--format", "{{.Id}} {{json .RepoDigests}}"], check=False).stdout.strip()
    px_inspect = run_cmd(["docker", "image", "inspect", PROXYSQL_IMAGE, "--format", "{{.Id}} {{json .RepoDigests}}"], check=False).stdout.strip()
    environment = [
        f"timestamp_utc={datetime.now(timezone.utc).isoformat()}",
        f"postgres_image={POSTGRES_IMAGE}",
        f"postgres_image_inspect={pg_inspect}",
        f"proxysql_image={PROXYSQL_IMAGE}",
        f"proxysql_image_inspect={px_inspect}",
        f"expected_proxysql_digest={EXPECTED_PROXY_DIGEST}",
        "postgresql_backend_port_container=5432",
        "postgresql_backend_port_host=15432",
        "proxysql_postgresql_listener_container=6133",
        "proxysql_postgresql_listener_host=15433",
        "proxysql_admin_mysql_listener_container=6032",
        "proxysql_admin_mysql_listener_host=16132",
        "baseline_api=http://127.0.0.1:18080",
        "firewall_api=http://127.0.0.1:18081",
        f"rule_runtime_sha256={rule_hash}",
        f"dataset_sha256={dataset_hash}",
    ]
    (RESULTS / "environment.txt").write_text("\n".join(environment) + "\n", encoding="utf-8")


def main() -> int:
    if REPEATS < 1:
        raise SystemExit("formal experiment requires PROXYSQL_REPEATS>=1")
    if (RESULTS / "summary.json").exists() and os.environ.get("PROXYSQL_ALLOW_OVERWRITE") != "1":
        raise SystemExit(f"{RESULTS} already contains results; refusing to overwrite. Set PROXYSQL_ALLOW_OVERWRITE=1 only for an explicitly new local run.")
    RESULTS.mkdir(parents=True, exist_ok=True)
    (RESULTS / "logs").mkdir(exist_ok=True)

    print("Waiting for ProxySQL admin and configuring the fixed policy", flush=True)
    for _ in range(60):
        try:
            mysql_admin("SELECT 1;")
            break
        except Exception:
            time.sleep(1)
    else:
        raise RuntimeError("ProxySQL admin interface did not become ready")
    mysql_admin(RULE_SQL)
    wait_for_http(BASELINE_URL + "/health")
    wait_for_http(FIREWALL_URL + "/health")

    smoke = smoke_test()
    (RESULTS / "smoke_test.json").write_text(json.dumps(smoke, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print("Smoke test passed", flush=True)

    rule_hash, rule_rows = snapshot_rules()
    if len(rule_rows) != len(RULE_IDS):
        raise RuntimeError(f"expected {len(RULE_IDS)} active rules, got {rule_rows}")
    (RESULTS / "rule_sha256.txt").write_text(
        f"runtime_canonical_sha256={rule_hash}\nimage_digest={EXPECTED_PROXY_DIGEST}\n", encoding="utf-8"
    )
    (RESULTS / "rules.sql").write_text(RULE_SQL + "\n", encoding="utf-8")
    (RESULTS / "pgsql_query_rules_frozen.tsv").write_text(
        "rule_id\tactive\tmatch_pattern\tre_modifiers\terror_msg\tapply\tcomment\n"
        + "".join("\t".join(row[key] for key in ("rule_id", "active", "match_pattern", "re_modifiers", "error_msg", "apply", "comment")) + "\n" for row in rule_rows),
        encoding="utf-8",
    )
    dataset = build_dataset()
    (RESULTS / "dataset.json").write_text(json.dumps(dataset, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    dataset_hash = sha256_bytes(canonical_json(dataset))
    (RESULTS / "dataset_sha256.txt").write_text(f"canonical_dataset_sha256={dataset_hash}\n", encoding="utf-8")
    save_environment(rule_hash, dataset_hash)
    print(f"Frozen rule SHA256: {rule_hash}", flush=True)
    print(f"Frozen dataset SHA256: {dataset_hash}", flush=True)

    # Baseline is completed before any protected evaluation.  A single invalid
    # unique sample aborts the run rather than silently changing the denominator.
    baseline_rows = run_stage(dataset, BASELINE_URL, "baseline")
    baseline_fields = list(baseline_rows[0])
    write_csv(RESULTS / "baseline_raw.csv", baseline_rows, baseline_fields)
    base_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in baseline_rows:
        base_by_id[row["sample_id"]].append(row)
    invalid = []
    for sample in dataset:
        rows = base_by_id[sample["sample_id"]]
        if not all(row["ok"] for row in rows) or (sample["label"] == "malicious" and not all(row["attack_success"] for row in rows)):
            invalid.append({"sample_id": sample["sample_id"], "scene": sample["scene"], "label": sample["label"], "rows": rows})
    if invalid:
        (RESULTS / "baseline_invalid.json").write_text(json.dumps(invalid, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        raise RuntimeError(f"baseline validation failed for {len(invalid)} unique samples; see baseline_invalid.json; no protected stage was run")
    print(f"Baseline validation passed for all {len(dataset)} unique samples", flush=True)

    # Freeze verification immediately before formal traffic and after it.  The
    # policy is never changed by this process once the formal stage starts.
    frozen_hash, _ = snapshot_rules()
    if frozen_hash != rule_hash:
        raise RuntimeError(f"rule hash changed before formal run: {frozen_hash} != {rule_hash}")
    firewall_rows = run_stage(dataset, FIREWALL_URL, "firewall")
    write_csv(RESULTS / "firewall_raw.csv", firewall_rows, list(firewall_rows[0]))
    after_hash, _ = snapshot_rules()
    if after_hash != rule_hash:
        raise RuntimeError(f"rule hash changed during formal run: {after_hash} != {rule_hash}")

    unique_rows, request_rows, errors, metrics = aggregate_metrics(dataset, baseline_rows, firewall_rows)
    write_csv(RESULTS / "unique_results.csv", unique_rows, list(unique_rows[0]))
    write_csv(RESULTS / "request_results.csv", request_rows, list(request_rows[0]) if request_rows else ["sample_id"])
    write_csv(RESULTS / "errors.csv", errors, list(errors[0]) if errors else ["sample_id", "error_type", "classification"])
    rule_hits = read_stats()
    write_csv(RESULTS / "rule_hits.csv", rule_hits, ["rule_id", "hits"])

    container_logs = {
        "proxysql": run_cmd(["docker", "logs", "--timestamps", service_container("proxysql")], check=False, timeout=120).stdout,
        "firewall_api": run_cmd(["docker", "logs", "--timestamps", service_container("firewall-api")], check=False, timeout=120).stdout,
        "baseline_api": run_cmd(["docker", "logs", "--timestamps", service_container("baseline-api")], check=False, timeout=120).stdout,
    }
    for name, content in container_logs.items():
        (RESULTS / "logs" / f"{name}.log").write_text(content, encoding="utf-8")

    overall = {
        "experiment": "PostgreSQL 13 + ProxySQL Database Firewall",
        "proxysql_version": "3.0.11",
        "proxysql_image_digest": EXPECTED_PROXY_DIGEST,
        "postgresql_version": "13",
        "rule_sha256": rule_hash,
        "dataset_sha256": dataset_hash,
        "listener_port_container": 6133,
        "listener_port_host": 15433,
        "backend_port_container": 5432,
        "backend_port_host": 15432,
        "admin_port_container": 6032,
        "admin_port_host": 16132,
        "repeats": REPEATS,
        "generated_unique": len(dataset),
        "smoke_test": smoke,
        "rule_hits": rule_hits,
        "scenes": list(metrics.values()),
        "completed_utc": datetime.now(timezone.utc).isoformat(),
    }
    (RESULTS / "summary.json").write_text(json.dumps(overall, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(overall, ensure_ascii=False, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit("interrupted")
