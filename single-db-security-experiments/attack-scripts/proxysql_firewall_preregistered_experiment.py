#!/usr/bin/env python3
"""Pre-registered, independent ProxySQL firewall evaluation.

The existing result directories are never overwritten.  This entry point
freezes the current three-rule policy, creates a deterministic corpus that is
deduplicated against every previous corpus, validates it through the direct
PostgreSQL baseline, and then runs the same corpus through ProxySQL.  Baseline
validity is the only criterion used for eligibility; firewall outcomes never
remove or replace a sample.

The formal run uses one request per unique sample.  The one-repeat choice is
recorded in the metadata and is independent of the earlier five-repeat runs.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import proxysql_firewall_experiment as base  # noqa: E402
import proxysql_firewall_tuned_experiment as tuned  # noqa: E402


RESULTS_DIR = base.ROOT / "results" / "proxysql_firewall_preregistered"
PROJECT = os.environ.get("PROXYSQL_COMPOSE_PROJECT", "proxysql-firewall-preregistered")
TARGET_PER_LABEL = 100
REPEATS = 1
RULE_IDS = (10, 11, 20)
RULE_SQL = tuned.TUNED_RULE_SQL
ERROR_TYPES = {
    "parser_error",
    "protocol_error",
    "connection_error",
    "sql_syntax_error",
    "application_error",
    "backend_error",
}
SMOKE_CANONICAL = {
    "select id, username, secret from vuln_users where id=1",
    "call public.safe_proc(1)",
    "call public.sensitive_proc(1)",
}


def canonical_sql(sql: str) -> str:
    no_block = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    no_line = re.sub(r"--[^\n]*(?:\n|$)", " ", no_block)
    normalized = re.sub(r"\s+", " ", no_line).strip()
    if normalized.endswith(";"):
        normalized = normalized[:-1].rstrip()
    return normalized.lower()


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def historical_canonical() -> set[str]:
    """Collect every prior dataset, not just the immediately preceding one."""

    result: set[str] = set(SMOKE_CANONICAL)
    results_root = base.ROOT / "results"
    for dataset_file in results_root.glob("**/dataset.json"):
        if RESULTS_DIR in dataset_file.parents:
            continue
        try:
            rows = json.loads(dataset_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for row in rows:
            if isinstance(row, dict) and isinstance(row.get("sql"), str):
                result.add(canonical_sql(row["sql"]))
    return result


def sample(sample_id: str, scene: str, label: str, sql: str, endpoint: str = "/pg/query") -> dict[str, str]:
    return base._sample(sample_id, scene, label, sql, endpoint)


def collect_sql(
    scene: str,
    label: str,
    producers: list[Callable[[int], str]],
    occupied: set[str],
    endpoint: str = "/pg/query",
) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for variant in range(401, 3000):
        for producer in producers:
            sql = producer(variant)
            key = canonical_sql(sql)
            if key in occupied:
                continue
            occupied.add(key)
            rows.append(sample(f"{scene}_{label}_{len(rows) + 1:03d}", scene, label, sql, endpoint))
            if len(rows) == TARGET_PER_LABEL:
                return rows
    raise AssertionError(f"could not generate {TARGET_PER_LABEL} unique {scene}/{label} statements")


def basic_malicious_families() -> list[Callable[[int], str]]:
    q = "SELECT id, username, secret FROM vuln_users"
    return [
        lambda i: f"{q} WHERE id = 0 OR {i} = {i};",
        lambda i: f"{q} WHERE (id = 0) OR ({i} BETWEEN {i} AND {i});",
        lambda i: f"{q} WHERE id = (0::integer) OR ({i} = {i});",
        lambda i: f"{q} WHERE id = 0 AND ({i} = {i}) OR ({i} = {i});",
        lambda i: f"{q} WHERE id = 0 OR EXISTS (SELECT 1 FROM vuln_users WHERE id = {(i % 3) + 1});",
        lambda i: f"{q} WHERE id = 0 OR (SELECT COUNT(*) FROM vuln_users) > 0;",
        lambda i: f"{q} WHERE id = 0 OR CASE WHEN {i} = {i} THEN TRUE ELSE FALSE END;",
        lambda i: f"{q} WHERE id = 0 OR NOT ({i} <> {i});",
        lambda i: f"{q} WHERE id = 0 OR id IN (SELECT id FROM vuln_users);",
        lambda i: f"{q} WHERE id = 0 OR id = ANY(ARRAY[1, 2, 3]);",
        lambda i: f"{q} WHERE id = 0 OR CAST({i} AS integer) = {i};",
        lambda i: f"SELECT id, username, secret FROM public.vuln_users WHERE id = 0 OR {i} = {i};",
        lambda i: f"SELECT u.id, u.username, u.secret FROM vuln_users AS u WHERE u.id = 0 OR {i} = {i};",
        lambda i: f"SELECT q.id, q.username, q.secret FROM (SELECT id, username, secret FROM vuln_users WHERE id = 0 OR {i} = {i}) AS q;",
        lambda i: f"WITH q AS (SELECT id, username, secret FROM vuln_users WHERE id = 0 OR {i} = {i}) SELECT id, username, secret FROM q;",
        lambda i: f"{q} WHERE id = 0 UNION SELECT {4000 + i}, 'prg_inj_{i}', 'prg_leak_{i}';",
        lambda i: f"{q} WHERE id = 0 UNION ALL SELECT {4000 + i}, 'prg_inj_{i}', 'prg_leak_{i}';",
        lambda i: f"{q} WHERE id = 0 UNION ALL SELECT {4000 + i}, 'prg_' || {i}::text, 'prg_leak';",
        lambda i: f"SELECT q.id, q.username, q.secret FROM ({q} WHERE id = 0 UNION ALL SELECT {4000 + i}, 'prg_inj_{i}', 'prg_leak_{i}') AS q;",
        lambda i: f"WITH q AS ({q} WHERE id = 0 UNION SELECT {4000 + i}, 'prg_inj_{i}', 'prg_leak_{i}') SELECT id, username, secret FROM q;",
    ]


def basic_legitimate_families() -> list[Callable[[int], str]]:
    q = "SELECT id, username, secret FROM vuln_users"
    return [
        lambda i: f"{q} WHERE id = {(i % 3) + 1};",
        lambda i: f"{q} WHERE id = ({(i % 3) + 1}) + 0;",
        lambda i: f"{q} WHERE id = CAST({(i % 3) + 1} AS integer);",
        lambda i: f"{q} WHERE id = CASE WHEN {i} = {i} THEN {(i % 3) + 1} ELSE 1 END;",
        lambda i: f"{q} WHERE id BETWEEN 1 AND 3 AND username <> 'ordinary-{i}';",
        lambda i: f"{q} WHERE id IN ({(i % 3) + 1}, 99) ORDER BY id;",
        lambda i: f"{q} WHERE id = 0 OR {i} <> {i};",
        lambda i: f"{q} WHERE id = 0 OR ({i} = {i - 1});",
        lambda i: f"{q} WHERE id IS NOT NULL AND id = {(i % 3) + 1};",
        lambda i: f"{q} WHERE EXISTS (SELECT 1 FROM vuln_users x WHERE x.id = {(i % 3) + 1}) ORDER BY username;",
        lambda i: f"SELECT v.id, v.username, v.secret FROM vuln_users v JOIN (SELECT {(i % 3) + 1} AS id) x ON x.id=v.id;",
        lambda i: f"SELECT id, COUNT(*)::text AS username, MAX(secret) AS secret FROM vuln_users GROUP BY id ORDER BY id;",
        lambda i: f"SELECT COUNT(*) AS id, 'ordinary aggregate {i}' AS username, MAX(secret) AS secret FROM vuln_users;",
        lambda i: f"SELECT 1 AS id, 'ordinary UNION {i}' AS username, 'normal' AS secret UNION SELECT 2, 'second', 'normal';",
        lambda i: f"SELECT 1 AS id, 'ordinary UNION ALL {i}' AS username, 'normal' AS secret UNION ALL SELECT 2, 'second', 'normal';",
        lambda i: f"SELECT id, username, secret FROM (SELECT id, username, secret FROM vuln_users WHERE id={(i % 3) + 1}) q;",
        lambda i: f"WITH q AS (SELECT id, username, secret FROM vuln_users WHERE id={(i % 3) + 1}) SELECT id, username, secret FROM q;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE username = 'contains UNION OR SELECT {i}';",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE ((id={(i % 3) + 1}) AND (id IS NOT NULL)) OR id=99;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id={(i % 3) + 1} /* comment with UNION and OR {i} */;",
    ]


def wrap_obfuscated(sql: str, variant: int, label: str) -> str:
    body = sql.rstrip()
    if body.endswith(";"):
        body = body[:-1]
    alias = f"pre_{label}_{variant}"
    return f"SELECT {alias}.id, {alias}.username, {alias}.secret FROM ({body}) AS {alias};"


def obfuscated_malicious_families() -> list[Callable[[int], str]]:
    q = "SELECT id, username, secret FROM vuln_users"
    raw: list[Callable[[int], str]] = [
        lambda i: f"{q} WHERE id/**/=/**/0/**/OR/**/{i}={i};",
        lambda i: f"{q} WHERE id = 0 /* left-{i} */ OR /* right-{i} */ ({i}={i});",
        lambda i: f"{q} WHERE id = 0\tOR\t({i}={i});",
        lambda i: f"{q} WHERE id = 0\nOR\n({i}={i});",
        lambda i: f"{q} WHERE (id = 0)/**/OR/**/({i}={i});",
        lambda i: f"{q} WHERE id = (0) /* p-{i} */ OR ({i}={i});",
        lambda i: f"{q} WHERE id = 0 + 0/**/oR/**/({i}={i});",
        lambda i: f"{q} WHERE id = 0 /* a-{i} */ AND ({i}={i}) /* b-{i} */ OR ({i}={i});",
        lambda i: f"{q} WHERE id = 0/**/OR/**/({i} BETWEEN {i} AND {i});",
        lambda i: f"{q} WHERE id = 0/**/OR/**/EXISTS(/* e-{i} */ SELECT 1 FROM vuln_users WHERE id=1);",
        lambda i: f"{q} WHERE id = 0 /* c-{i} */ OR (SELECT COUNT(*) FROM vuln_users) > 0;",
        lambda i: f"{q} WHERE id = 0/**/OR/**/CASE WHEN {i}={i} THEN TRUE ELSE FALSE END;",
        lambda i: f"SELECT id, username, secret FROM public.vuln_users WHERE id/**/=/**/0/**/OR/**/{i}={i};",
        lambda i: f"SELECT u.id, u.username, u.secret FROM vuln_users AS u WHERE u.id = 0/**/OR/**/({i}={i});",
        lambda i: f"SELECT q.id, q.username, q.secret FROM (SELECT id, username, secret FROM vuln_users WHERE id=0/**/OR/**/({i}={i})) q;",
        lambda i: f"WITH q AS (SELECT id, username, secret FROM vuln_users WHERE id = 0 /* cte-{i} */ OR ({i}={i})) SELECT id, username, secret FROM q;",
        lambda i: f"{q} WHERE id = 0/**/UNION/**/SELECT {5000+i}, 'pre_obf_{i}', 'pre_leak_{i}';",
        lambda i: f"{q} WHERE id = 0/**/UNION/**/ALL/**/SELECT {5000+i}, 'pre_obf_{i}', 'pre_leak_{i}';",
        lambda i: f"{q} WHERE id = 0 /* u-{i} */ UnIoN AlL /* s-{i} */ SeLeCt {5000+i}, 'pre_obf_{i}', 'pre_leak_{i}';",
        lambda i: f"{q} WHERE id = 0\nUNION\nALL\nSELECT {5000+i}, 'pre_obf_{i}', 'pre_leak_{i}';",
    ]
    return [lambda i, family=family: wrap_obfuscated(family(i), i, "m") for family in raw]


def obfuscated_legitimate_families() -> list[Callable[[int], str]]:
    q = "SELECT id, username, secret FROM vuln_users"
    raw: list[Callable[[int], str]] = [
        lambda i: f"SeLeCt id, username, secret FrOm vuln_users WhErE (id={(i % 3) + 1} AnD {i}={i});",
        lambda i: f"{q}\nWHERE id={(i % 3) + 1}\tAND username <> 'nobody-{i}' -- ordinary line\n;",
        lambda i: f"{q} WHERE id IN ({(i % 3) + 1},99) AND ('UNION value {i}' LIKE '%UNION%' OR 'x'='y');",
        lambda i: f"SELECT v.id,v.username,v.secret FROM vuln_users v WHERE EXISTS (SELECT 1 FROM vuln_users q WHERE q.id=v.id AND q.id={(i % 3) + 1}) AND CASE WHEN {i}={i} THEN TRUE ELSE FALSE END;",
        lambda i: f"SELECT 1 AS id, 'OR literal {i}' AS username, 'SELECT literal' AS secret UNION SELECT 2, 'normal', 'UNION is a value';",
        lambda i: f"SELECT 1 AS id, 'OR literal {i}' AS username, 'SELECT literal' AS secret UNION ALL SELECT 2, 'normal', 'UNION is a value';",
        lambda i: f"{q} WHERE ((id={(i % 3) + 1}) /* p-{i} */ AND (id IS NOT NULL)) AND (id BETWEEN 1 AND 3);",
        lambda i: f"{q} WHERE id=0 OR {i}={i-1} /* false branch {i} */;",
        lambda i: f"{q} WHERE id = 0 /* false-{i} */ OR ({i} <> {i});",
        lambda i: f"{q} WHERE id={(i % 3) + 1} /* text UNION OR SELECT {i} */;",
        lambda i: f"WITH q AS (SELECT id, username, secret FROM vuln_users WHERE id={(i % 3) + 1}) SELECT id,username,secret FROM q ORDER BY id;",
        lambda i: f"SELECT id,username,secret FROM vuln_users WHERE username='contains -- comment {i}' OR username<>'UNION';",
        lambda i: f"SELECT id,username,secret FROM vuln_users WHERE id={(i % 3) + 1} AND (username || secret) IS NOT NULL;",
        lambda i: f"SELECT id,username,secret FROM vuln_users WHERE id={(i % 3) + 1} GROUP BY id,username,secret HAVING COUNT(*)>=1;",
        lambda i: f"SELECT id,username,secret FROM vuln_users WHERE id=(SELECT MIN(id) FROM vuln_users)+{i % 2};",
    ]
    return [lambda i, family=family: wrap_obfuscated(family(i), i, "l") for family in raw]


def call_malicious_families() -> list[Callable[[int], str]]:
    return [
        lambda i: f"CALL public.sensitive_proc({i});",
        lambda i: f"CALL PUBLIC.sensitive_proc({i});",
        lambda i: f"CALL public.sensitive_proc( {i} );",
        lambda i: f"CALL\npublic.sensitive_proc({i});",
        lambda i: f"CALL /* pre-call-{i} */ public.sensitive_proc({i});",
        lambda i: f"CALL public./* pre-name-{i} */sensitive_proc({i});",
        lambda i: f"CALL public.\"sensitive_proc\"({i});",
        lambda i: f"call public.sensitive_proc(({i}));",
        lambda i: f"CALL public.sensitive_proc({i} /* argument-{i} */);",
        lambda i: f"CALL public.sensitive_proc(CAST({i} AS integer));",
    ]


def call_legitimate_families() -> list[Callable[[int], str]]:
    return [
        lambda i: f"CALL public.safe_proc({i});",
        lambda i: f"CALL PUBLIC.safe_proc({i});",
        lambda i: f"CALL public.safe_proc( {i} );",
        lambda i: f"CALL\npublic.safe_proc({i});",
        lambda i: f"CALL /* ordinary-call-{i} */ public.safe_proc({i});",
        lambda i: f"CALL public./* safe-name-{i} */safe_proc({i});",
        lambda i: f"CALL public.\"safe_proc\"({i});",
        lambda i: f"call public.safe_proc(({i}));",
        lambda i: f"CALL public.safe_proc({i} /* safe-argument-{i} */);",
        lambda i: f"CALL public.safe_proc(CAST({i} AS integer));",
        lambda i: f"CALL public.sensitive_proc_audit({i});",
        lambda i: f"CALL public.sensitive_proc_audit( {i} );",
        lambda i: f"CALL PUBLIC.sensitive_proc_audit({i});",
        lambda i: f"CALL public.\"sensitive_proc_audit\"({i});",
        lambda i: f"CALL /* audit-{i} */ public.sensitive_proc_audit({i});",
    ]


def build_dataset() -> list[dict[str, str]]:
    occupied = historical_canonical()
    rows: list[dict[str, str]] = []
    for scene, malicious, legitimate, endpoint in (
        ("basic_sql_injection", basic_malicious_families(), basic_legitimate_families(), "/pg/query"),
        ("obfuscated_sql_injection", obfuscated_malicious_families(), obfuscated_legitimate_families(), "/pg/query"),
        ("stored_procedure_call", call_malicious_families(), call_legitimate_families(), "/pg/call"),
    ):
        rows.extend(collect_sql(scene, "malicious", malicious, occupied, endpoint))
        rows.extend(collect_sql(scene, "legitimate", legitimate, occupied, endpoint))
    if len(rows) != 6 * TARGET_PER_LABEL:
        raise AssertionError(f"expected {6 * TARGET_PER_LABEL} rows, got {len(rows)}")
    if len({canonical_sql(row["sql"]) for row in rows}) != len(rows):
        raise AssertionError("global canonical uniqueness failed")
    return rows


def save_preregistration(dataset: list[dict[str, str]], rule_hash: str) -> str:
    dataset_hash = sha256_bytes(canonical_json(dataset))
    previous = historical_canonical()
    generated = {canonical_sql(row["sql"]) for row in dataset}
    overlap = sorted(generated & previous)
    (RESULTS_DIR / "dataset.json").write_text(json.dumps(dataset, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    (RESULTS_DIR / "dataset_sha256.txt").write_text(f"canonical_dataset_sha256={dataset_hash}\n", encoding="utf-8")
    (RESULTS_DIR / "overlap_check.json").write_text(
        json.dumps({"generated_unique": len(dataset), "canonical_unique": len(generated), "historical_canonical_count": len(previous), "overlap_count": len(overlap), "overlap": overlap}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    prereg = {
        "protocol": "pre-registered independent ProxySQL Database Firewall evaluation",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "rule_sha256_at_preregistration": rule_hash,
        "proxysql_version": "3.0.11",
        "postgresql_version": "13",
        "repeats": REPEATS,
        "target_per_label_per_scene": TARGET_PER_LABEL,
        "scenes": ["basic_sql_injection", "obfuscated_sql_injection", "stored_procedure_call"],
        "canonical_overlap_policy": "zero overlap with every existing results/**/dataset.json and smoke statements",
        "technical_invalid_criteria": [
            "baseline HTTP/DB request is not successful (ok != true)",
            "baseline error_type is parser_error, protocol_error, connection_error, sql_syntax_error, application_error, or backend_error",
            "malicious baseline request does not produce its predeclared attack effect",
            "legitimate baseline request does not execute successfully",
        ],
        "exclusion_policy": "criteria are evaluated from baseline only; invalid rows remain in raw files and are never replaced",
        "firewall_outcome_policy": "parser/transport/application/backend errors are reported separately and never count as TP/FN/FP/TN",
        "overlap_count": len(overlap),
    }
    (RESULTS_DIR / "preregistration.json").write_text(json.dumps(prereg, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    if overlap:
        raise RuntimeError(f"pre-registered dataset overlaps historical canonical SQL: {overlap[:3]}")
    return dataset_hash


def baseline_validity(sample_row: dict[str, Any], rows: list[dict[str, Any]]) -> tuple[bool, str]:
    for row in rows:
        if not row["ok"]:
            return False, f"baseline_not_successful:{row['error_type']}"
        if row["error_type"] in ERROR_TYPES:
            return False, f"baseline_technical_error:{row['error_type']}"
    if sample_row["label"] == "malicious" and not all(bool(row["attack_success"]) for row in rows):
        return False, "baseline_expected_attack_effect_missing"
    if sample_row["label"] == "legitimate" and not all(bool(row["ok"]) for row in rows):
        return False, "baseline_legitimate_execution_failed"
    return True, ""


def classify_firewall(sample_row: dict[str, Any], row: dict[str, Any]) -> tuple[str, str]:
    if row["error_type"] in ERROR_TYPES:
        return "error", row["error_type"]
    if sample_row["label"] == "malicious":
        if row["firewall_blocked"] and not row["attack_success"]:
            return "TP", "rule_block_and_no_backend_attack"
        if not row["firewall_blocked"] and row["attack_success"]:
            return "FN", "not_blocked_backend_attack_succeeded"
        return "error", "inconclusive_malicious_outcome"
    if row["firewall_blocked"]:
        return "FP", "rule_blocked_baseline_valid_legitimate"
    if row["ok"]:
        return "TN", "allowed_baseline_valid_legitimate"
    return "error", "legitimate_execution_not_successful"


def aggregate(
    dataset: list[dict[str, str]],
    baseline_rows: list[dict[str, Any]],
    firewall_rows: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    samples = {row["sample_id"]: row for row in dataset}
    base_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    fw_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in baseline_rows:
        base_by_id[row["sample_id"]].append(row)
    for row in firewall_rows:
        fw_by_id[row["sample_id"]].append(row)

    unique_rows: list[dict[str, Any]] = []
    request_rows: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    metrics: dict[str, Any] = {}
    for scene in ("basic_sql_injection", "obfuscated_sql_injection", "stored_procedure_call"):
        scene_samples = [row for row in dataset if row["scene"] == scene]
        counts = Counter()
        invalid_counts = Counter()
        error_counts = Counter()
        unstable = 0
        for sample_row in scene_samples:
            sid = sample_row["sample_id"]
            b_rows = base_by_id[sid]
            f_rows = fw_by_id[sid]
            eligible, invalid_reason = baseline_validity(sample_row, b_rows)
            if not eligible:
                invalid_counts[sample_row["label"]] += 1
            classifications: list[str] = []
            reasons: list[str] = []
            for row in f_rows:
                classification, reason = classify_firewall(sample_row, row)
                classifications.append(classification)
                reasons.append(reason)
                if classification == "error":
                    error_counts[reason] += 1
                    errors.append({**row, "classification": classification, "classification_reason": reason, "baseline_eligible": eligible})
                elif eligible:
                    counts[classification] += 1
                    request_rows.append({**row, "classification": classification, "classification_reason": reason, "baseline_eligible": eligible})
            stable = len(set(classifications)) <= 1
            if not stable:
                unstable += 1
            unique_class = "excluded_baseline_invalid" if not eligible else (classifications[0] if len(set(classifications)) == 1 and classifications[0] in {"TP", "FN", "FP", "TN"} else "error")
            if unique_class == "error" and eligible:
                errors.append({"sample_id": sid, "scene": scene, "classification": "error", "classification_reason": "mixed_or_inconclusive", "baseline_eligible": eligible})
            unique_rows.append(
                {
                    "sample_id": sid,
                    "scene": scene,
                    "label": sample_row["label"],
                    "baseline_eligible": eligible,
                    "baseline_invalid_reason": invalid_reason,
                    "classification": unique_class,
                    "repeat_classifications": ",".join(classifications),
                    "stable": stable,
                }
            )

        eligible_m = sum(row["label"] == "malicious" and row["baseline_eligible"] for row in unique_rows if row["scene"] == scene)
        eligible_l = sum(row["label"] == "legitimate" and row["baseline_eligible"] for row in unique_rows if row["scene"] == scene)
        generated_m = sum(row["label"] == "malicious" for row in scene_samples)
        generated_l = sum(row["label"] == "legitimate" for row in scene_samples)
        tpr_den = counts["TP"] + counts["FN"]
        fpr_den = counts["FP"] + counts["TN"]
        metrics[scene] = {
            "scene": scene,
            "generated_malicious_unique": generated_m,
            "generated_legitimate_unique": generated_l,
            "eligible_malicious_unique": eligible_m,
            "eligible_legitimate_unique": eligible_l,
            "baseline_invalid_malicious_unique": invalid_counts["malicious"],
            "baseline_invalid_legitimate_unique": invalid_counts["legitimate"],
            "repeats": REPEATS,
            "TP": counts["TP"],
            "FN": counts["FN"],
            "FP": counts["FP"],
            "TN": counts["TN"],
            "TPR": counts["TP"] / tpr_den if tpr_den else None,
            "FPR": counts["FP"] / fpr_den if fpr_den else None,
            "parser_or_transport_error_requests": sum(error_counts.values()),
            "error_breakdown": dict(error_counts),
            "unstable_unique_requests": unstable,
            "all_generated_conservative_TPR": counts["TP"] / generated_m if generated_m else None,
            "all_generated_conservative_FPR": counts["FP"] / generated_l if generated_l else None,
        }
    return unique_rows, request_rows, errors, metrics


def save_sensitivity(metrics: dict[str, Any]) -> None:
    rows: list[dict[str, Any]] = []
    for scene, m in metrics.items():
        for scope, tpr, fpr, mden, lden in (
            ("all_generated_conservative", m["all_generated_conservative_TPR"], m["all_generated_conservative_FPR"], m["generated_malicious_unique"], m["generated_legitimate_unique"]),
            ("baseline_eligible_standard", m["TPR"], m["FPR"], m["eligible_malicious_unique"], m["eligible_legitimate_unique"]),
        ):
            rows.append(
                {
                    "scene": scene,
                    "scope": scope,
                    "malicious_denominator": mden,
                    "legitimate_denominator": lden,
                    "TP": m["TP"],
                    "FN": m["FN"],
                    "FP": m["FP"],
                    "TN": m["TN"],
                    "TPR": tpr,
                    "FPR": fpr,
                    "baseline_invalid_malicious": m["baseline_invalid_malicious_unique"],
                    "baseline_invalid_legitimate": m["baseline_invalid_legitimate_unique"],
                    "parser_or_transport_errors": m["parser_or_transport_error_requests"],
                }
            )
    write_csv(RESULTS_DIR / "sensitivity_analysis.csv", rows, list(rows[0]))


def save_summary(metrics: dict[str, Any], rule_hash: str, dataset_hash: str, smoke: dict[str, Any], rule_hits: list[dict[str, Any]]) -> None:
    lines = [
        "# Pre-registered ProxySQL Database Firewall Evaluation",
        "",
        "This report is a new independent evaluation. Existing result directories are unchanged.",
        "Formal repeats per unique request: 1.",
        "Baseline-invalid samples are retained and excluded only by the pre-registered technical criteria in `preregistration.json`.",
        "Firewall parser/transport/application/backend errors are not TP/FN/FP/TN.",
        "",
        f"- Rule SHA256: `{rule_hash}`",
        f"- Dataset SHA256: `{dataset_hash}`",
        "- ProxySQL: 3.0.11",
        "- PostgreSQL: 13",
        "",
        "## Metrics",
        "",
        "| Scene | Generated M/L | Eligible M/L | TP | FN | TPR | FP | TN | FPR | Errors |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for scene, m in metrics.items():
        lines.append(
            f"| {scene} | {m['generated_malicious_unique']}/{m['generated_legitimate_unique']} | "
            f"{m['eligible_malicious_unique']}/{m['eligible_legitimate_unique']} | {m['TP']} | {m['FN']} | "
            f"{m['TPR']:.4%} | {m['FP']} | {m['TN']} | {m['FPR']:.4%} | {m['parser_or_transport_error_requests']} |"
        )
    lines.extend([
        "",
        "## Sensitivity analysis",
        "",
        "`baseline_eligible_standard` is the primary confusion-matrix metric. `all_generated_conservative` keeps all generated malicious/legitimate samples in the rate denominator; technical invalids remain visible rather than silently removed.",
        "",
        "## Smoke evidence",
        "",
        "```json",
        json.dumps(smoke, ensure_ascii=False, indent=2),
        "```",
        "",
        "## Rule hits",
        "",
        "```json",
        json.dumps(rule_hits, ensure_ascii=False, indent=2),
        "```",
        "",
        "## Reproduction",
        "",
        "```bash",
        "./run_proxysql_firewall_preregistered_experiment.sh",
        "```",
    ])
    (RESULTS_DIR / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    if (RESULTS_DIR / "summary.json").exists() and os.environ.get("PROXYSQL_ALLOW_OVERWRITE") != "1":
        raise SystemExit(f"{RESULTS_DIR} already contains results; refusing to overwrite")
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / "logs").mkdir(exist_ok=True)

    base.PROJECT = PROJECT
    base.RESULTS = RESULTS_DIR
    base.REPEATS = REPEATS
    base.RULE_SQL = RULE_SQL
    base.RULE_IDS = RULE_IDS

    print("Waiting for ProxySQL admin and applying the fixed policy", flush=True)
    for _ in range(60):
        try:
            base.mysql_admin("SELECT 1;")
            break
        except Exception:
            base.time.sleep(1)
    else:
        raise RuntimeError("ProxySQL admin interface did not become ready")
    base.mysql_admin(RULE_SQL)
    base.wait_for_http(base.BASELINE_URL + "/health")
    base.wait_for_http(base.FIREWALL_URL + "/health")

    smoke = base.smoke_test()
    (RESULTS_DIR / "smoke_test.json").write_text(json.dumps(smoke, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    # The policy is frozen after smoke/calibration and before corpus creation.
    rule_hash, rule_rows = base.snapshot_rules()
    if len(rule_rows) != len(RULE_IDS):
        raise RuntimeError(f"expected {len(RULE_IDS)} frozen rules, got {rule_rows}")
    (RESULTS_DIR / "rule_sha256.txt").write_text(f"runtime_canonical_sha256={rule_hash}\nimage_digest={base.EXPECTED_PROXY_DIGEST}\n", encoding="utf-8")
    (RESULTS_DIR / "rules.sql").write_text(RULE_SQL + "\n", encoding="utf-8")
    (RESULTS_DIR / "pgsql_query_rules_frozen.tsv").write_text(
        "rule_id\tactive\tmatch_pattern\tre_modifiers\terror_msg\tapply\tcomment\n"
        + "".join("\t".join(row[key] for key in ("rule_id", "active", "match_pattern", "re_modifiers", "error_msg", "apply", "comment")) + "\n" for row in rule_rows),
        encoding="utf-8",
    )

    dataset = build_dataset()
    dataset_hash = save_preregistration(dataset, rule_hash)
    print(f"Frozen rule SHA256: {rule_hash}", flush=True)
    print(f"Pre-registered dataset SHA256: {dataset_hash}", flush=True)

    baseline_rows = base.run_stage(dataset, base.BASELINE_URL, "baseline")
    write_csv(RESULTS_DIR / "baseline_raw.csv", baseline_rows, list(baseline_rows[0]))
    base_by_id: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in baseline_rows:
        base_by_id[row["sample_id"]].append(row)
    invalid_rows: list[dict[str, Any]] = []
    for sample_row in dataset:
        eligible, reason = baseline_validity(sample_row, base_by_id[sample_row["sample_id"]])
        if not eligible:
            invalid_rows.append({"sample_id": sample_row["sample_id"], "scene": sample_row["scene"], "label": sample_row["label"], "invalid_reason": reason})
    write_csv(RESULTS_DIR / "baseline_invalid.csv", invalid_rows, ["sample_id", "scene", "label", "invalid_reason"])

    firewall_rows = base.run_stage(dataset, base.FIREWALL_URL, "firewall")
    write_csv(RESULTS_DIR / "firewall_raw.csv", firewall_rows, list(firewall_rows[0]))
    after_hash, _ = base.snapshot_rules()
    if after_hash != rule_hash:
        raise RuntimeError(f"rule hash changed during formal evaluation: {after_hash} != {rule_hash}")

    unique_rows, request_rows, errors, metrics = aggregate(dataset, baseline_rows, firewall_rows)
    write_csv(RESULTS_DIR / "unique_results.csv", unique_rows, list(unique_rows[0]))
    write_csv(RESULTS_DIR / "request_results.csv", request_rows, list(request_rows[0]) if request_rows else ["sample_id"])
    write_csv(RESULTS_DIR / "errors.csv", errors, list(errors[0]) if errors else ["sample_id", "classification", "classification_reason"])
    save_sensitivity(metrics)

    # Stats are cumulative; capture the values after formal traffic once.
    rule_hits = [{"rule_id": row["rule_id"], "hits": row["hits"]} for row in base.read_stats()]
    write_csv(RESULTS_DIR / "rule_hits.csv", rule_hits, ["rule_id", "hits"])

    # Capture logs once after all traffic, rather than issuing per-request log calls.
    for name, service in (("proxysql", "proxysql"), ("firewall_api", "firewall-api"), ("baseline_api", "baseline-api")):
        content = base.run_cmd(["docker", "logs", "--timestamps", base.service_container(service)], check=False, timeout=120).stdout
        (RESULTS_DIR / "logs" / f"{name}.log").write_text(content, encoding="utf-8")

    summary = {
        "experiment": "Pre-registered independent PostgreSQL 13 + ProxySQL Database Firewall evaluation",
        "proxysql_version": "3.0.11",
        "proxysql_image_digest": base.EXPECTED_PROXY_DIGEST,
        "postgresql_version": "13",
        "rule_sha256": rule_hash,
        "dataset_sha256": dataset_hash,
        "repeats": REPEATS,
        "generated_unique": len(dataset),
        "baseline_invalid_unique": len(invalid_rows),
        "smoke_test": smoke,
        "scenes": list(metrics.values()),
        "completed_utc": datetime.now(timezone.utc).isoformat(),
        "result_scope_note": "existing result directories are preserved; baseline-invalid samples are retained and excluded only by pre-registered criteria",
    }
    (RESULTS_DIR / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    save_summary(metrics, rule_hash, dataset_hash, smoke, rule_hits)
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
