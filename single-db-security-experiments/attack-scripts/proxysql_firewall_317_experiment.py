#!/usr/bin/env python3
"""Run the fixed ProxySQL policy against a 317+317 corpus per scene.

The existing runner remains the implementation of the request execution,
smoke checks, rule snapshotting and metrics.  This entry point supplies a
larger, independent corpus and writes to a new results directory so the
previous 100+100 experiment is never overwritten.
"""

from __future__ import annotations

import os
import json
import re
import sys
from pathlib import Path
from typing import Callable, Iterable


SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPT_DIR))
import proxysql_firewall_experiment as base  # noqa: E402


TARGET_PER_LABEL = 317
RESULTS_DIR = base.ROOT / "results" / "proxysql_firewall_317"
SMOKE_SQL = {
    "SELECT id, username, secret FROM vuln_users WHERE id=1;",
    "CALL public.safe_proc(1);",
    "CALL public.sensitive_proc(1);",
}


def canonical_sql(sql: str) -> str:
    """Canonicalize enough SQL surface syntax for global corpus de-duplication."""

    without_block_comments = re.sub(r"/\*.*?\*/", " ", sql, flags=re.DOTALL)
    without_line_comments = re.sub(r"--[^\n]*(?:\n|$)", " ", without_block_comments)
    normalized = re.sub(r"\s+", " ", without_line_comments).strip()
    if normalized.endswith(";"):
        normalized = normalized[:-1].rstrip()
    return normalized.lower()


SMOKE_CANONICAL = {canonical_sql(sql) for sql in SMOKE_SQL}


OLD_DATASET_FILES = (
    base.ROOT / "results" / "proxysql_firewall" / "dataset.json",
    base.ROOT / "results" / "proxysql_firewall_pre_smoke_overlap" / "dataset.json",
    # The first 317-corpus run was archived after its overlap validation
    # failed.  Exclude it as well so the accepted corpus is not a rerun of
    # that invalid attempt.
    base.ROOT / "results" / "proxysql_firewall_317_attempt_overlap" / "dataset.json",
)
OLD_CANONICAL: set[str] = set()
for old_dataset_file in OLD_DATASET_FILES:
    if old_dataset_file.exists():
        for old_sample in json.loads(old_dataset_file.read_text(encoding="utf-8")):
            OLD_CANONICAL.add(canonical_sql(old_sample["sql"]))


def sample(sample_id: str, scene: str, label: str, sql: str, endpoint: str = "/pg/query") -> dict[str, str]:
    return base._sample(sample_id, scene, label, sql, endpoint)


def collect_sql(
    scene: str,
    label: str,
    producers: Iterable[Callable[[int], str]],
) -> list[dict[str, str]]:
    """Take the first target unique canonical statements from structural families."""

    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    # Interleave families for each variant so the fixed-size corpus contains
    # structural diversity rather than exhausting one template with changing
    # constants before reaching the next template.
    for variant in range(1, 80):
        for family_index, producer in enumerate(producers, 1):
            sql = producer(variant)
            key = canonical_sql(sql)
            if key in seen or key in SMOKE_CANONICAL or key in OLD_CANONICAL:
                continue
            seen.add(key)
            rows.append(sample(f"{scene}_{label}_{len(rows) + 1:03d}", scene, label, sql))
            if len(rows) == TARGET_PER_LABEL:
                return rows
    raise AssertionError(
        f"{scene}/{label} generated only {len(rows)} canonical SQL statements; "
        f"families={family_index}"
    )


def _basic_select() -> str:
    return "SELECT id, username, secret FROM vuln_users"


def _basic_malicious_families() -> list[Callable[[int], str]]:
    q = _basic_select()
    return [
        lambda i: f"{q} WHERE id = 0 OR {i} = {i};",
        lambda i: f"{q} WHERE id=0 OR ({i}={i});",
        lambda i: f"{q} WHERE (id = 0) OR ({i} BETWEEN {i} AND {i});",
        lambda i: f"{q} WHERE id = (0::integer) OR ({i} = {i});",
        lambda i: f"{q} WHERE id = 0::integer OR {i} = {i};",
        lambda i: f"{q} WHERE id = (0 + 0) OR ({i} = {i});",
        lambda i: f"{q} WHERE id = 0 AND ({i} = {i}) OR ({i} = {i});",
        lambda i: f"{q} WHERE id = 0 OR ({i} = {i} AND id IS NOT NULL);",
        lambda i: f"{q} WHERE id = 0 OR EXISTS (SELECT 1 FROM vuln_users AS x WHERE x.id = 1);",
        lambda i: f"{q} WHERE id = 0 OR 1 IN (SELECT x.id FROM vuln_users AS x);",
        lambda i: f"{q} WHERE id = 0 OR (SELECT COUNT(*) FROM vuln_users) > 0;",
        lambda i: f"{q} WHERE id = 0 OR CASE WHEN {i} = {i} THEN TRUE ELSE FALSE END;",
        lambda i: f"{q} WHERE id = 0 OR ({i} BETWEEN {i} AND {i});",
        lambda i: f"{q} WHERE id = 0 OR ('x' = 'x');",
        lambda i: f"{q} WHERE id = 0 OR length('abc') = 3;",
        lambda i: f"{q} WHERE id = 0 OR CAST({i} AS integer) = {i};",
        lambda i: f"{q} WHERE id = 0 OR (0 = 0 AND {i} = {i});",
        lambda i: f"{q} WHERE id = 0 OR NOT ({i} <> {i});",
        lambda i: f"{q} WHERE id = 0 OR id IN (SELECT id FROM vuln_users);",
        lambda i: f"{q} WHERE id = 0 OR id = ANY(ARRAY[1, 2, 3]);",
        lambda i: f"SELECT id, username, secret FROM public.vuln_users WHERE id = 0 OR {i} = {i};",
        lambda i: f"SELECT u.id, u.username, u.secret FROM vuln_users AS u WHERE u.id = 0 OR {i} = {i};",
        lambda i: f"SELECT q.id, q.username, q.secret FROM (SELECT id, username, secret FROM vuln_users WHERE id = 0 OR {i} = {i}) AS q;",
        lambda i: f"WITH q AS (SELECT id, username, secret FROM vuln_users WHERE id = 0 OR {i} = {i}) SELECT id, username, secret FROM q;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = 0 UNION SELECT {1000 + i}, 'inj_{i}', 'leak_{i}';",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = 0 UNION ALL SELECT {1000 + i}, 'inj_{i}', 'leak_{i}';",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = 0 UNION SELECT {1000 + i}, 'inj_' || {i}::text, 'leak_' || {i}::text;",
        lambda i: f"SELECT q.id, q.username, q.secret FROM (SELECT id, username, secret FROM vuln_users WHERE id = 0 UNION ALL SELECT {1000 + i}, 'inj_{i}', 'leak_{i}') AS q;",
        lambda i: f"SELECT id, username, secret FROM public.vuln_users WHERE id = 0 UNION ALL SELECT {1000 + i}, 'inj_{i}', 'leak_{i}';",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = 0 OR {i} = {i} UNION ALL SELECT {1000 + i}, 'inj_{i}', 'leak_{i}';",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = 0 OR EXISTS (SELECT 1 FROM vuln_users WHERE id = 1) UNION SELECT {1000 + i}, 'inj_{i}', 'leak_{i}';",
        lambda i: f"WITH q AS (SELECT id, username, secret FROM vuln_users WHERE id = 0 UNION ALL SELECT {1000 + i}, 'inj_{i}', 'leak_{i}') SELECT id, username, secret FROM q;",
        lambda i: f"SELECT * FROM (SELECT id, username, secret FROM vuln_users WHERE id = (0 + 0) OR ({i} = {i}) UNION ALL SELECT {1000 + i}, 'inj_{i}', 'leak_{i}') AS q;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = (0::int) OR (SELECT TRUE) UNION ALL SELECT {1000 + i}, 'inj_{i}', 'leak_{i}';",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = 0 OR (id IN (SELECT id FROM vuln_users)) UNION ALL SELECT {1000 + i}, 'inj_{i}', 'leak_{i}';",
    ]


def _basic_legitimate_families() -> list[Callable[[int], str]]:
    q = _basic_select()
    return [
        lambda i: f"{q} WHERE id = {(i % 3) + 1} /* legitimate basic {i} */;",
        lambda i: f"{q} WHERE id = ({(i % 3) + 1}) + 0;",
        lambda i: f"{q} WHERE id = CAST({(i % 3) + 1} AS integer);",
        lambda i: f"{q} WHERE id = CASE WHEN {i} = {i} THEN {(i % 3) + 1} ELSE 1 END;",
        lambda i: f"{q} WHERE id = COALESCE(NULL, {(i % 3) + 1});",
        lambda i: f"{q} WHERE id IN ({(i % 3) + 1}, 99) ORDER BY id;",
        lambda i: f"{q} WHERE id BETWEEN 1 AND 3 AND username <> 'nobody-{i}';",
        lambda i: f"{q} WHERE id = 0 OR {i} <> {i};",
        lambda i: f"{q} WHERE id = 0 OR ({i} = {i - 1});",
        lambda i: f"{q} WHERE id = 0 AND ({i} = {i});",
        lambda i: f"{q} WHERE id IS NOT NULL AND (id = {(i % 3) + 1});",
        lambda i: f"{q} WHERE EXISTS (SELECT 1 FROM vuln_users AS x WHERE x.id = {(i % 3) + 1}) ORDER BY username;",
        lambda i: f"{q} WHERE id IN (SELECT id FROM vuln_users WHERE id = {(i % 3) + 1});",
        lambda i: f"SELECT v.id, v.username, v.secret FROM vuln_users AS v JOIN (SELECT {(i % 3) + 1} AS id) AS x ON x.id = v.id;",
        lambda i: f"SELECT v.id, v.username, v.secret FROM vuln_users v LEFT JOIN vuln_users w ON w.id = v.id WHERE v.id = {(i % 3) + 1};",
        lambda i: f"SELECT id, COUNT(*)::text AS username, MAX(secret) AS secret FROM vuln_users WHERE id <= 3 GROUP BY id ORDER BY id;",
        lambda i: f"SELECT COUNT(*) AS id, 'aggregate_{i}' AS username, MAX(secret) AS secret FROM vuln_users;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE ((id = {(i % 3) + 1}) AND (id IS NOT NULL)) ORDER BY id DESC;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = ANY(ARRAY[1, 2, 3]) AND username LIKE 'a%';",
        lambda i: f"SELECT 1 AS id, 'union_value_{i}' AS username, 'normal' AS secret UNION SELECT 2, 'second_{i}', 'normal';",
        lambda i: f"SELECT 1 AS id, 'union_value_{i}' AS username, 'normal' AS secret UNION ALL SELECT 2, 'second_{i}', 'normal';",
        lambda i: f"SELECT id, username, secret FROM (SELECT id, username, secret FROM vuln_users WHERE id = {(i % 3) + 1}) AS q;",
        lambda i: f"WITH q AS (SELECT id, username, secret FROM vuln_users WHERE id = {(i % 3) + 1}) SELECT id, username, secret FROM q;",
        lambda i: f"SELECT id, username, secret FROM public.vuln_users WHERE id = {(i % 3) + 1};",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE username = 'contains UNION OR SELECT {i}';",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE CASE WHEN id = {(i % 3) + 1} THEN TRUE ELSE FALSE END;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE NOT (id <> {(i % 3) + 1}) OR id = 99;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id BETWEEN {(i % 3) + 1} AND {(i % 3) + 2} ORDER BY username LIMIT 3;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = {(i % 3) + 1} /* comment with UNION and OR {i} */;",
        lambda i: f"SELECT id, username, secret FROM vuln_users\nWHERE id = {(i % 3) + 1}\tAND secret IS NOT NULL\nORDER BY id;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE (id = {(i % 3) + 1} AND {i} = {i}) OR (id = 99 AND {i} <> {i});",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = {(i % 3) + 1} AND (username <> 'UNION' OR secret <> 'SELECT');",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id IN (1, 2, 3) GROUP BY id, username, secret HAVING COUNT(*) >= 1;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = {(i % 3) + 1} ORDER BY CASE WHEN username LIKE 'a%' THEN 0 ELSE 1 END, id;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = (SELECT MIN(id) FROM vuln_users) + {(i % 2)};",
    ]


def generate_basic() -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    malicious = collect_sql("basic_sql_injection", "malicious", _basic_malicious_families())
    legitimate = collect_sql("basic_sql_injection", "legitimate", _basic_legitimate_families())
    return malicious, legitimate


def _wrap_obfuscated(sql: str, variant: int, label: str) -> str:
    """Keep obfuscated samples structurally distinct from basic samples."""

    body = sql.rstrip()
    if body.endswith(";"):
        body = body[:-1]
    alias = f"obf_{label}_{variant}"
    return f"SELECT {alias}.id, {alias}.username, {alias}.secret FROM ({body}) AS {alias};"


def _obfuscated_malicious_families() -> list[Callable[[int], str]]:
    q = _basic_select()
    raw = [
        lambda i: f"{q} WHERE id/**/=/**/0/**/OR/**/{i}={i};",
        lambda i: f"{q} WHERE id = 0 /* left-{i} */ OR /* right-{i} */ ({i}={i});",
        lambda i: f"{q} WHERE id = 0\tOR\t({i} = {i});",
        lambda i: f"{q} WHERE id = 0\nOR\n({i} = {i});",
        lambda i: f"{q} WHERE (id = 0)/**/OR/**/({i}={i});",
        lambda i: f"{q} WHERE id = (0) /* p-{i} */ OR ({i}={i});",
        lambda i: f"{q} WHERE id = 0 + 0/**/oR/**/({i}={i});",
        lambda i: f"{q} WHERE id = 0 /* a-{i} */ AND ({i}={i}) /* b-{i} */ OR ({i}={i});",
        lambda i: f"{q} WHERE id = 0/**/OR/**/({i} BETWEEN {i} AND {i});",
        lambda i: f"{q} WHERE id = 0/**/OR/**/EXISTS(/* e-{i} */ SELECT 1 FROM vuln_users WHERE id = 1);",
        lambda i: f"{q} WHERE id = 0 /* c-{i} */ OR (SELECT COUNT(*) FROM vuln_users) > 0;",
        lambda i: f"{q} WHERE id = 0/**/OR/**/CASE WHEN {i}={i} THEN TRUE ELSE FALSE END;",
        lambda i: f"SELECT id, username, secret FROM public.vuln_users WHERE id/**/=/**/0/**/OR/**/{i}={i};",
        lambda i: f"SELECT u.id, u.username, u.secret FROM vuln_users AS u WHERE u.id = 0/**/OR/**/({i}={i});",
        lambda i: f"SELECT q.id, q.username, q.secret FROM (SELECT id, username, secret FROM vuln_users WHERE id = 0/**/OR/**/({i}={i})) AS q;",
        lambda i: f"WITH q AS (SELECT id, username, secret FROM vuln_users WHERE id = 0 /* cte-{i} */ OR ({i}={i})) SELECT id, username, secret FROM q;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = 0/**/UNION/**/SELECT {2000 + i}, 'obf_{i}', 'leak_{i}';",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = 0/**/UNION/**/ALL/**/SELECT {2000 + i}, 'obf_{i}', 'leak_{i}';",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = 0 /* u-{i} */ UnIoN AlL /* s-{i} */ SeLeCt {2000 + i}, 'obf_{i}', 'leak_{i}';",
        lambda i: f"SELECT q.id, q.username, q.secret FROM (SELECT id, username, secret FROM vuln_users WHERE id = 0 /* n-{i} */ UNION ALL SELECT {2000 + i}, 'obf_{i}', 'leak_{i}') AS q;",
        lambda i: f"SELECT id, username, secret FROM public.vuln_users WHERE id = 0\nUNION\nALL\nSELECT {2000 + i}, 'obf_{i}', 'leak_{i}';",
        lambda i: f"WITH q AS (SELECT id, username, secret FROM vuln_users WHERE id = 0/**/UNION ALL/**/SELECT {2000 + i}, 'obf_{i}', 'leak_{i}') SELECT id, username, secret FROM q;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE ({i}={i})/**/OR/**/id=0;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE ((id=0) /* nest-{i} */ OR ({i}={i}));",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = CAST(0 AS integer) /* cast-{i} */ OR ({i}={i});",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = 0/**/OR/**/(id IN (SELECT id FROM vuln_users));",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = 0 /* x-{i} */ OR (id = ANY(ARRAY[1,2,3]));",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = 0/**/OR/**/NOT ({i} <> {i});",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = 0 /* bool-{i} */ OR (({i}={i}) AND (id IS NOT NULL));",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = 0/**/OR/**/('x'='x');",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = 0 /* fn-{i} */ OR length('abc')=3;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = 0/**/OR/**/(0=0 AND {i}={i});",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = 0 /* union-or-{i} */ OR {i}={i} UNION ALL SELECT {2000 + i}, 'obf_{i}', 'leak_{i}';",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = 0/**/OR/**/EXISTS(SELECT 1 FROM vuln_users WHERE id=1) UNION SELECT {2000 + i}, 'obf_{i}', 'leak_{i}';",
    ]
    return [lambda i, f=f: _wrap_obfuscated(f(i), i, "m") for f in raw]


def _obfuscated_legitimate_families() -> list[Callable[[int], str]]:
    q = _basic_select()
    raw = [
        lambda i: f"SeLeCt id, username, secret FrOm vuln_users WhErE (id = {(i % 3) + 1} AnD {i}={i}) /* benign {i} */;",
        lambda i: f"{q}\nWHERE id = {(i % 3) + 1}\tAND username <> 'nobody-{i}' -- benign line {i}\n;",
        lambda i: f"{q} WHERE id IN ({(i % 3) + 1}, 99) AND ('UNION value {i}' LIKE '%UNION%' OR 'x'='y');",
        lambda i: f"SELECT v.id, v.username, v.secret FROM vuln_users v WHERE EXISTS (SELECT 1 FROM vuln_users q WHERE q.id=v.id AND q.id={(i % 3) + 1}) AND CASE WHEN {i}={i} THEN TRUE ELSE FALSE END;",
        lambda i: f"SELECT 1 AS id, 'OR literal {i}' AS username, 'SELECT literal' AS secret UNION SELECT 2, 'normal {i}', 'UNION is a value';",
        lambda i: f"SELECT 1 AS id, 'OR literal {i}' AS username, 'SELECT literal' AS secret UNION ALL SELECT 2, 'normal {i}', 'UNION is a value';",
        lambda i: f"{q} WHERE ((id={(i % 3) + 1}) /* p-{i} */ AND (id IS NOT NULL)) AND (id BETWEEN 1 AND 3);",
        lambda i: f"{q} WHERE id=0 OR {i}={i - 1} /* false benign branch {i} */;",
        lambda i: f"{q} WHERE id = 0 /* false-{i} */ OR ({i} <> {i});",
        lambda i: f"{q} WHERE id = {(i % 3) + 1} /* text UNION OR SELECT {i} */;",
        lambda i: f"SELECT id, username, secret FROM public.vuln_users WHERE id = {(i % 3) + 1} AND (username ILIKE '%a%' OR secret IS NOT NULL);",
        lambda i: f"WITH q AS (SELECT id, username, secret FROM vuln_users WHERE id = {(i % 3) + 1}) SELECT id, username, secret FROM q ORDER BY id;",
        lambda i: f"SELECT id, username, secret FROM (SELECT id, username, secret FROM vuln_users WHERE id BETWEEN 1 AND 3) AS q WHERE id={(i % 3) + 1};",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE (id = {(i % 3) + 1} AND ({i}={i})) OR (id=99 AND {i}<>{i});",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE CASE WHEN id={(i % 3) + 1} THEN TRUE ELSE FALSE END /* CASE {i} */;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = ANY(ARRAY[1,2,3]) AND id={(i % 3) + 1};",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id BETWEEN {(i % 3) + 1} AND {(i % 3) + 2} ORDER BY username;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE NOT (id <> {(i % 3) + 1}) AND secret IS NOT NULL;",
        lambda i: f"SELECT COUNT(*) AS id, 'normal aggregate {i}' AS username, MAX(secret) AS secret FROM vuln_users WHERE id IS NOT NULL;",
        lambda i: f"SELECT id, COUNT(*)::text AS username, MAX(secret) AS secret FROM vuln_users GROUP BY id ORDER BY id;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE username = 'contains -- comment {i}' OR username <> 'UNION';",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE username = 'literal /* comment */ {i}' AND id IS NOT NULL;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = {(i % 3) + 1} /* nested ( parentheses ) {i} */;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE ((id={(i % 3) + 1}) AND ((id IS NOT NULL) OR (id=99)));",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id = (SELECT MIN(id) FROM vuln_users) + {(i % 2)};",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id IN (SELECT id FROM vuln_users WHERE id={(i % 3) + 1}) ORDER BY id;",
        lambda i: f"SELECT v.id, v.username, v.secret FROM vuln_users v JOIN vuln_users w ON w.id=v.id WHERE v.id={(i % 3) + 1} AND w.secret IS NOT NULL;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id={(i % 3) + 1} GROUP BY id, username, secret HAVING COUNT(*)=1;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id={(i % 3) + 1} ORDER BY CASE WHEN username LIKE 'a%' THEN 0 ELSE 1 END;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE COALESCE(id, 0)={(i % 3) + 1} AND (1=1);",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE GREATEST(id, 1)={(i % 3) + 1} AND id IS NOT NULL;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id={(i % 3) + 1} AND (username || secret) IS NOT NULL;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id={(i % 3) + 1} AND substring(username,1,1) IS NOT NULL;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id={(i % 3) + 1} AND length(secret)>0;",
        lambda i: f"SELECT id, username, secret FROM vuln_users WHERE id={(i % 3) + 1} AND CAST(id AS text) <> '0';",
    ]
    return [lambda i, f=f: _wrap_obfuscated(f(i), i, "l") for f in raw]


def generate_obfuscated() -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    malicious = collect_sql("obfuscated_sql_injection", "malicious", _obfuscated_malicious_families())
    legitimate = collect_sql("obfuscated_sql_injection", "legitimate", _obfuscated_legitimate_families())
    return malicious, legitimate


CALL_EXPRESSIONS = [
    "{i}",
    "({i})",
    "{i} + 0",
    "0 + {i}",
    "CAST({i} AS integer)",
    "({i})::integer",
    "COALESCE(NULL, {i})",
    "COALESCE({i}, 1)",
    "GREATEST({i}, 1)",
    "LEAST({i}, 2147483647)",
    "ABS(-{i})",
    "(({i} + 1) - 1)",
    "({i} * 1)",
    "({i} / 1)",
    "(({i} % 10) + 1)",
    "CASE WHEN {i} > 0 THEN {i} ELSE 1 END",
    "NULLIF({i}, 0)",
    "(SELECT {i})",
    "(SELECT CAST({i} AS integer))",
    "CAST(({i} + 0) AS integer)",
    "GREATEST(1, ({i}::integer))",
    "LEAST(2147483647, ({i}::integer))",
    "COALESCE((SELECT {i}), 1)",
    "CASE WHEN ({i} = {i}) THEN {i} ELSE 1 END",
    "(({i}::integer) + (0::integer))",
    "ABS((-{i})::integer)",
]


CALL_STYLES = [
    "CALL public.{proc}({expr});",
    "CALL PUBLIC.{proc}({expr});",
    "CALL public.\"{proc}\"({expr});",
    "CALL \"public\".{proc}({expr});",
    "CALL \"public\".\"{proc}\"({expr});",
    "CALL public./* schema-gap-{tag} */ {proc}({expr});",
    "CALL public./* schema-gap-{tag} */{proc}({expr});",
    "CALL /* leading-{tag} */ public.{proc}({expr});",
    "/* prefix-{tag} */ CALL public.{proc}({expr});",
    "call public.{proc}(({expr}));",
    "CALL public.{proc}( {expr} );",
    "CALL\npublic.{proc}(\n {expr}\n);",
    "CALL\tpublic.{proc}(\t{expr}\t);",
    "CALL public.{proc}(CAST(({expr}) AS integer));",
    "CALL public.{proc}(COALESCE(({expr}), 1));",
    "CALL public.{proc}(GREATEST(({expr}), 1));",
    "CALL public.{proc}({expr} /* argument-{tag} */);",
    "CALL public./* name-gap-{tag} */{proc}(\n{expr}\n);",
    "CALL PUBLIC./* name-gap-{tag} */\"{proc}\"({expr});",
    "CALL \"public\"./* name-gap-{tag} */{proc}(({expr}));",
]


def generate_calls() -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    malicious: list[dict[str, str]] = []
    legitimate: list[dict[str, str]] = []
    seen_malicious: set[str] = set()
    seen_legitimate: set[str] = set()
    # Interleave formatting styles and expression families so the first 317
    # samples already cover comments, quoting, case, whitespace and nesting.
    for expression_index, expression_template in enumerate(CALL_EXPRESSIONS, 1):
        for style_index, style in enumerate(CALL_STYLES, 1):
            for value in range(2, 40):
                tag = f"s{style_index}e{expression_index}v{value}"
                expression = expression_template.format(i=value)
                for proc, label, rows, seen in (
                    ("sensitive_proc", "malicious", malicious, seen_malicious),
                    ("safe_proc", "legitimate", legitimate, seen_legitimate),
                ):
                    sql = style.format(proc=proc, expr=expression, tag=tag)
                    key = canonical_sql(sql)
                    if key in seen or key in SMOKE_CANONICAL or key in OLD_CANONICAL:
                        continue
                    seen.add(key)
                    rows.append(sample(f"stored_procedure_call_{label}_{len(rows) + 1:03d}", "stored_procedure_call", label, sql, "/pg/call"))
                if len(malicious) >= TARGET_PER_LABEL and len(legitimate) >= TARGET_PER_LABEL:
                    break
            if len(malicious) >= TARGET_PER_LABEL and len(legitimate) >= TARGET_PER_LABEL:
                break
        if len(malicious) >= TARGET_PER_LABEL and len(legitimate) >= TARGET_PER_LABEL:
            break
    if len(malicious) != TARGET_PER_LABEL or len(legitimate) != TARGET_PER_LABEL:
        raise AssertionError(f"stored_procedure_call generated {len(malicious)} malicious and {len(legitimate)} legitimate")
    return malicious, legitimate


def build_dataset() -> list[dict[str, str]]:
    samples: list[dict[str, str]] = []
    global_canonical: set[str] = set()
    for generator in (generate_basic, generate_obfuscated, generate_calls):
        malicious, legitimate = generator()
        if len(malicious) != TARGET_PER_LABEL or len(legitimate) != TARGET_PER_LABEL:
            raise AssertionError("each scene must have exactly 317 malicious and 317 legitimate samples")
        for row in [*malicious, *legitimate]:
            key = canonical_sql(row["sql"])
            if key in global_canonical or key in OLD_CANONICAL:
                raise AssertionError(f"canonical SQL overlap: {row['sample_id']}")
            global_canonical.add(key)
            samples.append(row)
    if len(samples) != 6 * TARGET_PER_LABEL:
        raise AssertionError(f"expected 1902 unique samples, got {len(samples)}")
    if len(global_canonical) != len(samples):
        raise AssertionError("canonical SQL is not globally unique")
    if global_canonical & SMOKE_CANONICAL:
        raise AssertionError("formal dataset overlaps smoke SQL")
    return samples


def main() -> int:
    # Keep the original runner's rule SQL, smoke validation, request execution,
    # log collection and aggregation unchanged; only replace its corpus/output.
    base.RESULTS = RESULTS_DIR
    base.REPEATS = 5
    base.PROJECT = os.environ.get("PROXYSQL_COMPOSE_PROJECT", "proxysql-firewall-local")
    base.generate_basic = generate_basic
    base.generate_obfuscated = generate_obfuscated
    base.generate_calls = generate_calls
    base.build_dataset = build_dataset
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
