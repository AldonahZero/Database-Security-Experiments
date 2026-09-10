"""Small, deliberately vulnerable PostgreSQL API used only by the ProxySQL experiment."""

import os
import time

import psycopg2
from flask import Flask, jsonify, request


app = Flask(__name__)


def dsn():
    return {
        "host": os.environ.get("PGHOST", "postgres-db"),
        "port": int(os.environ.get("PGPORT", "5432")),
        "dbname": os.environ.get("PGDATABASE", "juiceshop_db"),
        "user": os.environ.get("PGUSER", "youruser"),
        "password": os.environ.get("PGPASSWORD", "password123"),
        "connect_timeout": 5,
    }


def connect():
    return psycopg2.connect(**dsn())


def rows_as_dict(cursor):
    if cursor.description is None:
        return []
    columns = [description[0] for description in cursor.description]
    return [dict(zip(columns, row)) for row in cursor.fetchall()]


def state_snapshot():
    """Read only the experiment markers using a fresh connection."""
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(
                    "SELECT value FROM call_marker WHERE id=1"
                )
                call_value = cursor.fetchone()[0]
                cursor.execute(
                    "SELECT value FROM sensitive_marker WHERE id=1"
                )
                sensitive_value = cursor.fetchone()[0]
        return {"call_marker": call_value, "sensitive_marker": sensitive_value}
    except Exception as exc:  # pragma: no cover - only used for diagnostics
        return {"state_error": str(exc)}


def error_type(exc):
    text = str(exc).lower()
    if "proxySQL formal".lower() in text:
        return "firewall_deny"
    if isinstance(exc, psycopg2.OperationalError):
        return "connection_error"
    if "syntax error" in text:
        return "sql_syntax_error"
    if "protocol" in text:
        return "protocol_error"
    return "backend_error"


@app.get("/health")
def health():
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()
        return jsonify({"status": "ok", "dsn_host": dsn()["host"]})
    except Exception as exc:
        return jsonify({"status": "error", "error": str(exc)}), 503


@app.get("/pg/reset")
def reset_markers():
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute("UPDATE call_marker SET value=0 WHERE id=1")
                cursor.execute("UPDATE sensitive_marker SET value=0 WHERE id=1")
        return jsonify({"ok": True, "state": state_snapshot()})
    except Exception as exc:
        return jsonify({"ok": False, "error_type": error_type(exc), "error": str(exc)}), 500


@app.get("/pg/state")
def state():
    return jsonify(state_snapshot())


@app.get("/pg/query")
def pg_query():
    """Execute a supplied SELECT used to exercise the vulnerable SQL path."""
    query = request.args.get("sql", "")
    if not query:
        return jsonify({"ok": False, "error": "missing sql"}), 400
    started = time.perf_counter()
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query)
                result = rows_as_dict(cursor)
                row_count = len(result) if cursor.description else cursor.rowcount
        return jsonify(
            {
                "ok": True,
                "query": query,
                "rows": result,
                "row_count": row_count,
                "elapsed_ms": (time.perf_counter() - started) * 1000,
            }
        )
    except Exception as exc:
        return (
            jsonify(
                {
                    "ok": False,
                    "query": query,
                    "error_type": error_type(exc),
                    "error": str(exc),
                    "state": state_snapshot(),
                    "elapsed_ms": (time.perf_counter() - started) * 1000,
                }
            ),
            500,
        )


@app.get("/pg/call")
def pg_call():
    """Execute a PostgreSQL CALL and return both marker values."""
    query = request.args.get("sql", "")
    if not query:
        return jsonify({"ok": False, "error": "missing sql"}), 400
    started = time.perf_counter()
    try:
        with connect() as connection:
            with connection.cursor() as cursor:
                cursor.execute(query)
        return jsonify(
            {
                "ok": True,
                "query": query,
                "state": state_snapshot(),
                "elapsed_ms": (time.perf_counter() - started) * 1000,
            }
        )
    except Exception as exc:
        return (
            jsonify(
                {
                    "ok": False,
                    "query": query,
                    "error_type": error_type(exc),
                    "error": str(exc),
                    "state": state_snapshot(),
                    "elapsed_ms": (time.perf_counter() - started) * 1000,
                }
            ),
            500,
        )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081)
