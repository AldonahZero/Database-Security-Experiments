#!/usr/bin/env python3
"""Parse ModSecurity & Suricata logs to compute TPR/FPR for defined SQLi scenarios.

Inputs (default paths):
  ModSecurity audit log: results/modsecurity/audit.log (JSON lines or multiline segments)
  Suricata eve log: results/suricata/eve.json (JSON lines)

Detection logic:
  We rely on custom header X-Attack-ID injected by raw_http_attack.py
  When header not present we treat the request as benign baseline traffic (for FPR denominator).

Output:
  Prints per tool & scenario metrics and writes CSV rows to results/attack_detection_metrics.csv
"""
from __future__ import annotations
import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional

RESULTS_DIR = Path("results")
MODSEC_AUDIT = RESULTS_DIR / "modsecurity" / "audit.log"
SURICATA_EVE = RESULTS_DIR / "suricata" / "eve.json"
OUT_CSV = RESULTS_DIR / "attack_detection_metrics.csv"

SCENARIOS = {
    "BASIC_SQLI": "基础SQL注入",
    "OBFUSCATED_SQLI": "混淆SQL注入",
    "PROC_SQLI": "存储过程调用",
}

TOOLS = ["ModSecurity", "Suricata"]

HEADER = [
    "tool",
    "scenario_key",
    "scenario_name",
    "true_positives",
    "false_negatives",
    "tpr_percent",
    "false_positives",
    "true_negatives",
    "fpr_percent",
]


def load_suricata_events(path: Path) -> List[dict]:
    events: List[dict] = []
    if not path.exists():
        return events
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            events.append(obj)
    return events


MODSEC_AUDIT_ENTRY = re.compile(r"^--[0-9a-fA-F]{8}-[A-Z]--$")


def load_modsec_transactions(path: Path) -> List[str]:
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8", errors="ignore")
    # Simple split by transaction marker
    parts = [p for p in raw.split("--") if p.strip()]
    return parts


def extract_attack_id_from_modsec(entry: str) -> Optional[str]:
    # Search for header
    m = re.search(r"X-Attack-ID:\s*([A-Za-z0-9_\-]+)", entry, re.IGNORECASE)
    if m:
        return m.group(1).strip()
    return None


def modsec_is_sqli_alert(entry: str) -> bool:
    # Look for typical CRS tags or msg containing SQL injection
    if re.search(r"SQL Injection", entry, re.IGNORECASE):
        return True
    if re.search(r"ARGS:id", entry) and re.search(
        r"UNION|SELECT|pg_sleep", entry, re.IGNORECASE
    ):
        return True
    return False


def extract_attack_id_from_suricata(event: dict) -> Optional[str]:
    http = event.get("http", {})
    # Suricata may not log custom headers by default; if absent we fall back to heuristic from URI
    hx = http.get("http_headers") or http.get("headers")
    if isinstance(hx, str) and "X-Attack-ID" in hx:
        m = re.search(r"X-Attack-ID:\s*([A-Za-z0-9_\-]+)", hx, re.IGNORECASE)
        if m:
            return m.group(1).strip()
    uri = http.get("url") or http.get("uri")
    if isinstance(uri, str):
        if "UNION" in uri.upper():
            return "BASIC_SQLI"
        if "/*" in uri and "SELECT" in uri.upper():
            return "OBFUSCATED_SQLI"
        if "pg_sleep" in uri.lower():
            return "PROC_SQLI"
    return None


def suricata_is_sqli_alert(event: dict) -> bool:
    alert = event.get("alert")
    if not alert:
        return False
    sig = alert.get("signature", "")
    if any(k in sig.lower() for k in ["sqli", "sql", "select", "union", "pg_sleep"]):
        return True
    return False


def compute_metrics(
    detections: Dict[str, Dict[str, int]],
    attack_totals: Dict[str, Dict[str, int]],
    benign_stats: Dict[str, Dict[str, int]],
) -> List[Dict[str, object]]:
    rows: List[Dict[str, object]] = []
    for tool in TOOLS:
        for key, cname in SCENARIOS.items():
            tp = detections.get(tool, {}).get(key, 0)
            total_attacks = attack_totals.get(tool, {}).get(key, 0)
            fn = max(total_attacks - tp, 0)
            tool_benign = benign_stats.get(tool, {"total": 0, "alerts": 0})
            fp = tool_benign.get("alerts", 0)
            tn = max(tool_benign.get("total", 0) - fp, 0)
            tpr = (tp / total_attacks * 100) if total_attacks else 0.0
            fpr = (fp / (fp + tn) * 100) if (fp + tn) else 0.0
            rows.append(
                {
                    "tool": tool,
                    "scenario_key": key,
                    "scenario_name": cname,
                    "true_positives": tp,
                    "false_negatives": fn,
                    "tpr_percent": round(tpr, 2),
                    "false_positives": fp,
                    "true_negatives": tn,
                    "fpr_percent": round(fpr, 3),
                }
            )
    return rows


def write_csv(rows: List[Dict[str, object]]) -> None:
    if not rows:
        return
    OUT_CSV.parent.mkdir(exist_ok=True)
    if not OUT_CSV.exists():
        OUT_CSV.write_text(",".join(HEADER) + "\n", encoding="utf-8")
    with OUT_CSV.open("a", encoding="utf-8") as handle:
        for r in rows:
            handle.write(",".join(str(r[h]) for h in HEADER) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Compute detection metrics from logs")
    parser.add_argument("--modsec", default=str(MODSEC_AUDIT))
    parser.add_argument("--suricata", default=str(SURICATA_EVE))
    args = parser.parse_args()

    modsec_entries = load_modsec_transactions(Path(args.modsec))
    suricata_events = load_suricata_events(Path(args.suricata))

    detections: Dict[str, Dict[str, int]] = {}
    attack_totals: Dict[str, Dict[str, int]] = {}
    benign_stats: Dict[str, Dict[str, int]] = {}

    # Process ModSecurity
    for entry in modsec_entries:
        attack_id = extract_attack_id_from_modsec(entry)
        if attack_id and attack_id in SCENARIOS:
            attack_totals.setdefault("ModSecurity", {}).setdefault(attack_id, 0)
            attack_totals["ModSecurity"][attack_id] += 1
            if modsec_is_sqli_alert(entry):
                detections.setdefault("ModSecurity", {}).setdefault(attack_id, 0)
                detections["ModSecurity"][attack_id] += 1
        else:
            stats = benign_stats.setdefault("ModSecurity", {"total": 0, "alerts": 0})
            stats["total"] += 1
            if modsec_is_sqli_alert(entry):
                stats["alerts"] += 1

    # Process Suricata
    for ev in suricata_events:
        attack_id = extract_attack_id_from_suricata(ev)
        if attack_id and attack_id in SCENARIOS:
            attack_totals.setdefault("Suricata", {}).setdefault(attack_id, 0)
            attack_totals["Suricata"][attack_id] += 1
            if suricata_is_sqli_alert(ev):
                detections.setdefault("Suricata", {}).setdefault(attack_id, 0)
                detections["Suricata"][attack_id] += 1
        else:
            stats = benign_stats.setdefault("Suricata", {"total": 0, "alerts": 0})
            stats["total"] += 1
            if suricata_is_sqli_alert(ev):
                stats["alerts"] += 1

    rows = compute_metrics(detections, attack_totals, benign_stats)
    write_csv(rows)
    print("工具,场景,TP,FP,TPR%,FPR%")
    for r in rows:
        print(
            f"{r['tool']},{r['scenario_name']},{r['true_positives']},{r['false_positives']},{r['tpr_percent']},{r['fpr_percent']}"
        )


if __name__ == "__main__":
    main()
