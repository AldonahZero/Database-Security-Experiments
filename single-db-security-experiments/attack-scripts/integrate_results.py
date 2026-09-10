#!/usr/bin/env python3
"""Integrate performance attack metrics with detection metrics into experiment_summary.md."""
from __future__ import annotations
import csv
from pathlib import Path
from datetime import datetime

RESULTS = Path("results")
ATTACK_METRICS = RESULTS / "attack_metrics.csv"
DETECTION_METRICS = RESULTS / "attack_detection_metrics.csv"
SUMMARY = RESULTS / "experiment_summary.md"


def read_csv(path: Path):
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def main() -> None:
    attack_rows = read_csv(ATTACK_METRICS)
    detect_rows = read_csv(DETECTION_METRICS)

    lines = []
    lines.append(f"# 实验结果汇总\n")
    lines.append(f"_生成时间: {datetime.utcnow().isoformat()} UTC_\n")

    if attack_rows:
        lines.append("## 攻击执行性能 (节选)\n")
        lines.append(
            "| 工具 | 目标 | 攻击类型 | 成功率% | 平均延迟ms | 峰值CPU% | 峰值内存% | 备注 |\n"
        )
        lines.append(
            "| ---- | ---- | -------- | ------ | ---------- | -------- | -------- | ---- |\n"
        )
        for r in attack_rows[-10:]:  # 最近十条
            lines.append(
                f"| {r.get('tool')} | {r.get('target_database')} | {r.get('attack_type')} | {r.get('success_rate')} | {r.get('avg_latency_ms') or '-'} | {r.get('peak_cpu_percent') or '-'} | {r.get('peak_mem_percent') or '-'} | {r.get('notes') or ''} |\n"
            )
        lines.append("\n")
    else:
        lines.append("(尚无攻击性能数据)\n\n")

    if detect_rows:
        lines.append("## 检测效果 (SQL 注入)\n")
        lines.append("| 工具 | 场景 | TP | FN | TPR% | FP | TN | FPR% |\n")
        lines.append("| ---- | ---- | -- | -- | ---- | -- | -- | ---- |\n")
        for r in detect_rows:
            lines.append(
                f"| {r.get('tool')} | {r.get('scenario_name')} | {r.get('true_positives')} | {r.get('false_negatives')} | {r.get('tpr_percent')} | {r.get('false_positives')} | {r.get('true_negatives')} | {r.get('fpr_percent')} |\n"
            )
        lines.append("\n")
    else:
        lines.append("(尚无检测度量数据)\n\n")

    lines.append("## 说明\n")
    lines.append("- 基础SQL注入: 直接使用 UNION SELECT 提取信息。\n")
    lines.append("- 混淆SQL注入: 在关键字之间使用注释绕过简单匹配。\n")
    lines.append("- 存储过程调用: 利用 pg_sleep() 进行时间延迟侧信道。\n")
    lines.append("- TPR=True Positive Rate, FPR=False Positive Rate。\n")

    SUMMARY.write_text("".join(lines), encoding="utf-8")
    print(f"写入 {SUMMARY}")


if __name__ == "__main__":
    main()
