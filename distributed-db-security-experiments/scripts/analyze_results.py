#!/usr/bin/env python3
"""Analyze distributed database security experiment results."""

from __future__ import annotations

import argparse
import math
from pathlib import Path
from typing import Dict, List, Optional

from matplotlib import font_manager
import matplotlib.pyplot as plt
import pandas as pd


DEFENSE_LABELS = {
    "deterministic": "确定性路由",
    "obfuscated": "混淆路由模拟",
    "obfuscated_control": "混淆路由+流量控制",
    "baseline": "无防御",
    "shard_limit": "分片级限流",
    "hot_key_limit": "热点键限流",
    "queue_isolation": "队列隔离/读分流",
}

SCENARIO_LABELS = {
    "uniform": "均匀流量",
    "hot70": "70% 目标分片流量",
    "hot90": "90% 目标分片流量",
}

SHARD_LABELS = {
    "shard-0": "分片0",
    "shard-1": "分片1",
    "shard-2": "分片2",
}

COMPONENT_LABELS = {
    "coordinator": "协调节点",
    "worker": "工作节点",
}

NODE_LABELS = {
    "exp1_citus_coordinator": "Citus协调节点",
    "exp1_citus_worker_0": "Citus工作节点0",
    "exp1_citus_worker_1": "Citus工作节点1",
    "exp1_citus_worker_2": "Citus工作节点2",
    "citus-coordinator": "Citus协调节点",
    "citus-worker-0": "Citus工作节点0",
    "citus-worker-1": "Citus工作节点1",
    "citus-worker-2": "Citus工作节点2",
    "exp1_tidb_tikv0": "TiKV节点0",
    "exp1_tidb_tikv1": "TiKV节点1",
    "exp1_tidb_tikv2": "TiKV节点2",
}

CITUS_DEFENSE_LABELS = {
    "citus_native": "Citus 原生分布式执行",
}

TIDB_DEFENSE_LABELS = {
    "tidb_native": "TiDB 原生调度",
}

EXP2_SCENARIO_LABELS = {
    "baseline": "正常基线",
    "leader_cpu_stress": "Leader CPU压力",
    "leader_network_perturbation": "Leader节点暂停",
    "leader_cpu_stress_limited": "Leader CPU压力+应用侧限流",
}

EXP2_PHASE_LABELS = {
    "normal": "正常期",
    "perturbation": "扰动期",
    "recovery": "恢复期",
}

EXP2_MITIGATION_LABELS = {
    "tidb_native": "TiDB原生调度",
    "client_limited": "应用侧限流",
}

EXP2_PERTURBATION_LABELS = {
    "none": "无扰动",
    "cpu": "CPU压力",
    "network": "节点暂停",
    "container_pause": "节点暂停",
}

EXP2_METHOD_LABELS = {
    "": "-",
    "none": "-",
    "shell_busy_loop": "容器内CPU忙循环",
    "docker_pause": "TiKV容器暂停",
    "docker_pause_fallback": "TiKV容器暂停",
}

EXP3_DEFENSE_LABELS = {
    "baseline": "无防御",
    "global_sequence": "全局序列号",
    "occ": "版本检查/OCC",
    "conflict_key_queue": "冲突键队列化",
    "two_phase_commit": "两阶段提交模拟",
}

EXP3_DEFENSE_ORDER = ["baseline", "global_sequence", "occ", "conflict_key_queue", "two_phase_commit"]
RATE_LIMIT_ERRORS = {"traffic_control", "shard_limit", "hot_key_limit", "hot_queue_full"}


def main() -> int:
    args = parse_args()
    configure_chinese_font()
    root = Path(__file__).resolve().parents[1]
    raw_path = root / args.requests_csv
    table_dir = root / "results" / "tables"
    figure_dir = root / "results" / "figures"
    paper_dir = root / "paper"
    table_dir.mkdir(parents=True, exist_ok=True)
    figure_dir.mkdir(parents=True, exist_ok=True)
    paper_dir.mkdir(parents=True, exist_ok=True)

    requests = pd.read_csv(raw_path)
    summary = summarize_requests(requests)
    summary_path = table_dir / "exp1_single_shard_flood_summary.csv"
    write_chinese_csv(summary, summary_path, "single")

    citus_summary = pd.DataFrame()
    citus_resource_summary = pd.DataFrame()
    citus_placement_summary = pd.DataFrame()
    citus_resource_raw = pd.DataFrame()
    citus_raw_path = root / args.citus_requests_csv
    if citus_raw_path.exists():
        citus_requests = pd.read_csv(citus_raw_path)
        citus_summary = summarize_citus_requests(citus_requests)
        write_chinese_csv(citus_summary, table_dir / "exp1_citus_hotspot_summary.csv", "citus_hotspot")
        citus_resource_path = root / args.citus_resource_csv
        if citus_resource_path.exists():
            citus_resource_raw = pd.read_csv(citus_resource_path)
            citus_resource_summary = summarize_citus_resources(citus_resource_raw)
            write_chinese_csv(citus_resource_summary, table_dir / "exp1_citus_resource_summary.csv", "citus_resource")
            render_citus_worker_figure(citus_resource_raw, figure_dir / "exp1_citus_worker_load.png")
        citus_placement_path = root / args.citus_placement_csv
        if citus_placement_path.exists():
            citus_placement_summary = summarize_citus_placements(pd.read_csv(citus_placement_path))
            write_chinese_csv(citus_placement_summary, table_dir / "exp1_citus_shard_placement_summary.csv", "citus_placement")

    tidb_summary = pd.DataFrame()
    tidb_resource_summary = pd.DataFrame()
    tidb_region_summary = pd.DataFrame()
    tidb_resource_raw = pd.DataFrame()
    tidb_raw_path = root / args.tidb_requests_csv
    if tidb_raw_path.exists():
        tidb_requests = pd.read_csv(tidb_raw_path)
        tidb_summary = summarize_tidb_requests(tidb_requests)
        write_chinese_csv(tidb_summary, table_dir / "exp1_tidb_hotspot_summary.csv", "tidb_hotspot")
        tidb_resource_path = root / args.tidb_resource_csv
        if tidb_resource_path.exists():
            tidb_resource_raw = pd.read_csv(tidb_resource_path)
            tidb_resource_summary = summarize_tidb_resources(tidb_resource_raw)
            write_chinese_csv(tidb_resource_summary, table_dir / "exp1_tidb_tikv_resource_summary.csv", "tidb_resource")
            render_tidb_tikv_figure(tidb_resource_raw, figure_dir / "exp1_tidb_tikv_load.png")
        tidb_region_path = root / args.tidb_region_csv
        if tidb_region_path.exists():
            tidb_region_summary = summarize_tidb_regions(pd.read_csv(tidb_region_path))
            write_chinese_csv(tidb_region_summary, table_dir / "exp1_tidb_region_leader_summary.csv", "tidb_region")

    exp2_summary = pd.DataFrame()
    exp2_phase_summary = pd.DataFrame()
    exp2_resource_summary = pd.DataFrame()
    exp2_leader_summary = pd.DataFrame()
    exp2_events = pd.DataFrame()
    exp2_raw_path = root / args.exp2_requests_csv
    exp2_leader_path = root / args.exp2_leader_csv
    exp2_events_path = root / args.exp2_events_csv
    if exp2_events_path.exists():
        exp2_events = pd.read_csv(exp2_events_path)
    if exp2_raw_path.exists():
        exp2_requests = pd.read_csv(exp2_raw_path, low_memory=False)
        exp2_leaders = pd.read_csv(exp2_leader_path) if exp2_leader_path.exists() else pd.DataFrame()
        exp2_summary = summarize_exp2_scenarios(exp2_requests, exp2_leaders, exp2_events)
        exp2_phase_summary = summarize_exp2_phases(exp2_requests)
        write_chinese_csv(exp2_summary, table_dir / "exp2_tidb_leader_summary.csv", "exp2_summary")
        write_chinese_csv(exp2_phase_summary, table_dir / "exp2_tidb_leader_phase_summary.csv", "exp2_phase")
        table_b = render_table_b(exp2_summary)
        table_b_path = table_dir / "table_B_tidb_leader_stress.md"
        table_b_path.write_text(table_b, encoding="utf-8")
        render_exp2_recovery_figure(exp2_requests, figure_dir / "exp2_tidb_p99_recovery_curve.png")
        exp2_resources = pd.DataFrame()
        exp2_resource_path = root / args.exp2_resource_csv
        if exp2_resource_path.exists():
            exp2_resources = pd.read_csv(exp2_resource_path)
            exp2_resource_summary = summarize_exp2_resources(exp2_resources)
            write_chinese_csv(exp2_resource_summary, table_dir / "exp2_tidb_tikv_resource_summary.csv", "exp2_resource")
        if not exp2_leaders.empty:
            exp2_leader_summary = summarize_exp2_leaders(exp2_leaders)
            write_chinese_csv(exp2_leader_summary, table_dir / "exp2_tidb_leader_transfer_summary.csv", "exp2_leader")
        render_exp2_multiplot(exp2_requests, exp2_resources, figure_dir / "exp2_tidb_leader_multiplot.png")

    exp3_summary = pd.DataFrame()
    exp3_txn_path = root / args.exp3_transactions_csv
    exp3_pair_path = root / args.exp3_pairs_csv
    if exp3_txn_path.exists() and exp3_pair_path.exists():
        exp3_transactions = pd.read_csv(exp3_txn_path)
        exp3_pairs = pd.read_csv(exp3_pair_path)
        exp3_summary = summarize_exp3(exp3_transactions, exp3_pairs)
        write_chinese_csv(exp3_summary, table_dir / "exp3_cross_shard_frontrun_summary.csv", "exp3_summary")
        table_c_path = table_dir / "table_C_cross_shard_frontrun.md"
        table_c_path.write_text(render_table_c(exp3_summary), encoding="utf-8")
        render_exp3_figure(exp3_summary, figure_dir / "exp3_frontrun_defense_overhead.png")
        render_exp3_figure(exp3_summary, figure_dir / "exp3_frontrun_multiplot.png")

    table_md = render_table_a(
        summary,
        citus_summary,
        tidb_summary,
    )
    table_path = table_dir / "table_A_single_shard_flood.md"
    table_path.write_text(table_md, encoding="utf-8")

    supplement_md = render_supplemental_table_a(
        summary,
        citus_summary,
        citus_resource_summary,
        citus_placement_summary,
        tidb_summary,
        tidb_resource_summary,
        tidb_region_summary,
    )
    supplement_path = table_dir / "table_A_single_shard_flood_full.md"
    supplement_path.write_text(supplement_md, encoding="utf-8")

    figure_path = figure_dir / "exp1_shard_load_changes.png"
    render_shard_load_figure(requests, figure_path)
    exp1_multiplot_path = figure_dir / "exp1_distribution_multiplot.png"
    render_exp1_multiplot(
        requests,
        summary,
        citus_summary,
        citus_resource_raw,
        tidb_summary,
        tidb_resource_raw,
        exp1_multiplot_path,
    )

    paper_path = paper_dir / "section_4_append_text.md"
    paper_path.write_text(
        render_paper_text(
            summary,
            citus_summary,
            citus_resource_summary,
            citus_placement_summary,
            tidb_summary,
            tidb_resource_summary,
            tidb_region_summary,
            exp2_summary,
            exp2_resource_summary,
            exp3_summary,
        ),
        encoding="utf-8",
    )

    reviewer_path = paper_dir / "reviewer_response.md"
    reviewer_path.write_text(
        render_reviewer_response(not exp2_summary.empty, exp3_is_complete(exp3_summary)),
        encoding="utf-8",
    )

    print(f"[analyze] wrote {summary_path}")
    print(f"[analyze] wrote {table_path}")
    print(f"[analyze] wrote {supplement_path}")
    print(f"[analyze] wrote {figure_path}")
    print(f"[analyze] wrote {exp1_multiplot_path}")
    print(f"[analyze] wrote {paper_path}")
    if not exp2_summary.empty:
        print(f"[analyze] wrote {table_dir / 'table_B_tidb_leader_stress.md'}")
        print(f"[analyze] wrote {figure_dir / 'exp2_tidb_p99_recovery_curve.png'}")
        print(f"[analyze] wrote {figure_dir / 'exp2_tidb_leader_multiplot.png'}")
    if not exp3_summary.empty:
        print(f"[analyze] wrote {table_dir / 'table_C_cross_shard_frontrun.md'}")
        print(f"[analyze] wrote {figure_dir / 'exp3_frontrun_defense_overhead.png'}")
        print(f"[analyze] wrote {figure_dir / 'exp3_frontrun_multiplot.png'}")
    print(f"[analyze] wrote {reviewer_path}")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--requests-csv",
        default="results/raw/exp1_single_shard_flood_requests.csv",
        help="request-level raw CSV generated by exp1_single_shard_flood.py",
    )
    parser.add_argument("--citus-requests-csv", default="results/raw/exp1_citus_hotspot_requests.csv")
    parser.add_argument("--citus-resource-csv", default="results/raw/exp1_citus_resource_samples.csv")
    parser.add_argument("--citus-placement-csv", default="results/raw/exp1_citus_shard_placements.csv")
    parser.add_argument("--tidb-requests-csv", default="results/raw/exp1_tidb_hotspot_requests.csv")
    parser.add_argument("--tidb-resource-csv", default="results/raw/exp1_tidb_tikv_resource_samples.csv")
    parser.add_argument("--tidb-region-csv", default="results/raw/exp1_tidb_region_observations.csv")
    parser.add_argument("--exp2-requests-csv", default="results/raw/exp2_tidb_leader_requests.csv")
    parser.add_argument("--exp2-resource-csv", default="results/raw/exp2_tidb_tikv_resource_samples.csv")
    parser.add_argument("--exp2-leader-csv", default="results/raw/exp2_tidb_leader_observations.csv")
    parser.add_argument("--exp2-events-csv", default="results/raw/exp2_tidb_perturbation_events.csv")
    parser.add_argument("--exp3-transactions-csv", default="results/raw/exp3_cross_shard_transactions.csv")
    parser.add_argument("--exp3-pairs-csv", default="results/raw/exp3_cross_shard_pairs.csv")
    return parser.parse_args()


def configure_chinese_font() -> None:
    font_files = [
        Path("/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc"),
    ]
    for font_file in font_files:
        if font_file.exists():
            font_manager.fontManager.addfont(str(font_file))
            font_name = font_manager.FontProperties(fname=str(font_file)).get_name()
            plt.rcParams["font.family"] = "sans-serif"
            plt.rcParams["font.sans-serif"] = [font_name, "DejaVu Sans"]
            plt.rcParams["axes.unicode_minus"] = False
            return

    candidates = [
        "WenQuanYi Zen Hei",
        "Noto Sans CJK SC",
        "Source Han Sans SC",
        "SimHei",
        "Microsoft YaHei",
    ]
    available = {font.name for font in font_manager.fontManager.ttflist}
    for name in candidates:
        if name in available:
            plt.rcParams["font.sans-serif"] = [name, "DejaVu Sans"]
            break
    plt.rcParams["axes.unicode_minus"] = False


def write_chinese_csv(df: pd.DataFrame, output: Path, kind: str) -> None:
    display = df.copy()
    if display.empty:
        display.to_csv(output, index=False)
        return
    for column in display.select_dtypes(include=["float"]).columns:
        display[column] = display[column].round(2)

    if "scenario" in display.columns:
        display["scenario"] = display["scenario"].map(scenario_label).fillna(display["scenario"])
    if "defense" in display.columns:
        display["defense"] = display["defense"].map(defense_label).fillna(display["defense"])
    if "component" in display.columns:
        display["component"] = display["component"].map(COMPONENT_LABELS).fillna(display["component"])
    if "container" in display.columns:
        display["container"] = display["container"].map(node_label).fillna(display["container"])
    if "target_container" in display.columns:
        display["target_container"] = display["target_container"].map(node_label).fillna(display["target_container"])
    if "hot_leader_container" in display.columns:
        display["hot_leader_container"] = display["hot_leader_container"].map(node_list_label).fillna(display["hot_leader_container"])
    if "hotspot_worker" in display.columns:
        display["hotspot_worker"] = display["hotspot_worker"].map(node_list_label).fillna(display["hotspot_worker"])
    if "phase" in display.columns:
        display["phase"] = display["phase"].map(exp2_phase_label).fillna(display["phase"])
    if "mitigation" in display.columns:
        display["mitigation"] = display["mitigation"].map(exp2_mitigation_label).fillna(display["mitigation"])
    if "perturbation" in display.columns:
        display["perturbation"] = display["perturbation"].map(exp2_perturbation_label).fillna(display["perturbation"])
    if "perturbation_method" in display.columns:
        display["perturbation_method"] = display["perturbation_method"].map(exp2_method_label).fillna(display["perturbation_method"])

    column_maps = {
        "single": {
            "run_count": "重复次数",
            "scenario": "场景",
            "defense": "路由/防御策略",
            "requests": "请求数",
            "success_rate_pct": "成功率(%)",
            "failure_rate_pct": "失败率(%)",
            "rate_limited_pct": "限流率(%)",
            "timeout_pct": "超时率(%)",
            "qps": "总处理吞吐量(请求/秒)",
            "success_qps": "业务成功吞吐量(请求/秒)",
            "avg_latency_ms": "平均延迟(ms)",
            "p95_latency_ms": "P95延迟(ms)",
            "p99_latency_ms": "P99延迟(ms)",
            "physical_shard0_requests": "分片0物理请求数",
            "physical_shard1_requests": "分片1物理请求数",
            "physical_shard2_requests": "分片2物理请求数",
            "cache_hits": "缓存命中数",
            "hot_physical_load_ratio": "热点物理负载比",
            "uniform_qps_overhead_pct": "均匀流量总处理吞吐量变化(%)",
            "uniform_success_qps_overhead_pct": "均匀流量业务成功吞吐量变化(%)",
            "uniform_p95_overhead_pct": "均匀流量P95延迟变化(%)",
        },
        "citus_hotspot": {
            "run_count": "重复次数",
            "system": "系统",
            "scenario": "场景",
            "defense": "策略",
            "requests": "请求数",
            "success_rate_pct": "成功率(%)",
            "failure_rate_pct": "失败率(%)",
            "qps": "总处理吞吐量(请求/秒)",
            "success_qps": "业务成功吞吐量(请求/秒)",
            "avg_latency_ms": "平均延迟(ms)",
            "p95_latency_ms": "P95延迟(ms)",
            "p99_latency_ms": "P99延迟(ms)",
            "hot_request_pct": "热点请求占比(%)",
        },
        "citus_resource": {
            "run_count": "重复次数",
            "scenario": "场景",
            "container": "节点",
            "component": "组件",
            "avg_cpu_percent": "平均CPU(%)",
            "max_cpu_percent": "峰值CPU(%)",
            "avg_memory_mb": "平均内存(MB)",
            "max_memory_mb": "峰值内存(MB)",
        },
        "citus_placement": {
            "run_count": "重复次数",
            "scenario": "场景",
            "shard_count": "Citus逻辑分片数",
            "worker_count": "工作节点数",
            "hotspot_shard_id": "热点分片编号",
            "hotspot_worker": "热点分片所在工作节点",
        },
        "tidb_hotspot": {
            "run_count": "重复次数",
            "system": "系统",
            "scenario": "场景",
            "defense": "策略",
            "requests": "请求数",
            "success_rate_pct": "成功率(%)",
            "failure_rate_pct": "失败率(%)",
            "qps": "总处理吞吐量(请求/秒)",
            "success_qps": "业务成功吞吐量(请求/秒)",
            "avg_latency_ms": "平均延迟(ms)",
            "p95_latency_ms": "P95延迟(ms)",
            "p99_latency_ms": "P99延迟(ms)",
            "hot_request_pct": "热点请求占比(%)",
        },
        "tidb_resource": {
            "run_count": "重复次数",
            "scenario": "场景",
            "container": "TiKV节点",
            "avg_cpu_percent": "平均CPU(%)",
            "max_cpu_percent": "峰值CPU(%)",
            "avg_memory_mb": "平均内存(MB)",
            "max_memory_mb": "峰值内存(MB)",
        },
        "tidb_region": {
            "run_count": "重复次数",
            "scenario": "场景",
            "observed_regions": "观测Region数",
            "leader_store_ids": "Leader存储节点ID",
            "region_ids": "Region ID列表",
        },
        "exp2_summary": {
            "run_count": "重复次数",
            "scenario": "场景",
            "mitigation": "缓解策略",
            "perturbation": "扰动类型",
            "perturbation_method": "扰动注入方式",
            "target_container": "目标Leader节点",
            "normal_success_qps": "正常期成功吞吐量(请求/秒)",
            "perturb_success_qps": "扰动期成功吞吐量(请求/秒)",
            "recovery_success_qps": "恢复期成功吞吐量(请求/秒)",
            "throughput_drop_pct": "扰动期成功吞吐量下降(%)",
            "normal_avg_latency_ms": "正常期成功请求平均延迟(ms)",
            "perturb_avg_latency_ms": "扰动期成功请求平均延迟(ms)",
            "recovery_avg_latency_ms": "恢复期成功请求平均延迟(ms)",
            "normal_p95_latency_ms": "正常期成功请求P95延迟(ms)",
            "perturb_p95_latency_ms": "扰动期成功请求P95延迟(ms)",
            "recovery_p95_latency_ms": "恢复期成功请求P95延迟(ms)",
            "normal_p99_latency_ms": "正常期成功请求P99延迟(ms)",
            "perturb_p99_latency_ms": "扰动期成功请求P99延迟(ms)",
            "recovery_p99_latency_ms": "恢复期成功请求P99延迟(ms)",
            "perturb_failure_rate_pct": "扰动期失败率(%)",
            "perturb_timeout_pct": "扰动期超时率(%)",
            "leader_transfer_rate_pct": "Leader转移发生率(%)",
            "leader_transfer_time_s": "Leader转移耗时(s)",
            "recovery_time_s": "恢复时间(s)",
        },
        "exp2_phase": {
            "run_count": "重复次数",
            "scenario": "场景",
            "phase": "阶段",
            "mitigation": "缓解策略",
            "perturbation": "扰动类型",
            "requests": "请求数",
            "success_rate_pct": "成功率(%)",
            "failure_rate_pct": "失败率(%)",
            "timeout_pct": "超时率(%)",
            "qps": "总处理吞吐量(请求/秒)",
            "success_qps": "业务成功吞吐量(请求/秒)",
            "avg_latency_ms": "成功请求平均延迟(ms)",
            "p95_latency_ms": "成功请求P95延迟(ms)",
            "p99_latency_ms": "成功请求P99延迟(ms)",
        },
        "exp2_resource": {
            "run_count": "重复次数",
            "scenario": "场景",
            "phase": "阶段",
            "container": "TiKV节点",
            "target_container": "目标Leader节点",
            "is_target_leader_pct": "目标Leader节点占比(%)",
            "avg_cpu_percent": "平均CPU(%)",
            "max_cpu_percent": "峰值CPU(%)",
            "avg_memory_mb": "平均内存(MB)",
            "max_memory_mb": "峰值内存(MB)",
        },
        "exp2_leader": {
            "run_count": "重复次数",
            "scenario": "场景",
            "phase": "阶段",
            "leader_changed_pct": "Leader变更观测占比(%)",
            "leader_store_ids": "观测Leader存储节点ID",
            "target_container": "初始目标Leader节点",
            "hot_leader_container": "当前热点Leader节点",
        },
        "exp3_summary": {
            "run_count": "重复次数",
            "defense": "防御策略",
            "pairs": "事务对数",
            "transactions": "事务数",
            "front_run_success_pct": "抢占式提交成功率(%)",
            "order_violation_pct": "顺序违规率(%)",
            "consistency_violation_pct": "一致性违规率(%)",
            "oversell_pct": "库存超卖率(%)",
            "rollback_rate_pct": "事务回滚率(%)",
            "success_rate_pct": "事务成功率(%)",
            "throughput_txn_s": "吞吐量(事务/秒)",
            "successful_order_throughput_s": "成功订单吞吐量(订单/秒)",
            "avg_latency_ms": "平均延迟(ms)",
            "p95_latency_ms": "P95延迟(ms)",
            "p99_latency_ms": "P99延迟(ms)",
            "avg_wait_ms": "平均等待时间(ms)",
            "p95_latency_overhead_pct": "P95延迟开销(%)",
            "throughput_change_pct": "吞吐量变化(%)",
        },
    }
    base_map = column_maps[kind]
    rename_map = {}
    for column in display.columns:
        if column in base_map:
            rename_map[column] = base_map[column]
        elif column.endswith("_std"):
            base = column[: -len("_std")]
            rename_map[column] = f"{base_map.get(base, base)}标准差"
        elif column.endswith("_ci95"):
            base = column[: -len("_ci95")]
            rename_map[column] = f"{base_map.get(base, base)}95%置信区间半宽"
    display = display.rename(columns=rename_map)
    display.to_csv(output, index=False)


def scenario_label(value: object) -> str:
    text = str(value)
    for prefix in ("citus_", "tidb_"):
        if text.startswith(prefix):
            text = text[len(prefix) :]
            break
    return EXP2_SCENARIO_LABELS.get(str(value), SCENARIO_LABELS.get(text, str(value)))


def defense_label(value: object) -> str:
    text = str(value)
    return DEFENSE_LABELS.get(
        text,
        CITUS_DEFENSE_LABELS.get(text, TIDB_DEFENSE_LABELS.get(text, EXP3_DEFENSE_LABELS.get(text, str(value)))),
    )


def node_label(value: object) -> str:
    return NODE_LABELS.get(str(value), str(value))


def exp2_phase_label(value: object) -> str:
    return EXP2_PHASE_LABELS.get(str(value), str(value))


def exp2_mitigation_label(value: object) -> str:
    return EXP2_MITIGATION_LABELS.get(str(value), str(value))


def exp2_perturbation_label(value: object) -> str:
    return EXP2_PERTURBATION_LABELS.get(str(value), str(value))


def exp2_method_label(value: object) -> str:
    return EXP2_METHOD_LABELS.get(str(value), str(value))


def node_list_label(value: object) -> str:
    return ",".join(node_label(part.strip()) for part in str(value).split(",") if part.strip())


def ensure_run_id(df: pd.DataFrame) -> pd.DataFrame:
    if "run_id" in df.columns:
        return df.copy()
    copy = df.copy()
    copy["run_id"] = 1
    return copy


def aggregate_repeated_runs(per_run: pd.DataFrame, group_cols: List[str]) -> pd.DataFrame:
    if per_run.empty:
        return per_run

    numeric_cols = [
        column
        for column in per_run.columns
        if column not in set(group_cols + ["run_id"]) and pd.api.types.is_numeric_dtype(per_run[column])
    ]
    object_cols = [
        column
        for column in per_run.columns
        if column not in set(group_cols + ["run_id"] + numeric_cols)
    ]

    rows: List[Dict[str, object]] = []
    for keys, group in per_run.groupby(group_cols, sort=False):
        if not isinstance(keys, tuple):
            keys = (keys,)
        row: Dict[str, object] = dict(zip(group_cols, keys))
        row["run_count"] = int(group["run_id"].nunique())
        for column in object_cols:
            non_null = group[column].dropna()
            row[column] = non_null.mode().iloc[0] if not non_null.mode().empty else (non_null.iloc[0] if not non_null.empty else "")
        for column in numeric_cols:
            values = group[column].dropna().astype(float)
            if values.empty:
                row[column] = math.nan
                row[f"{column}_std"] = math.nan
                row[f"{column}_ci95"] = math.nan
                continue
            row[column] = values.mean()
            std = values.std(ddof=1) if len(values) > 1 else 0.0
            row[f"{column}_std"] = std
            row[f"{column}_ci95"] = 1.96 * std / math.sqrt(len(values)) if len(values) > 1 else 0.0
        rows.append(row)
    return pd.DataFrame(rows)


def summarize_requests(df: pd.DataFrame) -> pd.DataFrame:
    df = ensure_run_id(df)
    rows: List[Dict[str, object]] = []
    for (run_id, scenario, defense), group in df.groupby(["run_id", "scenario", "defense"], sort=False):
        duration = max(group["end_ts"].max() - group["start_ts"].min(), 0.001)
        success = group[group["success"] == True]  # noqa: E712
        limited = group[group["error"].isin(RATE_LIMIT_ERRORS)]
        timeout = group[group["error"].astype(str).str.contains("timeout", na=False)]
        latencies = group["latency_ms"].astype(float)
        physical = group[
            group["physical_shard"].astype(str).str.startswith("shard-")
            & ~group["error"].astype(str).isin(RATE_LIMIT_ERRORS)
        ]
        physical_counts = (
            physical
            .groupby("physical_shard")
            .size()
            .to_dict()
        )
        hot_load = float(physical_counts.get("shard-0", 0))
        cold_loads = [float(physical_counts.get(f"shard-{i}", 0)) for i in (1, 2)]
        cold_mean = max(sum(cold_loads) / len(cold_loads), 1.0)
        rows.append(
            {
                "run_id": run_id,
                "scenario": scenario,
                "defense": defense,
                "requests": int(len(group)),
                "success_rate_pct": pct(len(success), len(group)),
                "failure_rate_pct": pct(len(group) - len(success), len(group)),
                "rate_limited_pct": pct(len(limited), len(group)),
                "timeout_pct": pct(len(timeout), len(group)),
                "qps": len(group) / duration,
                "success_qps": len(success) / duration,
                "avg_latency_ms": latencies.mean(),
                "p95_latency_ms": latencies.quantile(0.95),
                "p99_latency_ms": latencies.quantile(0.99),
                "physical_shard0_requests": int(hot_load),
                "physical_shard1_requests": int(physical_counts.get("shard-1", 0)),
                "physical_shard2_requests": int(physical_counts.get("shard-2", 0)),
                "cache_hits": int((group["physical_shard"] == "cache").sum()),
                "hot_physical_load_ratio": hot_load / cold_mean,
            }
        )

    per_run = pd.DataFrame(rows)
    per_run["uniform_qps_overhead_pct"] = math.nan
    per_run["uniform_success_qps_overhead_pct"] = math.nan
    per_run["uniform_p95_overhead_pct"] = math.nan
    for run_id, run_group in per_run[per_run["scenario"] == "uniform"].groupby("run_id", sort=False):
        uniform = run_group.set_index("defense")
        base_defense = "deterministic" if "deterministic" in uniform.index else "baseline"
        if base_defense not in uniform.index:
            continue
        base_qps = float(uniform.loc[base_defense, "qps"])
        base_success_qps = float(uniform.loc[base_defense, "success_qps"])
        base_p95 = float(uniform.loc[base_defense, "p95_latency_ms"])
        mask = (per_run["run_id"] == run_id) & (per_run["scenario"] == "uniform")
        per_run.loc[mask, "uniform_qps_overhead_pct"] = (
            (per_run.loc[mask, "qps"] - base_qps) / base_qps * 100.0
        )
        per_run.loc[mask, "uniform_success_qps_overhead_pct"] = (
            (per_run.loc[mask, "success_qps"] - base_success_qps) / base_success_qps * 100.0
        )
        per_run.loc[mask, "uniform_p95_overhead_pct"] = (
            (per_run.loc[mask, "p95_latency_ms"] - base_p95) / base_p95 * 100.0
        )
    return aggregate_repeated_runs(per_run, ["scenario", "defense"])


def pct(part: int, total: int) -> float:
    if total == 0:
        return 0.0
    return part / total * 100.0


def summarize_tidb_requests(df: pd.DataFrame) -> pd.DataFrame:
    df = ensure_run_id(df)
    rows: List[Dict[str, object]] = []
    for (run_id, scenario), group in df.groupby(["run_id", "scenario"], sort=False):
        duration = max(group["end_ts"].max() - group["start_ts"].min(), 0.001)
        success = group[group["success"] == True]  # noqa: E712
        latencies = group["latency_ms"].astype(float)
        rows.append(
            {
                "run_id": run_id,
                "system": "TiDB",
                "scenario": scenario,
                "defense": "tidb_native",
                "requests": int(len(group)),
                "success_rate_pct": pct(len(success), len(group)),
                "failure_rate_pct": pct(len(group) - len(success), len(group)),
                "qps": len(group) / duration,
                "success_qps": len(success) / duration,
                "avg_latency_ms": latencies.mean(),
                "p95_latency_ms": latencies.quantile(0.95),
                "p99_latency_ms": latencies.quantile(0.99),
                "hot_request_pct": pct(int(group["is_hot"].sum()), len(group)),
            }
        )
    return aggregate_repeated_runs(pd.DataFrame(rows), ["scenario"])


def summarize_citus_requests(df: pd.DataFrame) -> pd.DataFrame:
    df = ensure_run_id(df)
    rows: List[Dict[str, object]] = []
    for (run_id, scenario), group in df.groupby(["run_id", "scenario"], sort=False):
        duration = max(group["end_ts"].max() - group["start_ts"].min(), 0.001)
        success = group[group["success"] == True]  # noqa: E712
        latencies = group["latency_ms"].astype(float)
        rows.append(
            {
                "run_id": run_id,
                "system": "PostgreSQL+Citus",
                "scenario": scenario,
                "defense": "citus_native",
                "requests": int(len(group)),
                "success_rate_pct": pct(len(success), len(group)),
                "failure_rate_pct": pct(len(group) - len(success), len(group)),
                "qps": len(group) / duration,
                "success_qps": len(success) / duration,
                "avg_latency_ms": latencies.mean(),
                "p95_latency_ms": latencies.quantile(0.95),
                "p99_latency_ms": latencies.quantile(0.99),
                "hot_request_pct": pct(int(group["is_hot"].sum()), len(group)),
            }
        )
    return aggregate_repeated_runs(pd.DataFrame(rows), ["scenario"])


def summarize_citus_resources(df: pd.DataFrame) -> pd.DataFrame:
    df = ensure_run_id(df)
    rows: List[Dict[str, object]] = []
    for (run_id, scenario, container), group in df.groupby(["run_id", "scenario", "container"], sort=False):
        rows.append(
            {
                "run_id": run_id,
                "scenario": scenario,
                "container": container,
                "component": group["component"].iloc[0],
                "avg_cpu_percent": group["cpu_percent"].astype(float).mean(),
                "max_cpu_percent": group["cpu_percent"].astype(float).max(),
                "avg_memory_mb": group["memory_mb"].astype(float).mean(),
                "max_memory_mb": group["memory_mb"].astype(float).max(),
            }
        )
    return aggregate_repeated_runs(pd.DataFrame(rows), ["scenario", "container"])


def summarize_citus_placements(df: pd.DataFrame) -> pd.DataFrame:
    df = ensure_run_id(df)
    if df.empty:
        return pd.DataFrame()
    rows: List[Dict[str, object]] = []
    for (run_id, scenario), group in df.groupby(["run_id", "scenario"], sort=False):
        after = group[group["phase"] == "after"]
        target = after if not after.empty else group
        hotspot = target[target["is_hotspot_shard"] == True]  # noqa: E712
        rows.append(
            {
                "run_id": run_id,
                "scenario": scenario,
                "shard_count": int(target["shard_id"].nunique()),
                "worker_count": int(target["node_name"].nunique()),
                "hotspot_shard_id": ",".join(sorted({clean_id(v) for v in hotspot["shard_id"].dropna()})),
                "hotspot_worker": ",".join(sorted({str(v) for v in hotspot["node_name"].dropna()})),
            }
        )
    return aggregate_repeated_runs(pd.DataFrame(rows), ["scenario"])


def summarize_tidb_resources(df: pd.DataFrame) -> pd.DataFrame:
    df = ensure_run_id(df)
    rows: List[Dict[str, object]] = []
    for (run_id, scenario, container), group in df.groupby(["run_id", "scenario", "container"], sort=False):
        rows.append(
            {
                "run_id": run_id,
                "scenario": scenario,
                "container": container,
                "avg_cpu_percent": group["cpu_percent"].astype(float).mean(),
                "max_cpu_percent": group["cpu_percent"].astype(float).max(),
                "avg_memory_mb": group["memory_mb"].astype(float).mean(),
                "max_memory_mb": group["memory_mb"].astype(float).max(),
            }
        )
    return aggregate_repeated_runs(pd.DataFrame(rows), ["scenario", "container"])


def summarize_tidb_regions(df: pd.DataFrame) -> pd.DataFrame:
    df = ensure_run_id(df)
    table_regions = df[df["phase"].astype(str).isin(["before", "after"])].copy()
    if table_regions.empty:
        return pd.DataFrame()
    rows: List[Dict[str, object]] = []
    for (run_id, scenario), group in table_regions.groupby(["run_id", "scenario"], sort=False):
        after = group[group["phase"] == "after"]
        target = after if not after.empty else group
        leaders = sorted({clean_id(value) for value in target["leader_store_id"].dropna() if str(value)})
        regions = sorted({clean_id(value) for value in target["region_id"].dropna() if str(value)})
        rows.append(
            {
                "run_id": run_id,
                "scenario": scenario,
                "observed_regions": len(regions),
                "leader_store_ids": ",".join(leaders),
                "region_ids": ",".join(regions[:12]),
            }
        )
    return aggregate_repeated_runs(pd.DataFrame(rows), ["scenario"])


def summarize_exp2_phases(df: pd.DataFrame) -> pd.DataFrame:
    df = ensure_run_id(df)
    rows: List[Dict[str, object]] = []
    for (run_id, scenario, phase), group in df.groupby(["run_id", "scenario", "phase"], sort=False):
        duration = phase_duration(group)
        success = group[group["success"] == True]  # noqa: E712
        timeout = group[group["error"].astype(str).str.contains("Timeout|timeout", na=False)]
        latency_source = success if not success.empty else group
        latencies = latency_source["latency_ms"].astype(float)
        rows.append(
            {
                "run_id": run_id,
                "scenario": scenario,
                "phase": phase,
                "mitigation": first_value(group, "mitigation"),
                "perturbation": first_value(group, "perturbation"),
                "requests": int(len(group)),
                "success_rate_pct": pct(len(success), len(group)),
                "failure_rate_pct": pct(len(group) - len(success), len(group)),
                "timeout_pct": pct(len(timeout), len(group)),
                "qps": len(group) / duration,
                "success_qps": len(success) / duration,
                "avg_latency_ms": latencies.mean(),
                "p95_latency_ms": latencies.quantile(0.95),
                "p99_latency_ms": latencies.quantile(0.99),
            }
        )
    return aggregate_repeated_runs(pd.DataFrame(rows), ["scenario", "phase"])


def summarize_exp2_scenarios(
    requests: pd.DataFrame,
    leaders: pd.DataFrame,
    events: pd.DataFrame,
) -> pd.DataFrame:
    requests = ensure_run_id(requests)
    rows: List[Dict[str, object]] = []
    leader_lookup = {}
    if not leaders.empty:
        leaders = ensure_run_id(leaders)
        for (run_id, scenario), group in leaders.groupby(["run_id", "scenario"], sort=False):
            changed = group[group["leader_changed"] == True]  # noqa: E712
            changed_after_start = changed[changed["phase"].isin(["perturbation", "recovery"])]
            transfer_time = math.nan
            if not changed_after_start.empty:
                baseline_s = float(requests[(requests["run_id"] == run_id) & (requests["scenario"] == scenario)]["baseline_s"].iloc[0])
                transfer_time = max(float(changed_after_start["relative_s"].min()) - baseline_s, 0.0)
            leader_lookup[(run_id, scenario)] = {
                "leader_transfer_rate_pct": 100.0 if not changed_after_start.empty else 0.0,
                "leader_transfer_time_s": transfer_time,
                "leader_store_ids": ",".join(sorted({clean_id(value) for value in group["hot_leader_store_id"].dropna() if str(value)})),
            }

    method_lookup = {}
    if not events.empty:
        events = ensure_run_id(events)
        starts = events[events["event"].astype(str) == "start"]
        for (run_id, scenario), group in starts.groupby(["run_id", "scenario"], sort=False):
            method_lookup[(run_id, scenario)] = first_value(group, "method")

    for (run_id, scenario), group in requests.groupby(["run_id", "scenario"], sort=False):
        phase_stats = {}
        for phase, phase_group in group.groupby("phase", sort=False):
            phase_stats[phase] = request_phase_metrics(phase_group)
        normal = phase_stats.get("normal", request_phase_metrics(pd.DataFrame()))
        perturb = phase_stats.get("perturbation", normal if scenario == "baseline" else request_phase_metrics(pd.DataFrame()))
        recovery = phase_stats.get("recovery", normal if scenario == "baseline" else request_phase_metrics(pd.DataFrame()))
        throughput_drop = safe_pct_drop(normal.get("success_qps"), perturb.get("success_qps"))
        recovery_time = compute_recovery_time(group, normal)
        leader = leader_lookup.get((run_id, scenario), {})
        rows.append(
            {
                "run_id": run_id,
                "scenario": scenario,
                "mitigation": first_value(group, "mitigation"),
                "perturbation": first_value(group, "perturbation"),
                "perturbation_method": method_lookup.get((run_id, scenario), "none" if scenario == "baseline" else ""),
                "target_container": first_value(group, "target_container"),
                "normal_success_qps": normal.get("success_qps"),
                "perturb_success_qps": perturb.get("success_qps"),
                "recovery_success_qps": recovery.get("success_qps"),
                "throughput_drop_pct": throughput_drop,
                "normal_avg_latency_ms": normal.get("avg_latency_ms"),
                "perturb_avg_latency_ms": perturb.get("avg_latency_ms"),
                "recovery_avg_latency_ms": recovery.get("avg_latency_ms"),
                "normal_p95_latency_ms": normal.get("p95_latency_ms"),
                "perturb_p95_latency_ms": perturb.get("p95_latency_ms"),
                "recovery_p95_latency_ms": recovery.get("p95_latency_ms"),
                "normal_p99_latency_ms": normal.get("p99_latency_ms"),
                "perturb_p99_latency_ms": perturb.get("p99_latency_ms"),
                "recovery_p99_latency_ms": recovery.get("p99_latency_ms"),
                "perturb_failure_rate_pct": perturb.get("failure_rate_pct"),
                "perturb_timeout_pct": perturb.get("timeout_pct"),
                "leader_transfer_rate_pct": leader.get("leader_transfer_rate_pct", 0.0),
                "leader_transfer_time_s": leader.get("leader_transfer_time_s", math.nan),
                "recovery_time_s": recovery_time,
            }
        )
    return aggregate_repeated_runs(pd.DataFrame(rows), ["scenario"])


def request_phase_metrics(group: pd.DataFrame) -> Dict[str, float]:
    if group.empty:
        return {
            "requests": 0.0,
            "success_rate_pct": math.nan,
            "failure_rate_pct": math.nan,
            "timeout_pct": math.nan,
            "qps": math.nan,
            "success_qps": math.nan,
            "avg_latency_ms": math.nan,
            "p95_latency_ms": math.nan,
            "p99_latency_ms": math.nan,
        }
    duration = phase_duration(group)
    success = group[group["success"] == True]  # noqa: E712
    timeout = group[group["error"].astype(str).str.contains("Timeout|timeout", na=False)]
    latency_source = success if not success.empty else group
    latencies = latency_source["latency_ms"].astype(float)
    return {
        "requests": float(len(group)),
        "success_rate_pct": pct(len(success), len(group)),
        "failure_rate_pct": pct(len(group) - len(success), len(group)),
        "timeout_pct": pct(len(timeout), len(group)),
        "qps": len(group) / duration,
        "success_qps": len(success) / duration,
        "avg_latency_ms": latencies.mean(),
        "p95_latency_ms": latencies.quantile(0.95),
        "p99_latency_ms": latencies.quantile(0.99),
    }


def phase_duration(group: pd.DataFrame) -> float:
    if group.empty:
        return 0.001
    return max(float(group["end_ts"].max()) - float(group["start_ts"].min()), 0.001)


def first_value(group: pd.DataFrame, column: str) -> str:
    if group.empty or column not in group.columns:
        return ""
    values = group[column].dropna()
    if values.empty:
        return ""
    modes = values.mode()
    return str(modes.iloc[0] if not modes.empty else values.iloc[0])


def safe_pct_drop(before: object, after: object) -> float:
    try:
        before_f = float(before)
        after_f = float(after)
        if before_f <= 0 or pd.isna(before_f) or pd.isna(after_f):
            return math.nan
        return (before_f - after_f) / before_f * 100.0
    except Exception:
        return math.nan


def exp3_is_complete(exp3_summary: pd.DataFrame) -> bool:
    if exp3_summary.empty or "defense" not in exp3_summary.columns:
        return False
    return set(EXP3_DEFENSE_ORDER).issubset(set(exp3_summary["defense"].astype(str)))


def compute_recovery_time(group: pd.DataFrame, normal: Dict[str, float]) -> float:
    if group.empty or "recovery" not in set(group["phase"].astype(str)):
        return 0.0
    try:
        baseline_s = float(group["baseline_s"].iloc[0])
        perturb_s = float(group["perturb_s"].iloc[0])
        recovery_start = baseline_s + perturb_s
        target_qps = float(normal.get("success_qps", math.nan)) * 0.90
        target_p99 = float(normal.get("p99_latency_ms", math.nan)) * 1.10
    except Exception:
        return math.nan
    if pd.isna(target_qps) or pd.isna(target_p99):
        return math.nan
    recovery = group[group["phase"] == "recovery"].copy()
    if recovery.empty:
        return math.nan
    recovery["second_bin"] = recovery["relative_s"].astype(float).floordiv(1).astype(int)
    for second, bin_group in recovery.groupby("second_bin", sort=True):
        metrics = request_phase_metrics(bin_group)
        if metrics["success_qps"] >= target_qps and metrics["p99_latency_ms"] <= target_p99:
            return max(float(second) - recovery_start, 0.0)
    return float(recovery["relative_s"].max()) - recovery_start


def summarize_exp2_resources(df: pd.DataFrame) -> pd.DataFrame:
    df = ensure_run_id(df)
    rows: List[Dict[str, object]] = []
    for (run_id, scenario, phase, container), group in df.groupby(["run_id", "scenario", "phase", "container"], sort=False):
        rows.append(
            {
                "run_id": run_id,
                "scenario": scenario,
                "phase": phase,
                "container": container,
                "target_container": first_value(group, "target_container"),
                "is_target_leader_pct": pct(int(group["is_target_leader"].sum()), len(group)),
                "avg_cpu_percent": group["cpu_percent"].astype(float).mean(),
                "max_cpu_percent": group["cpu_percent"].astype(float).max(),
                "avg_memory_mb": group["memory_mb"].astype(float).mean(),
                "max_memory_mb": group["memory_mb"].astype(float).max(),
            }
        )
    return aggregate_repeated_runs(pd.DataFrame(rows), ["scenario", "phase", "container"])


def summarize_exp2_leaders(df: pd.DataFrame) -> pd.DataFrame:
    df = ensure_run_id(df)
    rows: List[Dict[str, object]] = []
    for (run_id, scenario, phase), group in df.groupby(["run_id", "scenario", "phase"], sort=False):
        rows.append(
            {
                "run_id": run_id,
                "scenario": scenario,
                "phase": phase,
                "leader_changed_pct": pct(int(group["leader_changed"].sum()), len(group)),
                "leader_store_ids": ",".join(sorted({clean_id(value) for value in group["hot_leader_store_id"].dropna() if str(value)})),
                "target_container": first_value(group, "target_container"),
                "hot_leader_container": ",".join(sorted({str(value) for value in group["hot_leader_container"].dropna() if str(value)})),
            }
        )
    return aggregate_repeated_runs(pd.DataFrame(rows), ["scenario", "phase"])


def summarize_exp3(transactions: pd.DataFrame, pairs: pd.DataFrame) -> pd.DataFrame:
    transactions = ensure_run_id(transactions)
    pairs = ensure_run_id(pairs)
    rows: List[Dict[str, object]] = []
    for (run_id, defense), txn_group in transactions.groupby(["run_id", "defense"], sort=False):
        pair_group = pairs[(pairs["run_id"] == run_id) & (pairs["defense"] == defense)]
        duration = max(txn_group["end_ts"].max() - txn_group["start_ts"].min(), 0.001)
        latencies = txn_group["latency_ms"].astype(float)
        success = txn_group[txn_group["success"] == True]  # noqa: E712
        rollback = txn_group[txn_group["rollback"] == True]  # noqa: E712
        rows.append(
            {
                "run_id": run_id,
                "defense": defense,
                "pairs": int(len(pair_group)),
                "transactions": int(len(txn_group)),
                "front_run_success_pct": bool_pct(pair_group, "front_run_success"),
                "order_violation_pct": bool_pct(pair_group, "order_violation"),
                "consistency_violation_pct": bool_pct(pair_group, "consistency_violation"),
                "oversell_pct": bool_pct(pair_group, "oversell"),
                "rollback_rate_pct": pct(len(rollback), len(txn_group)),
                "success_rate_pct": pct(len(success), len(txn_group)),
                "throughput_txn_s": len(txn_group) / duration,
                "successful_order_throughput_s": len(success) / duration,
                "avg_latency_ms": latencies.mean(),
                "p95_latency_ms": latencies.quantile(0.95),
                "p99_latency_ms": latencies.quantile(0.99),
                "avg_wait_ms": txn_group["wait_ms"].astype(float).mean() if "wait_ms" in txn_group.columns else 0.0,
            }
        )
    per_run = pd.DataFrame(rows)
    per_run["p95_latency_overhead_pct"] = math.nan
    per_run["throughput_change_pct"] = math.nan
    for run_id, group in per_run.groupby("run_id", sort=False):
        lookup = group.set_index("defense")
        if "baseline" not in lookup.index:
            continue
        base_p95 = float(lookup.loc["baseline", "p95_latency_ms"])
        base_throughput = float(lookup.loc["baseline", "throughput_txn_s"])
        mask = per_run["run_id"] == run_id
        if base_p95 > 0:
            per_run.loc[mask, "p95_latency_overhead_pct"] = (
                (per_run.loc[mask, "p95_latency_ms"] - base_p95) / base_p95 * 100.0
            )
        if base_throughput > 0:
            per_run.loc[mask, "throughput_change_pct"] = (
                (per_run.loc[mask, "throughput_txn_s"] - base_throughput) / base_throughput * 100.0
            )
    return aggregate_repeated_runs(per_run, ["defense"])


def bool_pct(df: pd.DataFrame, column: str) -> float:
    if df.empty or column not in df.columns:
        return 0.0
    return pct(int(df[column].sum()), len(df))


def clean_id(value) -> str:
    text = str(value)
    if text.endswith(".0"):
        text = text[:-2]
    return text


def render_table_a(
    summary: pd.DataFrame,
    citus_summary: pd.DataFrame,
    tidb_summary: pd.DataFrame,
) -> str:
    lines = [
        "# 表A：确定性路由攻击与混淆路由防御效果评估",
        "",
    ]
    cols = [
        "实验环境",
        "热点比例",
        "路由/防御策略",
        "限流率/失败率(%)",
        "处理吞吐量(请求/s)",
        "平均延迟(ms)",
        "P99延迟(ms)",
        "热点物理负载比",
    ]
    lines.append("|" + "|".join(cols) + "|")
    lines.append("|---|---:|---|---:|---:|---:|---:|---:|")

    lookup = summary.set_index(["scenario", "defense"])
    postgres_rows = [
        ("uniform", "deterministic", "0%"),
        ("uniform", "obfuscated", "0%"),
        ("hot70", "deterministic", "70%"),
        ("hot70", "obfuscated", "70%"),
        ("hot90", "deterministic", "90%"),
        ("hot90", "obfuscated", "90%"),
        ("hot90", "obfuscated_control", "90%"),
    ]
    for scenario, defense, hotspot_pct in postgres_rows:
        if (scenario, defense) not in lookup.index:
            continue
        row = lookup.loc[(scenario, defense)]
        lines.append(
            "|"
            + "|".join(
                [
                    "PostgreSQL三分片",
                    hotspot_pct,
                    DEFENSE_LABELS.get(defense, defense),
                    fmt(row["failure_rate_pct"]),
                    fmt(row["qps"]),
                    fmt(row["avg_latency_ms"]),
                    fmt(row["p99_latency_ms"]),
                    fmt(row["hot_physical_load_ratio"]),
                ]
            )
            + "|"
        )

    if not citus_summary.empty:
        citus_lookup = citus_summary.set_index("scenario")
        citus_rows = [("citus_hot90", "90%")]
        for scenario, hotspot_pct in citus_rows:
            if scenario not in citus_lookup.index:
                continue
            row = citus_lookup.loc[scenario]
            lines.append(
                "|"
                + "|".join(
                    [
                        "PostgreSQL+Citus",
                        hotspot_pct,
                        "原生分布式扩展",
                        fmt(row["failure_rate_pct"]),
                        fmt(row["qps"]),
                        fmt(row["avg_latency_ms"]),
                        fmt(row["p99_latency_ms"]),
                        "-",
                    ]
                )
                + "|"
            )

    if not tidb_summary.empty:
        tidb_lookup = tidb_summary.set_index("scenario")
        tidb_rows = [("tidb_hot90", "90%")]
        for scenario, hotspot_pct in tidb_rows:
            if scenario not in tidb_lookup.index:
                continue
            row = tidb_lookup.loc[scenario]
            lines.append(
                "|"
                + "|".join(
                    [
                        "TiDB",
                        hotspot_pct,
                        "原生调度",
                        fmt(row["failure_rate_pct"]),
                        fmt(row["qps"]),
                        fmt(row["avg_latency_ms"]),
                        fmt(row["p99_latency_ms"]),
                        "-",
                    ]
                )
                + "|"
            )

    lines.extend(
        [
            "",
            "注：表中数值为多次重复实验的均值；PostgreSQL 三分片中，70%/90% 目标流量表示攻击者按公开规则筛选出 `item_id % 3 == 0` 的 key 集合。"
            "混淆路由使用带 secret salt 的哈希虚拟桶重映射，热点物理负载比为分片0已路由物理请求量与分片1、分片2平均请求量之比；主动限流请求不计入物理请求量。"
            "Citus/TiDB 作为原生系统对照，未计算该 PostgreSQL 机制模拟指标。",
        ]
    )
    return "\n".join(lines)


def render_table_b(exp2_summary: pd.DataFrame) -> str:
    lines = [
        "# 表B：TiDB Leader 压力/节点暂停下的可用性与恢复评估",
        "",
        "注：表中数值为 5 次重复实验的均值；扰动对象为热点 Region 初始 Leader 所在 TiKV 节点，更详细的重复实验统计见结构化汇总 CSV。",
        "",
    ]
    cols = [
        "场景",
        "缓解策略",
        "扰动方式",
        "目标Leader节点",
        "正常期成功吞吐量(请求/秒)",
        "扰动期成功吞吐量(请求/秒)",
        "吞吐下降(%)",
        "扰动期失败率(%)",
        "正常期成功请求P99(ms)",
        "扰动期成功请求P99(ms)",
        "恢复时间(s)",
    ]
    lines.append("|" + "|".join(cols) + "|")
    lines.append("|" + "|".join(["---"] * len(cols)) + "|")
    order = [
        "baseline",
        "leader_cpu_stress",
        "leader_network_perturbation",
        "leader_cpu_stress_limited",
    ]
    if exp2_summary.empty:
        lines.append("|尚未生成实验二结果|-|-|-|-|-|-|-|-|-|-|")
    else:
        lookup = exp2_summary.set_index("scenario")
        for scenario in order:
            if scenario not in lookup.index:
                continue
            row = lookup.loc[scenario]
            lines.append(
                "|"
                + "|".join(
                    [
                        EXP2_SCENARIO_LABELS.get(scenario, scenario),
                        EXP2_MITIGATION_LABELS.get(str(row.get("mitigation", "")), str(row.get("mitigation", ""))),
                        EXP2_METHOD_LABELS.get(str(row.get("perturbation_method", "")), str(row.get("perturbation_method", ""))),
                        node_label(row.get("target_container", "")),
                        fmt(row.get("normal_success_qps")),
                        fmt(row.get("perturb_success_qps")),
                        fmt(row.get("throughput_drop_pct")),
                        fmt(row.get("perturb_failure_rate_pct")),
                        fmt(row.get("normal_p99_latency_ms")),
                        fmt(row.get("perturb_p99_latency_ms")),
                        fmt(row.get("recovery_time_s")),
                    ]
                )
                + "|"
            )
    lines.extend(
        [
            "",
            "注：本文所报告的节点故障组实际采用短时暂停目标 TiKV 容器，未采用网络时延或丢包注入。"
            "历史原始 CSV 保留场景标识 `leader_network_perturbation`，实际方式以事件文件的 `method` 字段为准。"
            "P99 延迟按成功请求统计，失败请求通过失败率单独报告；"
            "恢复时间按恢复期内成功吞吐量达到正常期 90% 且成功请求 P99 延迟不高于正常期 110% 的最早时间估算。",
        ]
    )
    return "\n".join(lines)


def render_table_c(exp3_summary: pd.DataFrame) -> str:
    lines = [
        "# 表C：跨分片事务异步窗口下的抢占式提交模拟结果",
        "",
        "注：表中数值为 5 次重复实验的均值；场景为 victim 先到、attacker 后到，victim 在用户校验后存在人为异步窗口，更详细的重复实验统计见结构化汇总 CSV。",
        "",
    ]
    cols = [
        "防御策略",
        "抢占式提交成功率(%)",
        "一致性违规率(%)",
        "事务回滚率(%)",
        "事务成功率(%)",
        "吞吐量(事务/秒)",
        "平均延迟(ms)",
        "P95延迟(ms)",
        "P99延迟(ms)",
        "P95延迟开销(%)",
    ]
    lines.append("|" + "|".join(cols) + "|")
    lines.append("|" + "|".join(["---"] * len(cols)) + "|")
    lookup = exp3_summary.set_index("defense") if not exp3_summary.empty else pd.DataFrame()
    for defense in EXP3_DEFENSE_ORDER:
        if exp3_summary.empty or defense not in lookup.index:
            continue
        row = lookup.loc[defense]
        lines.append(
            "|"
            + "|".join(
                [
                    EXP3_DEFENSE_LABELS.get(defense, defense),
                    fmt(row.get("front_run_success_pct")),
                    fmt(row.get("consistency_violation_pct")),
                    fmt(row.get("rollback_rate_pct")),
                    fmt(row.get("success_rate_pct")),
                    fmt(row.get("throughput_txn_s")),
                    fmt(row.get("avg_latency_ms")),
                    fmt(row.get("p95_latency_ms")),
                    fmt(row.get("p99_latency_ms")),
                    fmt(row.get("p95_latency_overhead_pct")),
                ]
            )
            + "|"
        )
    lines.extend(
        [
            "",
            "注：一致性违规率表示业务语义层面的顺序反转比例，不等同于数据库物理一致性破坏；"
            "库存初始值为 2，因此本实验主要观察后到事务先完成库存扣减和订单确认，而非库存超卖。",
        ]
    )
    return "\n".join(lines)


def render_supplemental_table_a(
    summary: pd.DataFrame,
    citus_summary: pd.DataFrame,
    citus_resource_summary: pd.DataFrame,
    citus_placement_summary: pd.DataFrame,
    tidb_summary: pd.DataFrame,
    tidb_resource_summary: pd.DataFrame,
    tidb_region_summary: pd.DataFrame,
) -> str:
    cols = [
        "场景",
        "路由/防御策略",
        "成功率(%)",
        "限流率(%)",
        "总处理吞吐量(请求/秒)",
        "业务成功吞吐量(请求/秒)",
        "平均延迟(ms)",
        "P95延迟(ms)",
        "P99延迟(ms)",
        "热点物理负载比",
        "均匀流量业务成功吞吐量变化(%)",
    ]
    lines = [
        "# 补充表S1：确定性路由攻击与混淆路由防御完整结果",
        "",
        "注：表中主要数值为 5 次重复实验的均值±标准差；正文表 A 仅保留均值简表。",
        "",
        "## 补充表S1-1：PostgreSQL 三分片机制模拟",
        "",
        "|" + "|".join(cols) + "|",
    ]
    lines.append("|" + "|".join(["---"] * len(cols)) + "|")
    for _, row in summary.iterrows():
        lines.append(
            "|"
            + "|".join(
                [
                    SCENARIO_LABELS.get(row["scenario"], row["scenario"]),
                    DEFENSE_LABELS.get(row["defense"], row["defense"]),
                    fmt_pm(row, "success_rate_pct"),
                    fmt_pm(row, "rate_limited_pct"),
                    fmt_pm(row, "qps"),
                    fmt_pm(row, "success_qps"),
                    fmt_pm(row, "avg_latency_ms"),
                    fmt_pm(row, "p95_latency_ms"),
                    fmt_pm(row, "p99_latency_ms"),
                    fmt_pm(row, "hot_physical_load_ratio"),
                    fmt_pm(row, "uniform_success_qps_overhead_pct"),
                ]
            )
            + "|"
        )
    lines.append("")
    lines.append(
        "注：目标流量由攻击者按公开确定性规则筛选 `item_id % 3 == 0` 的 key 集合构造；"
        "热点物理负载比为公开目标分片0的已路由物理请求量与分片1、分片2平均请求量之比，主动限流请求不计入物理请求量。"
    )
    section_no = 2
    if not citus_summary.empty:
        lines.extend(["", f"## 补充表S1-{section_no}：PostgreSQL+Citus 分布式扩展对照", ""])
        section_no += 1
        citus_cols = [
            "系统",
            "场景",
            "策略",
            "成功率(%)",
            "失败率(%)",
            "总处理吞吐量(请求/秒)",
            "业务成功吞吐量(请求/秒)",
            "平均延迟(ms)",
            "P95延迟(ms)",
            "P99延迟(ms)",
            "热点请求占比(%)",
            "Citus逻辑分片数",
            "热点分片所在工作节点",
        ]
        lines.append("|" + "|".join(citus_cols) + "|")
        lines.append("|" + "|".join(["---"] * len(citus_cols)) + "|")
        placement_lookup = {}
        if not citus_placement_summary.empty:
            placement_lookup = citus_placement_summary.set_index("scenario").to_dict(orient="index")
        for _, row in citus_summary.iterrows():
            placement = placement_lookup.get(row["scenario"], {})
            lines.append(
                "|"
                + "|".join(
                    [
                        "PostgreSQL+Citus",
                        SCENARIO_LABELS.get(row["scenario"].replace("citus_", ""), row["scenario"]),
                        "Citus 原生分布式扩展",
                        fmt_pm(row, "success_rate_pct"),
                        fmt_pm(row, "failure_rate_pct"),
                        fmt_pm(row, "qps"),
                        fmt_pm(row, "success_qps"),
                        fmt_pm(row, "avg_latency_ms"),
                        fmt_pm(row, "p95_latency_ms"),
                        fmt_pm(row, "p99_latency_ms"),
                        fmt_pm(row, "hot_request_pct"),
                        fmt_pm(pd.Series(placement), "shard_count") if placement else "-",
                        node_list_label(placement.get("hotspot_worker", "-")),
                    ]
                )
                + "|"
            )
    if not citus_resource_summary.empty:
        lines.extend(["", f"## 补充表S1-{section_no}：PostgreSQL+Citus 节点负载采样", ""])
        section_no += 1
        lines.append("|场景|节点|组件|平均CPU(%)|峰值CPU(%)|平均内存(MB)|峰值内存(MB)|")
        lines.append("|---|---|---|---|---|---|---|")
        for _, row in citus_resource_summary.iterrows():
            lines.append(
                "|"
                + "|".join(
                    [
                        SCENARIO_LABELS.get(str(row["scenario"]).replace("citus_", ""), row["scenario"]),
                        node_label(row["container"]),
                        COMPONENT_LABELS.get(str(row["component"]), str(row["component"])),
                        fmt_pm(row, "avg_cpu_percent"),
                        fmt_pm(row, "max_cpu_percent"),
                        fmt_pm(row, "avg_memory_mb"),
                        fmt_pm(row, "max_memory_mb"),
                    ]
                )
                + "|"
            )
    if not tidb_summary.empty:
        lines.extend(["", f"## 补充表S1-{section_no}：TiDB 真实分布式数据库对照", ""])
        section_no += 1
        tidb_cols = [
            "系统",
            "场景",
            "策略",
            "成功率(%)",
            "失败率(%)",
            "总处理吞吐量(请求/秒)",
            "业务成功吞吐量(请求/秒)",
            "平均延迟(ms)",
            "P95延迟(ms)",
            "P99延迟(ms)",
            "热点请求占比(%)",
            "Region 数",
            "Leader 存储节点",
        ]
        lines.append("|" + "|".join(tidb_cols) + "|")
        lines.append("|" + "|".join(["---"] * len(tidb_cols)) + "|")
        region_lookup = {}
        if not tidb_region_summary.empty:
            region_lookup = tidb_region_summary.set_index("scenario").to_dict(orient="index")
        for _, row in tidb_summary.iterrows():
            region = region_lookup.get(row["scenario"], {})
            lines.append(
                "|"
                + "|".join(
                    [
                        "TiDB",
                        SCENARIO_LABELS.get(row["scenario"].replace("tidb_", ""), row["scenario"]),
                        "TiDB 原生调度",
                        fmt_pm(row, "success_rate_pct"),
                        fmt_pm(row, "failure_rate_pct"),
                        fmt_pm(row, "qps"),
                        fmt_pm(row, "success_qps"),
                        fmt_pm(row, "avg_latency_ms"),
                        fmt_pm(row, "p95_latency_ms"),
                        fmt_pm(row, "p99_latency_ms"),
                        fmt_pm(row, "hot_request_pct"),
                        fmt_pm(pd.Series(region), "observed_regions") if region else "-",
                        str(region.get("leader_store_ids", "-")),
                    ]
                )
                + "|"
            )
    if not tidb_resource_summary.empty:
        lines.extend(["", f"## 补充表S1-{section_no}：TiDB 对照实验 TiKV 负载采样", ""])
        section_no += 1
        lines.append("|场景|TiKV节点|平均CPU(%)|峰值CPU(%)|平均内存(MB)|峰值内存(MB)|")
        lines.append("|---|---|---|---|---|---|")
        for _, row in tidb_resource_summary.iterrows():
            lines.append(
                "|"
                + "|".join(
                    [
                        SCENARIO_LABELS.get(str(row["scenario"]).replace("tidb_", ""), row["scenario"]),
                        node_label(row["container"]),
                        fmt_pm(row, "avg_cpu_percent"),
                        fmt_pm(row, "max_cpu_percent"),
                        fmt_pm(row, "avg_memory_mb"),
                        fmt_pm(row, "max_memory_mb"),
                    ]
                )
                + "|"
            )
    return "\n".join(lines)


def fmt(value) -> str:
    try:
        if pd.isna(value):
            return "-"
        return f"{float(value):.2f}"
    except Exception:
        return str(value)


def fmt_pm(row: pd.Series, column: str) -> str:
    mean = row.get(column)
    std = row.get(f"{column}_std")
    try:
        if pd.isna(mean):
            return "-"
        if std is None or pd.isna(std):
            return f"{float(mean):.2f}"
        return f"{float(mean):.2f}±{float(std):.2f}"
    except Exception:
        return str(mean)


def fmt_count(value) -> str:
    try:
        number = float(value)
        if number.is_integer():
            return str(int(number))
        return f"{number:.2f}"
    except Exception:
        return str(value)


def fmt_ci(row: pd.Series, column: str) -> str:
    mean = row.get(column)
    ci95 = row.get(f"{column}_ci95")
    try:
        if pd.isna(mean):
            return "-"
        if ci95 is None or pd.isna(ci95):
            return f"{float(mean):.2f}"
        return f"{float(mean):.2f}±{float(ci95):.2f}"
    except Exception:
        return str(mean)


def clipped_yerr(means: pd.Series, cis: pd.Series) -> List[List[float]]:
    lower = []
    upper = []
    for mean, ci in zip(means.fillna(0).astype(float), cis.fillna(0).astype(float)):
        lower.append(min(ci, mean))
        upper.append(ci)
    return [lower, upper]


def render_exp1_multiplot(
    requests: pd.DataFrame,
    summary: pd.DataFrame,
    citus_summary: pd.DataFrame,
    citus_resources: pd.DataFrame,
    tidb_summary: pd.DataFrame,
    tidb_resources: pd.DataFrame,
    output: Path,
) -> None:
    fig, axes = plt.subplots(2, 2, figsize=(13.2, 8.6))
    fig.suptitle("实验一：确定性路由攻击与混淆路由防御组图（n=5，误差线/阴影为95%置信区间）", fontsize=13)
    draw_exp1_shard_load_axis(axes[0, 0], requests)
    draw_exp1_resource_axis(
        axes[0, 1],
        citus_resources,
        ["citus_uniform", "citus_hot70", "citus_hot90"],
        "B. PostgreSQL+Citus 节点峰值CPU",
        "流量场景",
    )
    draw_exp1_resource_axis(
        axes[1, 0],
        tidb_resources,
        ["tidb_uniform", "tidb_hot70", "tidb_hot90"],
        "C. TiDB TiKV 节点峰值CPU",
        "流量场景",
    )
    draw_exp1_p99_line_axis(axes[1, 1], summary, citus_summary, tidb_summary)
    fig.tight_layout(rect=[0, 0, 1, 0.95])
    fig.savefig(output, dpi=180)
    plt.close(fig)


def draw_exp1_shard_load_axis(ax, df: pd.DataFrame) -> None:
    if df.empty:
        ax.text(0.5, 0.5, "无数据", transform=ax.transAxes, ha="center", va="center")
        return
    df = ensure_run_id(df)
    hot = df[df["scenario"] == "hot90"].copy()
    hot = hot[
        hot["physical_shard"].astype(str).str.startswith("shard-")
        & ~hot["error"].astype(str).isin(RATE_LIMIT_ERRORS)
    ]
    run_ids = sorted(df["run_id"].dropna().unique())
    observed = set(df["defense"].astype(str))
    defenses = [item for item in ["deterministic", "obfuscated", "obfuscated_control"] if item in observed]
    if not defenses:
        defenses = [item for item in ["baseline", "shard_limit", "hot_key_limit", "queue_isolation"] if item in observed]
    shards = ["shard-0", "shard-1", "shard-2"]
    counts = hot.groupby(["run_id", "defense", "physical_shard"]).size().rename("requests")
    full_index = pd.MultiIndex.from_product([run_ids, defenses, shards], names=["run_id", "defense", "physical_shard"])
    per_run = counts.reindex(full_index, fill_value=0).reset_index()
    stats = per_run.groupby(["defense", "physical_shard"])["requests"].agg(["mean", "std", "count"]).reset_index()
    stats["ci95"] = stats["std"].fillna(0) * 1.96 / stats["count"].pow(0.5)
    means = stats.pivot(index="defense", columns="physical_shard", values="mean").reindex(index=defenses, columns=shards)
    cis = stats.pivot(index="defense", columns="physical_shard", values="ci95").reindex(index=defenses, columns=shards).fillna(0)
    x = range(len(means.index))
    width = 0.24
    colors = ["#C94C4C", "#4C78A8", "#59A14F"]
    for idx, shard in enumerate(means.columns):
        ax.bar(
            [pos + (idx - 1) * width for pos in x],
            means[shard].values,
            width=width,
            yerr=clipped_yerr(means[shard], cis[shard]),
            capsize=3,
            label=SHARD_LABELS.get(shard, shard),
            color=colors[idx],
        )
    ax.set_title("A. 90%目标流量下 PostgreSQL 物理分片负载")
    ax.set_ylabel("已路由物理请求数")
    ax.set_xticks(list(x), [DEFENSE_LABELS.get(item, item) for item in means.index], rotation=14, ha="right")
    ax.legend(title="物理分片", fontsize=8, title_fontsize=9)
    ax.grid(axis="y", alpha=0.25)


def draw_exp1_resource_axis(ax, df: pd.DataFrame, scenarios: List[str], title: str, xlabel: str) -> None:
    if df.empty:
        ax.text(0.5, 0.5, "无资源采样", transform=ax.transAxes, ha="center", va="center")
        ax.set_title(title)
        return
    df = ensure_run_id(df)
    per_run = df.groupby(["run_id", "scenario", "container"])["cpu_percent"].max().reset_index(name="peak_cpu")
    stats = per_run.groupby(["scenario", "container"])["peak_cpu"].agg(["mean", "std", "count"]).reset_index()
    stats["ci95"] = stats["std"].fillna(0) * 1.96 / stats["count"].pow(0.5)
    pivot = stats.pivot(index="scenario", columns="container", values="mean").reindex(index=scenarios)
    ci = stats.pivot(index="scenario", columns="container", values="ci95").reindex(index=scenarios).fillna(0)
    pivot = pivot.dropna(axis=1, how="all")
    x = range(len(pivot.index))
    node_count = max(len(pivot.columns), 1)
    width = min(0.72 / node_count, 0.22)
    offsets = [(idx - (node_count - 1) / 2) * width for idx in range(node_count)]
    colors = ["#4C78A8", "#59A14F", "#F28E2B", "#C94C4C"]
    for idx, container in enumerate(pivot.columns):
        ax.bar(
            [pos + offsets[idx] for pos in x],
            pivot[container].values,
            width=width,
            yerr=clipped_yerr(pivot[container], ci[container]),
            capsize=3,
            label=node_label(container),
            color=colors[idx % len(colors)],
        )
    ax.set_title(title)
    ax.set_ylabel("峰值CPU(%)")
    ax.set_xlabel(xlabel)
    ax.set_xticks(list(x), [scenario_label(item) for item in pivot.index], rotation=0)
    ax.legend(title="节点", fontsize=7, title_fontsize=8, loc="upper left")
    ax.grid(axis="y", alpha=0.25)


def draw_exp1_p99_line_axis(ax, summary: pd.DataFrame, citus_summary: pd.DataFrame, tidb_summary: pd.DataFrame) -> None:
    hotspot = [0, 70, 90]
    series = [
        ("PostgreSQL确定性路由", summary, ["uniform", "hot70", "hot90"], "deterministic", "#C94C4C"),
        ("PostgreSQL混淆路由", summary, ["uniform", "hot70", "hot90"], "obfuscated", "#4C78A8"),
        ("PostgreSQL+Citus", citus_summary, ["citus_uniform", "citus_hot70", "citus_hot90"], None, "#F28E2B"),
        ("TiDB", tidb_summary, ["tidb_uniform", "tidb_hot70", "tidb_hot90"], None, "#59A14F"),
    ]
    for label, frame, scenarios, defense, color in series:
        if frame.empty:
            continue
        values = []
        cis = []
        for scenario in scenarios:
            row = exp1_summary_row(frame, scenario, defense)
            if row is None:
                values.append(math.nan)
                cis.append(0.0)
            else:
                values.append(float(row.get("p99_latency_ms", math.nan)))
                ci = row.get("p99_latency_ms_ci95", 0.0)
                cis.append(0.0 if pd.isna(ci) else float(ci))
        if all(pd.isna(value) for value in values):
            continue
        y = pd.Series(values, dtype="float")
        ci_series = pd.Series(cis, dtype="float")
        ax.plot(hotspot, y, marker="o", linewidth=2, label=label, color=color)
        ax.fill_between(hotspot, (y - ci_series).clip(lower=0), y + ci_series, color=color, alpha=0.12)
    ax.set_title("D. 目标流量比例升高时的 P99 延迟变化")
    ax.set_xlabel("目标请求比例(%)")
    ax.set_ylabel("P99延迟(ms)")
    ax.set_xticks(hotspot, ["0", "70", "90"])
    ax.grid(alpha=0.25)
    ax.legend(fontsize=8, loc="upper left")


def exp1_summary_row(frame: pd.DataFrame, scenario: str, defense: object) -> Optional[pd.Series]:
    subset = frame[frame["scenario"] == scenario]
    if defense is not None and "defense" in subset.columns:
        subset = subset[subset["defense"] == defense]
    if subset.empty:
        return None
    return subset.iloc[0]


def render_shard_load_figure(df: pd.DataFrame, output: Path) -> None:
    df = ensure_run_id(df)
    hot = df[df["scenario"] == "hot90"].copy()
    hot = hot[
        hot["physical_shard"].astype(str).str.startswith("shard-")
        & ~hot["error"].astype(str).isin(RATE_LIMIT_ERRORS)
    ]
    run_ids = sorted(df["run_id"].dropna().unique())
    observed = set(df["defense"].astype(str))
    defenses = [item for item in ["deterministic", "obfuscated", "obfuscated_control"] if item in observed]
    if not defenses:
        defenses = [item for item in ["baseline", "shard_limit", "hot_key_limit", "queue_isolation"] if item in observed]
    shards = ["shard-0", "shard-1", "shard-2"]
    counts = hot.groupby(["run_id", "defense", "physical_shard"]).size().rename("requests")
    full_index = pd.MultiIndex.from_product([run_ids, defenses, shards], names=["run_id", "defense", "physical_shard"])
    per_run = counts.reindex(full_index, fill_value=0).reset_index()
    stats = (
        per_run.groupby(["defense", "physical_shard"])["requests"]
        .agg(["mean", "std", "count"])
        .reset_index()
    )
    stats["ci95"] = stats["std"].fillna(0) * 1.96 / stats["count"].pow(0.5)
    means = stats.pivot(index="defense", columns="physical_shard", values="mean").reindex(index=defenses, columns=shards)
    cis = stats.pivot(index="defense", columns="physical_shard", values="ci95").reindex(index=defenses, columns=shards).fillna(0)

    plt.figure(figsize=(9.5, 5.2))
    x = range(len(means.index))
    width = 0.24
    colors = ["#C94C4C", "#4C78A8", "#59A14F"]
    for idx, shard in enumerate(means.columns):
        plt.bar(
            [pos + (idx - 1) * width for pos in x],
            means[shard].values,
            width=width,
            yerr=clipped_yerr(means[shard], cis[shard]),
            capsize=4,
            label=SHARD_LABELS.get(shard, shard),
            color=colors[idx],
        )
    plt.xticks(list(x), [DEFENSE_LABELS.get(item, item) for item in means.index], rotation=0)
    plt.ylabel("已路由物理请求数")
    plt.xlabel("防御策略")
    plt.title("90% 目标流量下的物理分片负载（误差线为95%置信区间）")
    plt.legend(title="物理分片", loc="upper left", bbox_to_anchor=(1.01, 1.0), borderaxespad=0)
    plt.tight_layout()
    plt.savefig(output, dpi=180)
    plt.close()


def render_tidb_tikv_figure(df: pd.DataFrame, output: Path) -> None:
    if df.empty:
        return
    df = ensure_run_id(df)
    per_run = df.groupby(["run_id", "scenario", "container"])["cpu_percent"].max().reset_index(name="peak_cpu")
    stats = (
        per_run.groupby(["scenario", "container"])["peak_cpu"]
        .agg(["mean", "std", "count"])
        .reset_index()
    )
    stats["ci95"] = stats["std"].fillna(0) * 1.96 / stats["count"].pow(0.5)
    scenarios = ["tidb_uniform", "tidb_hot70", "tidb_hot90"]
    pivot = stats.pivot(index="scenario", columns="container", values="mean").reindex(index=scenarios)
    ci = stats.pivot(index="scenario", columns="container", values="ci95").reindex(index=scenarios).fillna(0)
    plt.figure(figsize=(9.5, 5.2))
    x = range(len(pivot.index))
    width = 0.24
    colors = ["#4C78A8", "#59A14F", "#F28E2B"]
    for idx, container in enumerate(pivot.columns):
        plt.bar(
            [pos + (idx - 1) * width for pos in x],
            pivot[container].values,
            width=width,
            yerr=clipped_yerr(pivot[container], ci[container]),
            capsize=4,
            label=node_label(container),
            color=colors[idx % len(colors)],
        )
    plt.xticks(list(x), ["均匀流量", "70% 目标流量", "90% 目标流量"])
    plt.ylabel("峰值 CPU(%)")
    plt.xlabel("流量场景")
    plt.title("TiDB 目标流量下的 TiKV 节点负载（误差线为95%置信区间）")
    plt.legend(title="节点", loc="upper left", bbox_to_anchor=(1.01, 1.0), borderaxespad=0)
    plt.tight_layout()
    plt.savefig(output, dpi=180)
    plt.close()


def render_exp2_recovery_figure(df: pd.DataFrame, output: Path) -> None:
    if df.empty:
        return
    fig, ax = plt.subplots(figsize=(9.8, 5.4))
    draw_exp2_p99_curve_axis(ax, df, "TiDB Leader 短时扰动前后成功请求 P99 延迟曲线")
    ax.legend(title="场景", loc="upper left", bbox_to_anchor=(1.01, 1.0), borderaxespad=0)
    fig.tight_layout()
    fig.savefig(output, dpi=180)
    plt.close(fig)


def render_exp2_multiplot(requests: pd.DataFrame, resources: pd.DataFrame, output: Path) -> None:
    if requests.empty:
        return
    requests = ensure_run_id(requests).copy()
    scenarios = ["leader_cpu_stress", "leader_network_perturbation", "leader_cpu_stress_limited"]
    phases = ["normal", "perturbation", "recovery"]
    scenario_labels = [EXP2_SCENARIO_LABELS[scenario].replace("Leader", "") for scenario in scenarios]
    colors = {"normal": "#4C78A8", "perturbation": "#C94C4C", "recovery": "#59A14F"}

    rows: List[Dict[str, object]] = []
    for (run_id, scenario, phase), group in requests.groupby(["run_id", "scenario", "phase"], sort=False):
        if scenario == "baseline":
            continue
        duration = phase_duration(group)
        success = group[group["success"] == True]  # noqa: E712
        p99 = success["latency_ms"].astype(float).quantile(0.99) if not success.empty else math.nan
        rows.append(
            {
                "run_id": run_id,
                "scenario": scenario,
                "phase": phase,
                "success_qps": len(success) / duration,
                "success_p99_latency_ms": p99,
            }
        )
    metric_df = pd.DataFrame(rows)
    metric_stats = exp2_plot_stats(metric_df, ["scenario", "phase"])

    cpu_stats = pd.DataFrame()
    if not resources.empty:
        res = ensure_run_id(resources).copy()
        if "is_target_leader" in res.columns:
            res = res[res["is_target_leader"] == True]  # noqa: E712
        res = res[res["scenario"].isin(scenarios)]
        cpu_rows = (
            res.groupby(["run_id", "scenario", "phase"])["cpu_percent"]
            .max()
            .reset_index(name="target_peak_cpu_pct")
        )
        cpu_stats = exp2_plot_stats(cpu_rows, ["scenario", "phase"])

    fig, axes = plt.subplots(2, 2, figsize=(12.2, 8.0))
    fig.suptitle("实验二：TiDB Leader 扰动可用性与恢复组图（n=5，误差线为95%置信区间）", fontsize=13)
    draw_exp2_phase_bars(
        axes[0, 0],
        metric_stats,
        scenarios,
        phases,
        "success_qps",
        "成功吞吐量(请求/秒)",
        "A. 成功吞吐量变化",
        scenario_labels,
        colors,
    )
    draw_exp2_phase_bars(
        axes[0, 1],
        metric_stats,
        scenarios,
        phases,
        "success_p99_latency_ms",
        "成功请求P99延迟(ms)",
        "B. 成功请求尾延迟",
        scenario_labels,
        colors,
        annotate_missing=True,
    )
    draw_exp2_phase_bars(
        axes[1, 0],
        cpu_stats,
        scenarios,
        phases,
        "target_peak_cpu_pct",
        "目标TiKV峰值CPU(%)",
        "C. 目标Leader节点资源压力",
        scenario_labels,
        colors,
    )
    draw_exp2_p99_curve_axis(axes[1, 1], requests, "D. 成功请求P99延迟恢复曲线", legend=False)
    handles, labels = axes[0, 0].get_legend_handles_labels()
    line_handles, line_labels = axes[1, 1].get_legend_handles_labels()
    fig.legend(handles, labels, title="阶段", loc="upper center", bbox_to_anchor=(0.35, 0.965), ncol=3)
    fig.legend(line_handles, line_labels, title="曲线场景", loc="upper center", bbox_to_anchor=(0.76, 0.965), ncol=2)
    fig.tight_layout(rect=[0, 0, 1, 0.93])
    fig.savefig(output, dpi=180)
    plt.close(fig)


def draw_exp2_p99_curve_axis(ax, df: pd.DataFrame, title: str, legend: bool = True) -> None:
    if df.empty:
        ax.text(0.5, 0.5, "无数据", transform=ax.transAxes, ha="center", va="center")
        ax.set_title(title)
        return
    df = ensure_run_id(df).copy()
    successful = df[df["success"] == True].copy()  # noqa: E712
    if not successful.empty:
        df = successful
    df["second_bin"] = df["relative_s"].astype(float).floordiv(1).astype(int)
    per_run = (
        df.groupby(["run_id", "scenario", "second_bin"])["latency_ms"]
        .quantile(0.99)
        .reset_index(name="p99_latency_ms")
    )
    stats = per_run.groupby(["scenario", "second_bin"])["p99_latency_ms"].agg(["mean", "std", "count"]).reset_index()
    stats["ci95"] = stats["std"].fillna(0) * 1.96 / stats["count"].pow(0.5)
    baseline_s = float(df["baseline_s"].dropna().iloc[0]) if "baseline_s" in df.columns else 4.0
    perturb_s = float(df["perturb_s"].dropna().iloc[0]) if "perturb_s" in df.columns else 6.0
    scenarios = ["baseline", "leader_cpu_stress", "leader_network_perturbation", "leader_cpu_stress_limited"]
    colors = {
        "baseline": "#4C78A8",
        "leader_cpu_stress": "#C94C4C",
        "leader_network_perturbation": "#F28E2B",
        "leader_cpu_stress_limited": "#59A14F",
    }
    ax.axvspan(baseline_s, baseline_s + perturb_s, color="#9E9E9E", alpha=0.18)
    for scenario in scenarios:
        subset = stats[stats["scenario"] == scenario].sort_values("second_bin")
        if subset.empty:
            continue
        x = subset["second_bin"].astype(float)
        mean = subset["mean"].astype(float)
        ci = subset["ci95"].fillna(0).astype(float)
        ax.plot(x, mean, label=EXP2_SCENARIO_LABELS.get(scenario, scenario), color=colors.get(scenario), linewidth=2)
        ax.fill_between(x, (mean - ci).clip(lower=0), mean + ci, color=colors.get(scenario), alpha=0.12)
    ax.axvline(baseline_s, color="#555555", linewidth=1, linestyle="--")
    ax.axvline(baseline_s + perturb_s, color="#555555", linewidth=1, linestyle="--")
    ax.set_xlabel("短时故障注入相对时间(s)")
    ax.set_ylabel("成功请求P99延迟(ms)")
    ax.set_title(title)
    ax.grid(alpha=0.25)
    if legend:
        ax.legend(title="场景", fontsize=8, title_fontsize=9)


def exp2_plot_stats(df: pd.DataFrame, group_cols: List[str]) -> pd.DataFrame:
    if df.empty:
        return df
    numeric_cols = [
        column
        for column in df.columns
        if column not in set(group_cols + ["run_id"]) and pd.api.types.is_numeric_dtype(df[column])
    ]
    rows: List[Dict[str, object]] = []
    for keys, group in df.groupby(group_cols, sort=False):
        if not isinstance(keys, tuple):
            keys = (keys,)
        row: Dict[str, object] = dict(zip(group_cols, keys))
        for column in numeric_cols:
            values = group[column].dropna().astype(float)
            row[column] = values.mean() if not values.empty else math.nan
            std = values.std(ddof=1) if len(values) > 1 else 0.0
            row[f"{column}_ci95"] = 1.96 * std / math.sqrt(len(values)) if len(values) > 1 else 0.0
        rows.append(row)
    return pd.DataFrame(rows)


def draw_exp2_phase_bars(
    ax,
    stats: pd.DataFrame,
    scenarios: List[str],
    phases: List[str],
    metric: str,
    ylabel: str,
    title: str,
    scenario_labels: List[str],
    colors: Dict[str, str],
    annotate_missing: bool = False,
) -> None:
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    if stats.empty or metric not in stats.columns:
        ax.text(0.5, 0.5, "无数据", transform=ax.transAxes, ha="center", va="center")
        ax.set_xticks(range(len(scenarios)), scenario_labels, rotation=12, ha="right")
        return
    data = stats.set_index(["scenario", "phase"])
    x = list(range(len(scenarios)))
    width = 0.24
    ymax = 0.0
    for idx, phase in enumerate(phases):
        means = []
        errs = []
        for scenario in scenarios:
            if (scenario, phase) in data.index:
                mean = data.loc[(scenario, phase), metric]
                ci = data.loc[(scenario, phase), f"{metric}_ci95"] if f"{metric}_ci95" in data.columns else 0.0
            else:
                mean = math.nan
                ci = 0.0
            means.append(mean)
            errs.append(0.0 if pd.isna(ci) else float(ci))
            if not pd.isna(mean):
                ymax = max(ymax, float(mean + (0.0 if pd.isna(ci) else ci)))
        positions = [pos + (idx - 1) * width for pos in x]
        bars = ax.bar(
            positions,
            [0 if pd.isna(value) else value for value in means],
            width=width,
            yerr=errs,
            capsize=3,
            color=colors[phase],
            label=EXP2_PHASE_LABELS[phase],
            alpha=0.92,
        )
        for bar, value in zip(bars, means):
            if pd.isna(value):
                if annotate_missing:
                    ax.text(bar.get_x() + bar.get_width() / 2, 0, "无成功", ha="center", va="bottom", fontsize=8, rotation=90)
                continue
            if value == 0:
                ax.text(bar.get_x() + bar.get_width() / 2, 0, "0", ha="center", va="bottom", fontsize=8)
    ax.set_xticks(x, scenario_labels, rotation=12, ha="right")
    ax.grid(axis="y", alpha=0.25)
    ax.set_ylim(bottom=0, top=max(ymax * 1.18, 1.0))


def render_exp3_figure(summary: pd.DataFrame, output: Path) -> None:
    if summary.empty:
        return
    data = summary.set_index("defense").reindex(EXP3_DEFENSE_ORDER).dropna(how="all")
    x = range(len(data.index))
    labels = [EXP3_DEFENSE_LABELS.get(item, item) for item in data.index]

    fig, axes = plt.subplots(2, 2, figsize=(12.4, 8.4))
    fig.suptitle("实验三：跨分片抢占式提交与防御代价组图（n=5，误差线为95%置信区间）", fontsize=13)
    front = data["front_run_success_pct"].astype(float)
    front_ci = data["front_run_success_pct_ci95"].fillna(0).astype(float)
    bars = axes[0, 0].bar(
        list(x),
        front.values,
        yerr=clipped_yerr(front, front_ci),
        capsize=4,
        color="#C94C4C",
    )
    axes[0, 0].set_title("A. 抢占式提交成功率")
    axes[0, 0].set_ylabel("成功率(%)")
    axes[0, 0].set_xticks(list(x), labels, rotation=18, ha="right")
    axes[0, 0].set_ylim(bottom=0, top=max(front.max() * 1.18, 5))
    annotate_bars(axes[0, 0], bars, front.values, suffix="%")

    width = 0.36
    consistency = data["consistency_violation_pct"].astype(float)
    rollback = data["rollback_rate_pct"].astype(float)
    cons_ci = data["consistency_violation_pct_ci95"].fillna(0).astype(float)
    rollback_ci = data["rollback_rate_pct_ci95"].fillna(0).astype(float)
    bars1 = axes[0, 1].bar(
        [pos - width / 2 for pos in x],
        consistency.values,
        width=width,
        yerr=clipped_yerr(consistency, cons_ci),
        capsize=3,
        color="#F28E2B",
        label="一致性违规率",
    )
    bars2 = axes[0, 1].bar(
        [pos + width / 2 for pos in x],
        rollback.values,
        width=width,
        yerr=clipped_yerr(rollback, rollback_ci),
        capsize=3,
        color="#4C78A8",
        label="事务回滚率",
    )
    axes[0, 1].set_title("B. 违规与回滚")
    axes[0, 1].set_ylabel("比例(%)")
    axes[0, 1].set_xticks(list(x), labels, rotation=18, ha="right")
    axes[0, 1].legend()
    axes[0, 1].set_ylim(bottom=0, top=max(float(max(consistency.max(), rollback.max())) * 1.22, 5))
    annotate_bars(axes[0, 1], bars1, consistency.values, suffix="%")
    annotate_bars(axes[0, 1], bars2, rollback.values, suffix="%")

    throughput = data["throughput_txn_s"].astype(float)
    throughput_ci = data["throughput_txn_s_ci95"].fillna(0).astype(float)
    bars = axes[1, 0].bar(
        list(x),
        throughput.values,
        yerr=clipped_yerr(throughput, throughput_ci),
        capsize=4,
        color="#59A14F",
    )
    axes[1, 0].set_title("C. 事务吞吐量")
    axes[1, 0].set_ylabel("吞吐量(事务/秒)")
    axes[1, 0].set_xticks(list(x), labels, rotation=18, ha="right")
    axes[1, 0].set_ylim(bottom=0, top=max(throughput.max() * 1.18, 1))
    annotate_bars(axes[1, 0], bars, throughput.values, fmt_str="{:.0f}")

    overhead = data["p95_latency_overhead_pct"].astype(float)
    overhead_ci = data["p95_latency_overhead_pct_ci95"].fillna(0).astype(float)
    colors = ["#9E9E9E" if value < 0 else "#4C78A8" for value in overhead.values]
    bars = axes[1, 1].bar(
        list(x),
        overhead.values,
        yerr=overhead_ci.values,
        capsize=4,
        color=colors,
    )
    axes[1, 1].axhline(0, color="#333333", linewidth=1)
    axes[1, 1].set_title("D. P95延迟开销")
    axes[1, 1].set_ylabel("相对无防御变化(%)")
    axes[1, 1].set_xticks(list(x), labels, rotation=18, ha="right")
    annotate_bars(axes[1, 1], bars, overhead.values, suffix="%")
    for ax in axes.flat:
        ax.grid(axis="y", alpha=0.25)
    fig.tight_layout(rect=[0, 0, 1, 0.96])
    fig.savefig(output, dpi=180)
    plt.close(fig)


def annotate_bars(ax, bars, values, suffix: str = "", fmt_str: str = "{:.1f}") -> None:
    ymin, ymax = ax.get_ylim()
    span = ymax - ymin
    for bar, value in zip(bars, values):
        try:
            value_f = float(value)
        except Exception:
            continue
        if pd.isna(value_f):
            continue
        label = f"{fmt_str.format(value_f)}{suffix}"
        offset = span * 0.015
        va = "bottom"
        y = value_f + offset
        if value_f < 0:
            va = "top"
            y = value_f - offset
        if abs(value_f) < 1e-9:
            y = 0 + offset
            va = "bottom"
            label = f"0{suffix}"
        ax.text(bar.get_x() + bar.get_width() / 2, y, label, ha="center", va=va, fontsize=8)


def render_citus_worker_figure(df: pd.DataFrame, output: Path) -> None:
    if df.empty:
        return
    df = ensure_run_id(df)
    per_run = df.groupby(["run_id", "scenario", "container"])["cpu_percent"].max().reset_index(name="peak_cpu")
    stats = (
        per_run.groupby(["scenario", "container"])["peak_cpu"]
        .agg(["mean", "std", "count"])
        .reset_index()
    )
    stats["ci95"] = stats["std"].fillna(0) * 1.96 / stats["count"].pow(0.5)
    scenarios = ["citus_uniform", "citus_hot70", "citus_hot90"]
    pivot = stats.pivot(index="scenario", columns="container", values="mean").reindex(index=scenarios)
    ci = stats.pivot(index="scenario", columns="container", values="ci95").reindex(index=scenarios).fillna(0)
    plt.figure(figsize=(9.5, 5.2))
    x = range(len(pivot.index))
    width = 0.20
    colors = ["#4C78A8", "#59A14F", "#F28E2B", "#C94C4C"]
    for idx, container in enumerate(pivot.columns):
        plt.bar(
            [pos + (idx - 1.5) * width for pos in x],
            pivot[container].values,
            width=width,
            yerr=clipped_yerr(pivot[container], ci[container]),
            capsize=4,
            label=node_label(container),
            color=colors[idx % len(colors)],
        )
    plt.xticks(list(x), ["均匀流量", "70% 目标流量", "90% 目标流量"])
    plt.ylabel("峰值 CPU(%)")
    plt.xlabel("流量场景")
    plt.title("PostgreSQL+Citus 目标流量下的节点负载（误差线为95%置信区间）")
    plt.legend(title="节点", loc="upper left", bbox_to_anchor=(1.01, 1.0), borderaxespad=0)
    plt.tight_layout()
    plt.savefig(output, dpi=180)
    plt.close()


def render_paper_text(
    summary: pd.DataFrame,
    citus_summary: pd.DataFrame,
    citus_resource_summary: pd.DataFrame,
    citus_placement_summary: pd.DataFrame,
    tidb_summary: pd.DataFrame,
    tidb_resource_summary: pd.DataFrame,
    tidb_region_summary: pd.DataFrame,
    exp2_summary: pd.DataFrame,
    exp2_resource_summary: pd.DataFrame,
    exp3_summary: pd.DataFrame,
) -> str:
    lookup = summary.set_index(["scenario", "defense"])

    def v(scenario: str, defense: str, column: str) -> float:
        return float(lookup.loc[(scenario, defense), column])

    det_p99 = v("hot90", "deterministic", "p99_latency_ms")
    obf_p99 = v("hot90", "obfuscated", "p99_latency_ms")
    det_ratio = v("hot90", "deterministic", "hot_physical_load_ratio")
    obf_ratio = v("hot90", "obfuscated", "hot_physical_load_ratio")
    control_ratio = v("hot90", "obfuscated_control", "hot_physical_load_ratio")
    control_fail = v("hot90", "obfuscated_control", "failure_rate_pct")
    det70_ratio = v("hot70", "deterministic", "hot_physical_load_ratio")
    obf70_ratio = v("hot70", "obfuscated", "hot_physical_load_ratio")
    uniform_obf_qps = v("uniform", "obfuscated", "uniform_qps_overhead_pct")
    uniform_obf_p95 = v("uniform", "obfuscated", "uniform_p95_overhead_pct")

    citus_text = "PostgreSQL+Citus 扩展对照实验尚未生成结果；本节先保留脚本和表结构，待镜像与资源就绪后补充实测值。"
    if not citus_summary.empty:
        citus_lookup = citus_summary.set_index("scenario")
        citus_uniform_p99 = float(citus_lookup.loc["citus_uniform", "p99_latency_ms"])
        citus_hot90_p99 = float(citus_lookup.loc["citus_hot90", "p99_latency_ms"])
        citus_hot90_qps = float(citus_lookup.loc["citus_hot90", "qps"])
        citus_hot90_fail = float(citus_lookup.loc["citus_hot90", "failure_rate_pct"])
        placement_text = "未获取到热点分片放置观测"
        if not citus_placement_summary.empty:
            placement_lookup = citus_placement_summary.set_index("scenario")
            if "citus_hot90" in placement_lookup.index:
                placement_text = (
                    f"90% 目标流量后观测到 {fmt_count(placement_lookup.loc['citus_hot90', 'shard_count'])} 个 Citus 逻辑分片，"
                    f"对应热点分片所在工作节点为 {node_list_label(placement_lookup.loc['citus_hot90', 'hotspot_worker'])}"
                )
        citus_resource_text = ""
        if not citus_resource_summary.empty:
            hot90_resource = citus_resource_summary[citus_resource_summary["scenario"] == "citus_hot90"]
            if not hot90_resource.empty:
                peak = hot90_resource.sort_values("max_cpu_percent", ascending=False).iloc[0]
                citus_resource_text = (
                    f"热点期间 PostgreSQL+Citus 峰值 CPU 最高节点为 {node_label(peak['container'])}，"
                    f"峰值为 {float(peak['max_cpu_percent']):.2f}%。"
                )
        citus_text = (
            f"PostgreSQL+Citus 对照使用 1 个协调节点与 3 个工作节点，"
            f"通过 Citus 扩展将 `citus_items` 和 `citus_events` 按 `item_id` 分布式分片。"
            f"在 Citus 原生分布式执行路径下，均匀流量 P99 延迟为 {citus_uniform_p99:.2f} ms，"
            f"90% 目标流量 P99 延迟为 {citus_hot90_p99:.2f} ms，吞吐量为 {citus_hot90_qps:.2f} 请求/秒，"
            f"失败率为 {citus_hot90_fail:.2f}%。{placement_text}。{citus_resource_text}"
        )

    tidb_text = "TiDB 对照实验尚未生成结果；本节仅报告 PostgreSQL 三分片机制模拟与 PostgreSQL+Citus 扩展对照。"
    if not tidb_summary.empty:
        tidb_lookup = tidb_summary.set_index("scenario")
        tidb_uniform_p99 = float(tidb_lookup.loc["tidb_uniform", "p99_latency_ms"])
        tidb_hot90_p99 = float(tidb_lookup.loc["tidb_hot90", "p99_latency_ms"])
        tidb_hot90_qps = float(tidb_lookup.loc["tidb_hot90", "qps"])
        leader_text = "未获取到 Leader 存储节点观测"
        if not tidb_region_summary.empty:
            region_lookup = tidb_region_summary.set_index("scenario")
            if "tidb_hot90" in region_lookup.index:
                leader_text = (
                    f"90% 目标流量后观测到 {fmt_count(region_lookup.loc['tidb_hot90', 'observed_regions'])} 个表 Region，"
                    f"Leader 存储节点 ID 为 {region_lookup.loc['tidb_hot90', 'leader_store_ids']}"
                )
        tikv_text = ""
        if not tidb_resource_summary.empty:
            hot90_resource = tidb_resource_summary[tidb_resource_summary["scenario"] == "tidb_hot90"]
            if not hot90_resource.empty:
                peak = hot90_resource.sort_values("max_cpu_percent", ascending=False).iloc[0]
                tikv_text = f"热点期间 TiKV 峰值 CPU 最高节点为 {node_label(peak['container'])}，峰值为 {float(peak['max_cpu_percent']):.2f}%。"
        tidb_text = (
            f"TiDB 对照实验使用 1 个 TiDB Server、3 个 TiKV 和 3 个 PD，"
            f"通过 `SPLIT TABLE` 将测试表拆分为多个 Region；本次环境中 `SCATTER TABLE` 语句未被当前 TiDB 语法接受，"
            f"因此以实际采集到的 Region/Leader 分布作为对照观测。"
            f"在 TiDB 原生调度下，均匀流量 P99 延迟为 {tidb_uniform_p99:.2f} ms，"
            f"90% 目标流量 P99 延迟为 {tidb_hot90_p99:.2f} ms，吞吐量为 {tidb_hot90_qps:.2f} 请求/秒。"
            f"{leader_text}。{tikv_text}"
        )

    exp2_text = ""
    if not exp2_summary.empty:
        exp2_lookup = exp2_summary.set_index("scenario")

        def e(scenario: str, column: str) -> float:
            return float(exp2_lookup.loc[scenario, column])

        cpu_drop = e("leader_cpu_stress", "throughput_drop_pct") if "leader_cpu_stress" in exp2_lookup.index else math.nan
        cpu_normal_p99 = e("leader_cpu_stress", "normal_p99_latency_ms") if "leader_cpu_stress" in exp2_lookup.index else math.nan
        cpu_perturb_p99 = e("leader_cpu_stress", "perturb_p99_latency_ms") if "leader_cpu_stress" in exp2_lookup.index else math.nan
        cpu_recovery_time = e("leader_cpu_stress", "recovery_time_s") if "leader_cpu_stress" in exp2_lookup.index else math.nan
        network_drop = (
            e("leader_network_perturbation", "throughput_drop_pct")
            if "leader_network_perturbation" in exp2_lookup.index
            else math.nan
        )
        network_fail = (
            e("leader_network_perturbation", "perturb_failure_rate_pct")
            if "leader_network_perturbation" in exp2_lookup.index
            else math.nan
        )
        network_recovery_time = (
            e("leader_network_perturbation", "recovery_time_s")
            if "leader_network_perturbation" in exp2_lookup.index
            else math.nan
        )
        limited_drop = (
            e("leader_cpu_stress_limited", "throughput_drop_pct")
            if "leader_cpu_stress_limited" in exp2_lookup.index
            else math.nan
        )
        limited_p99 = (
            e("leader_cpu_stress_limited", "perturb_p99_latency_ms")
            if "leader_cpu_stress_limited" in exp2_lookup.index
            else math.nan
        )
        limited_recovery_time = (
            e("leader_cpu_stress_limited", "recovery_time_s")
            if "leader_cpu_stress_limited" in exp2_lookup.index
            else math.nan
        )
        peak_text = ""
        if not exp2_resource_summary.empty:
            target_samples = exp2_resource_summary[
                (exp2_resource_summary["scenario"] == "leader_cpu_stress")
                & (exp2_resource_summary["phase"] == "perturbation")
            ]
            if not target_samples.empty:
                peak = target_samples.sort_values("max_cpu_percent", ascending=False).iloc[0]
                peak_text = (
                    f"扰动期 TiKV 峰值 CPU 最高节点为 {node_label(peak['container'])}，"
                    f"峰值为 {float(peak['max_cpu_percent']):.2f}%。"
                )
        exp2_text = f"""
## 实验二：TiDB Leader 压力/节点暂停下的可用性与恢复评估

### 实验动机与设计

第2章指出，基于 Leader 的共识复制和副本调度机制是分布式数据库区别于单机数据库的重要安全边界。为避免将受控实验表述为产品漏洞复现，本文将实验二定位为“共识 Leader 节点压力与节点暂停下的可用性评估”。实验使用同一 TiDB 集群，通过 `SHOW TABLE ... REGIONS` 定位热点键所在 Region 的初始 Leader Store，并由 PD API 映射到具体 TiKV 容器。随后在正常基线、Leader CPU 压力、Leader 所在 TiKV 节点暂停以及 CPU 压力下应用侧限流四组场景中运行相同读写混合负载，记录正常期、扰动期和恢复期的吞吐量、成功请求平均延迟、成功请求 P95/P99 延迟、失败率、TiKV CPU/内存和恢复时间，并保留 Leader 位置变化作为补充观测。节点暂停组通过 `docker pause` 短时暂停目标 TiKV 容器，未采用网络时延或丢包注入。每组场景独立重复运行 5 次。实验二组图包含成功吞吐量、成功请求 P99 延迟、目标 TiKV 峰值 CPU 和短时扰动 P99 恢复曲线四个子图；柱状图误差线和折线图阴影均表示 95% 置信区间。需要强调的是，本实验采用秒级短时故障注入窗口，用于观察受控容器集群的可用性退化和恢复趋势，不将该时间尺度解释为生产数据库的恢复 SLA。

### 结果与分析

在 Leader CPU 压力组中，扰动期成功吞吐量相对正常期下降 {cpu_drop:.2f}%，成功请求 P99 延迟由 {cpu_normal_p99:.2f} ms 上升到 {cpu_perturb_p99:.2f} ms，恢复到正常期 90% 吞吐且成功请求 P99 不高于正常期 110% 的时间为 {cpu_recovery_time:.2f} s。Leader 所在 TiKV 节点暂停组的成功吞吐量下降 {network_drop:.2f}%，扰动期失败率为 {network_fail:.2f}%，恢复时间为 {network_recovery_time:.2f} s。应用侧限流组在相同 CPU 压力下注入下的成功吞吐量下降为 {limited_drop:.2f}%，扰动期成功请求 P99 延迟为 {limited_p99:.2f} ms，恢复时间为 {limited_recovery_time:.2f} s，说明限流能够降低部分尾延迟压力，但会以主动压低吞吐作为代价。{peak_text}

该结果表明，Leader 所在节点遭遇资源压力或短时暂停时，即使请求本身仍是合法 SQL，系统可用性也会出现可观退化；客户端限流和集群恢复机制可以缓解部分影响，但恢复过程存在非零时间窗口。因此，分布式数据库安全评估不能只覆盖应用层注入或认证问题，也需要纳入共识层和调度层韧性指标。
"""

    exp3_text = ""
    if not exp3_summary.empty:
        exp3_lookup = exp3_summary.set_index("defense")
        missing_defenses = [defense for defense in EXP3_DEFENSE_ORDER if defense not in exp3_lookup.index]
        if missing_defenses:
            available = "、".join(EXP3_DEFENSE_LABELS.get(str(value), str(value)) for value in exp3_lookup.index)
            missing = "、".join(EXP3_DEFENSE_LABELS.get(value, value) for value in missing_defenses)
            exp3_text = f"""
## 实验三：跨分片事务异步窗口下的抢占式提交模拟

当前跨分片事务异步窗口实验已生成部分结果，已包含策略为 {available}；尚缺少 {missing} 的完整重复实验结果。因此，本文暂不基于该组不完整数据展开定量结论，完整结果补齐后再并入正文分析。
"""
        else:

            def c(defense: str, column: str) -> float:
                return float(exp3_lookup.loc[defense, column])

            baseline_front = c("baseline", "front_run_success_pct")
            baseline_violation = c("baseline", "consistency_violation_pct")
            global_front = c("global_sequence", "front_run_success_pct")
            occ_front = c("occ", "front_run_success_pct")
            queue_front = c("conflict_key_queue", "front_run_success_pct")
            two_pc_front = c("two_phase_commit", "front_run_success_pct")
            global_overhead = c("global_sequence", "p95_latency_overhead_pct")
            occ_rollback = c("occ", "rollback_rate_pct")
            queue_overhead = c("conflict_key_queue", "p95_latency_overhead_pct")
            two_pc_overhead = c("two_phase_commit", "p95_latency_overhead_pct")
            exp3_text = f"""
## 实验三：跨分片事务异步窗口下的抢占式提交模拟

### 实验动机与设计

跨分片事务在用户校验、库存扣减和订单确认之间需要经过多个分片，处理阶段与提交阶段之间天然存在异步窗口。本文使用 PostgreSQL 三分片环境构造可控模拟：shard-0 存放用户资格，shard-1 存放商品库存，shard-2 存放订单确认。每个事务对包含先到达的 `T_victim` 和后到达的 `T_attacker`，其中 `T_victim` 在完成用户资格校验后被人为延迟，`T_attacker` 在该窗口内尝试先完成库存扣减和订单写入。实验比较无防御、全局序列号、版本检查/OCC、冲突键队列化和两阶段提交模拟五组策略。每组策略独立重复运行 5 次，记录抢占式提交成功率、业务顺序违规率、事务回滚率、吞吐量、平均延迟和 P95/P99 延迟。实验三组图包含抢占式提交成功率、违规/回滚比例、事务吞吐量和 P95 延迟开销四个子图，误差线表示 95% 置信区间。

### 结果与分析

无防御组的抢占式提交成功率为 {baseline_front:.2f}%，一致性违规率为 {baseline_violation:.2f}%，说明后到事务可以利用 victim 的异步窗口先完成库存扣减和订单确认，从而形成业务语义层面的顺序反转。全局序列号、版本检查/OCC、冲突键队列化和两阶段提交模拟将抢占式提交成功率分别降至 {global_front:.2f}%、{occ_front:.2f}%、{queue_front:.2f}% 和 {two_pc_front:.2f}%。其中，全局序列号通过在提交阶段按入口顺序放行冲突事务实现顺序约束，P95 延迟开销为 {global_overhead:.2f}%；OCC 通过版本/冲突检查回滚后到事务，事务回滚率为 {occ_rollback:.2f}%；冲突键队列化和两阶段提交模拟分别带来 {queue_overhead:.2f}% 和 {two_pc_overhead:.2f}% 的 P95 延迟开销。该结果说明，跨分片异步窗口风险可以通过全局排序、冲突检测、按键串行化或资源锁定显著缓解，但代价表现为尾延迟上升、回滚率增加或吞吐下降。
"""

    return f"""# 第4章补充实验：分布式架构攻击与防御评估

## 实验动机

第2章将数据分发机制风险列为分布式数据库的重要攻击面，第3章表15将“混淆路由”列为降低攻击者精准命中分片能力的防御思路。与 SQL 注入不同，确定性路由攻击流量通常由合法查询、更新和插入组成，外围 WAF/IDS 很难仅根据语法特征区分其攻击性。为量化该类风险，本文采用“PostgreSQL 三实例机制模拟 + PostgreSQL+Citus 分布式扩展对照 + TiDB 真实分布式数据库对照”的设计：第一部分使用路由层比较公开确定性路由 `item_id mod 3` 与混淆路由 `sha256(secret_salt:item_id)` 虚拟桶映射；第二部分使用 Citus 扩展构造 PostgreSQL 协调节点/工作节点分布式拓扑，作为插件化分布式执行对照；第三部分使用 1 TiDB Server、3 TiKV、3 PD 的小规模集群，作为真实分布式数据库调度对照。

## 实验设计

确定性路由实验在三个独立 PostgreSQL 实例中分别初始化相同的完整 `items` 基础数据，再由 Python 客户端依据路由规则选择目标实例；因此该环境属于应用层路由机制模拟，而非数据库系统实现的真实分片或副本机制。实验设置三种流量分布：均匀流量、70% 目标实例流量、90% 目标实例流量。目标流量不使用单个热点 key，而是由攻击者按公开规则筛选一批 `item_id % 3 == 0` 的 key；在确定性路由下这些请求集中到实例0，在混淆路由下真实映射变为带 secret salt 的哈希虚拟桶并重新分散到3个物理实例。每组请求采用 70% `SELECT`、20% `UPDATE`、10% `INSERT` 的读写混合负载。PostgreSQL 机制模拟比较确定性路由、混淆路由模拟和混淆路由+流量控制三组策略，并记录吞吐量、平均延迟、P95/P99 延迟、失败率、限流率和热点物理负载比；PostgreSQL+Citus 与 TiDB 保留为原生系统对照，记录吞吐量、延迟、失败率和节点资源负载。每个场景和配置均独立重复运行 5 次，正文主表仅报告均值，完整均值±标准差及节点资源采样见补充材料。实验一组图包含 PostgreSQL 物理实例负载、PostgreSQL+Citus 节点峰值 CPU、TiDB TiKV 峰值 CPU 和目标比例升高时 P99 延迟变化四个子图；柱状图误差线和折线图阴影均表示 95% 置信区间。

## 结果与分析

在 90% 目标分片流量下，确定性路由组的热点物理负载比达到 {det_ratio:.2f}，P99 延迟为 {det_p99:.2f} ms，说明攻击者只要知道 `item_id mod 3` 规则，就能用一批正常 key 将压力集中到公开目标分片。混淆路由模拟将同一批目标 key 重新分散，热点物理负载比降至 {obf_ratio:.2f}，P99 延迟为 {obf_p99:.2f} ms；在 70% 目标分片流量下，热点物理负载比也由 {det70_ratio:.2f} 降至 {obf70_ratio:.2f}。混淆路由+流量控制在 90% 目标流量下的热点物理负载比为 {control_ratio:.2f}，限流/失败率为 {control_fail:.2f}%，说明其可以进一步保护过载路径，但代价是主动拒绝部分请求。

在正常均匀流量下，混淆路由模拟的总处理吞吐量变化为 {uniform_obf_qps:.2f}%，P95 延迟变化为 {uniform_obf_p95:.2f}%。这说明混淆路由主要改变 key 到分片的映射关系，本身并不依赖识别异常 SQL；如果叠加流量控制，仍需要结合业务容量校准阈值，避免把正常突发流量误判为攻击流量。

{citus_text}

{tidb_text}

{exp2_text}

{exp3_text}

## 评测边界

需要说明的是，分布式架构级攻击通常与具体系统实现、部署拓扑、共识协议版本及云平台权限模型高度相关。直接复现某一产品级共识漏洞或云基础设施攻击，不仅需要特定历史版本和故障注入条件，也可能引入较高的安全与伦理风险。因此，本实验采用“机制复现 + 插件化分布式 PostgreSQL 对照 + 真实系统对照”的方式进行评估：使用 PostgreSQL 三实例环境抽象复现确定性路由可预测性风险和跨实例事务异步窗口风险，并量化混淆路由、流量控制、全局排序、OCC 和两阶段提交等机制的防御代价；使用 PostgreSQL+Citus 与 TiDB 观察原生分布式执行/调度路径下的热点负载表现；使用 TiDB 集群观察 Leader 所在 TiKV 节点遭遇 CPU 压力或短时暂停时的 Region/Leader、TiKV 负载、可用性退化与恢复过程。该设计并不声称覆盖所有分布式数据库攻击类型，也不声称复现 TiDB 产品级共识漏洞或产品级跨分片事务漏洞，而是用于量化第2章和第3章所讨论的典型架构级风险与防御机制在受控实验条件下的影响边界和代价。
"""


def render_reviewer_response(has_exp2: bool, has_exp3: bool) -> str:
    exp2_sentence = (
        "同时，本文新增“TiDB 共识 Leader 压力/节点暂停下的可用性与恢复评估”，"
        "通过定位热点 Region Leader 所在 TiKV 节点并施加 CPU 压力或短时容器暂停，量化正常期、扰动期和恢复期的吞吐量、尾延迟、失败率和恢复时间，并保留 Leader 位置变化作为补充观测。"
        if has_exp2
        else "TiDB 共识 Leader 压力/节点暂停实验脚本和表结构已补充，待受控环境资源就绪后填入实测结果。"
    )
    exp3_sentence = (
        "此外，本文新增“跨实例事务异步窗口下的抢占式提交模拟”，"
        "将用户资格、商品库存和订单确认分别放置在三个 PostgreSQL 实例中，并比较全局序列号、OCC、冲突键队列化和两阶段提交模拟的防御效果与性能代价。"
        if has_exp3
        else "跨实例事务异步窗口模拟实验脚本和表结构已补充，待受控环境资源就绪后填入实测结果。"
    )
    return (
        "感谢审稿专家指出理论分类与实证评估覆盖度之间的匹配问题。根据该意见，本文在第4章补充了分布式架构级攻击防御评估。"
        "首先，本文新增“确定性路由攻击与混淆路由防御评估”，采用“PostgreSQL 三实例机制模拟 + PostgreSQL+Citus 分布式扩展对照 + TiDB 真实分布式数据库对照”的方式。"
        "三个 PostgreSQL 实例分别初始化相同的完整基础数据，再由客户端根据公开 `item_id mod 3` 规则或混淆路由规则选择目标实例；因此该实验属于应用层路由机制模拟，而非数据库层真实分片。"
        "实验构造均匀流量、70% 目标实例流量和 90% 目标实例流量，目标流量由攻击者按公开规则筛选一批 key，而非单个热点 key。"
        "实验比较确定性路由、混淆路由模拟和混淆路由+流量控制策略，重点报告热点物理负载比、吞吐量和 P99 延迟，以对应第3章表15中的混淆路由防御思想。"
        f"{exp2_sentence}{exp3_sentence}"
        "每个场景和配置均独立重复运行 5 次，正文主表仅报告均值，完整均值±标准差及节点资源采样见补充材料，图中使用 95% 置信区间标注波动。\n\n"
        "考虑到真实共识实现漏洞、DBaaS 元数据攻击和产品级跨分片事务问题高度依赖特定系统版本、云平台权限模型和故障注入条件，"
        "本文采用可控仿真环境、PostgreSQL 分布式扩展与真实分布式数据库对照相结合的方式，明确限定评测边界，"
        "避免将实验结论泛化为对所有分布式数据库产品的安全性判断，也避免将 TiDB 可用性扰动实验表述为产品漏洞复现。"
    )


if __name__ == "__main__":
    raise SystemExit(main())
