#!/usr/bin/env python3
"""Render distributed architecture risk and defense figures as 1x2 panels."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import matplotlib.pyplot as plt
from matplotlib import colors as mcolors
from matplotlib import patches
import pandas as pd

import analyze_results as ar


ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = ROOT / "results" / "raw"
FIGURE_DIR = ROOT / "results" / "figures"
OUTPUTS = {
    "shard_flooding": FIGURE_DIR / "fig9_shard_flooding.png",
    "tidb_leader": FIGURE_DIR / "fig10_tidb_leader.png",
    "cross_shard_tx": FIGURE_DIR / "fig11_cross_shard_tx.png",
}
PALETTE = {
    "red": "#C94C4C",
    "blue": "#4C78A8",
    "orange": "#F28E2B",
    "green": "#59A14F",
    "gray": "#9E9E9E",
}
SERIES_COLORS = {
    "PostgreSQL确定性路由": PALETTE["red"],
    "PostgreSQL混淆路由": PALETTE["blue"],
    "PostgreSQL+Citus": PALETTE["orange"],
    "TiDB": PALETTE["green"],
}
EXP2_SCENARIO_COLORS = {
    "baseline": PALETTE["blue"],
    "leader_cpu_stress": PALETTE["red"],
    "leader_network_perturbation": PALETTE["orange"],
    "leader_cpu_stress_limited": PALETTE["green"],
}
EXP2_FIGURE_SCENARIO_LABELS = {
    **ar.EXP2_SCENARIO_LABELS,
    "leader_network_perturbation": "目标TiKV节点暂停",
}
EXP3_DEFENSE_COLORS = {
    "baseline": PALETTE["red"],
    "global_sequence": PALETTE["blue"],
    "occ": PALETTE["orange"],
    "conflict_key_queue": PALETTE["green"],
    "two_phase_commit": PALETTE["gray"],
}


def main() -> int:
    ar.configure_chinese_font()
    configure_style()
    FIGURE_DIR.mkdir(parents=True, exist_ok=True)

    exp1_requests = read_csv("exp1_single_shard_flood_requests.csv")
    citus_requests = read_csv("exp1_citus_hotspot_requests.csv")
    tidb_requests = read_csv("exp1_tidb_hotspot_requests.csv")
    exp2_requests = read_csv("exp2_tidb_leader_requests.csv", low_memory=False)
    exp3_summary = load_exp3_summary()

    render_panel_pair(
        OUTPUTS["shard_flooding"],
        lambda axes: (
            draw_panel_a(axes[0], exp1_requests),
            draw_panel_b(axes[1], exp1_requests, citus_requests, tidb_requests),
        ),
    )
    render_panel_pair(
        OUTPUTS["tidb_leader"],
        lambda axes: (
            draw_panel_c(axes[0], exp2_requests),
            draw_panel_d(axes[1], exp2_requests),
        ),
    )
    render_panel_pair(
        OUTPUTS["cross_shard_tx"],
        lambda axes: (
            draw_panel_e(axes[0], exp3_summary),
            draw_panel_f(axes[1], exp3_summary),
        ),
    )
    return 0


def render_panel_pair(output: Path, draw_pair) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(12.6, 5.3), constrained_layout=True)
    draw_pair(axes)
    relabel_panel_titles(axes)
    fig.savefig(output, dpi=300)
    plt.close(fig)
    print(f"[split-figure] wrote {output}")


def relabel_panel_titles(axes) -> None:
    for label, ax in zip(("a)", "b)"), axes):
        title = ax.get_title()
        if len(title) >= 2 and title[0].isalpha() and title[1] == ")":
            title = f"{label}{title[2:]}"
        else:
            title = f"{label} {title}"
        ax.set_title(title)


def configure_style() -> None:
    plt.rcParams.update(
        {
            "font.size": 14.6,
            "axes.titlesize": 16.8,
            "axes.labelsize": 14.6,
            "legend.fontsize": 12.0,
            "legend.title_fontsize": 13.0,
            "xtick.labelsize": 13.2,
            "ytick.labelsize": 13.2,
            "axes.unicode_minus": False,
        }
    )


def read_csv(filename: str, **kwargs) -> pd.DataFrame:
    path = RAW_DIR / filename
    if not path.exists():
        return pd.DataFrame()
    return pd.read_csv(path, **kwargs)


def load_exp3_summary() -> pd.DataFrame:
    transactions = read_csv("exp3_cross_shard_transactions.csv")
    pairs = read_csv("exp3_cross_shard_pairs.csv")
    if transactions.empty or pairs.empty:
        return pd.DataFrame()
    return ar.summarize_exp3(transactions, pairs)


def draw_panel_a(ax, requests: pd.DataFrame) -> None:
    data = exp1_shard_load_by_run(requests)
    if data.empty:
        ax.text(0.5, 0.5, "无数据", transform=ax.transAxes, ha="center", va="center")
        ax.set_title("a) 单分片泛洪模拟下的实例负载分布")
        return
    data = data.copy()
    data["series"] = data["series"].replace(
        {"分片0": "实例0", "分片1": "实例1", "分片2": "实例2"}
    )
    draw_grouped_bar_boxplot(
        ax,
        data,
        groups=["确定性路由", "混淆路由模拟", "混淆路由+流量控制"],
        series=["实例0", "实例1", "实例2"],
        colors={"实例0": PALETTE["red"], "实例1": PALETTE["blue"], "实例2": PALETTE["green"]},
        title="a) 单分片泛洪模拟下的实例负载分布",
        xlabel="路由/防御策略",
        ylabel="各实例接收请求数",
        legend_title="PostgreSQL实例",
        legend_loc="upper right",
        x_rotation=0,
        y_pad=0.12,
    )


def draw_grouped_bar_boxplot(
    ax,
    data: pd.DataFrame,
    groups: List[object],
    series: List[str],
    colors: Dict[str, str],
    title: str,
    xlabel: str,
    ylabel: str,
    legend_title: str | None = None,
    legend_loc: str = "upper left",
    legend_ncol: int = 1,
    x_rotation: float = 0,
    y_pad: float = 0.12,
) -> None:
    x = list(range(len(groups)))
    width = min(0.74 / max(len(series), 1), 0.22)
    offsets = [(idx - (len(series) - 1) / 2) * width for idx in range(len(series))]
    max_y = 0.0

    for idx, label in enumerate(series):
        positions = [pos + offsets[idx] for pos in x]
        means = []
        cis = []
        distributions = []
        for group in groups:
            values = data[(data["group"] == group) & (data["series"] == label)]["value"].astype(float)
            distribution = values.tolist() if not values.empty else [0.0]
            distributions.append(distribution)
            mean = float(values.mean()) if not values.empty else 0.0
            std = float(values.std(ddof=1)) if len(values) > 1 else 0.0
            ci = 1.96 * std / (len(values) ** 0.5) if len(values) > 1 else 0.0
            means.append(mean)
            cis.append(ci)
            max_y = max(max_y, max(distribution), mean + ci)

        ax.bar(
            positions,
            means,
            width=width * 0.88,
            yerr=cis,
            capsize=2.5,
            color=colors[label],
            alpha=0.48,
            edgecolor=colors[label],
            linewidth=0.8,
            label=label,
        )
        box = ax.boxplot(
            distributions,
            positions=positions,
            widths=width * 0.52,
            patch_artist=True,
            showfliers=False,
            manage_ticks=False,
            medianprops={"color": colors[label], "linewidth": 1.5},
            boxprops={"facecolor": "white", "edgecolor": colors[label], "linewidth": 1.0, "alpha": 0.92},
            whiskerprops={"color": colors[label], "linewidth": 0.9},
            capprops={"color": colors[label], "linewidth": 0.9},
        )
        for patch in box["boxes"]:
            patch.set_facecolor("white")
            patch.set_alpha(0.92)

    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_xticks(x, [str(group) for group in groups], rotation=x_rotation, ha="right" if x_rotation else "center")
    if max_y > 0:
        ax.set_ylim(bottom=0, top=max_y * (1 + y_pad))
    ax.grid(axis="y", alpha=0.25)
    ax.legend(
        title=legend_title,
        fontsize=12.0,
        title_fontsize=13.0,
        loc=legend_loc,
        ncol=legend_ncol,
        framealpha=0.86,
    )


def exp1_shard_load_by_run(requests: pd.DataFrame) -> pd.DataFrame:
    if requests.empty:
        return pd.DataFrame()
    df = ar.ensure_run_id(requests).copy()
    hot = df[df["scenario"] == "hot90"].copy()
    hot = hot[
        hot["physical_shard"].astype(str).str.startswith("shard-")
        & ~hot["error"].astype(str).isin(ar.RATE_LIMIT_ERRORS)
    ]
    run_ids = sorted(df["run_id"].dropna().unique())
    observed = set(df["defense"].astype(str))
    defenses = [item for item in ["deterministic", "obfuscated", "obfuscated_control"] if item in observed]
    shards = ["shard-0", "shard-1", "shard-2"]
    counts = hot.groupby(["run_id", "defense", "physical_shard"]).size().rename("value")
    full_index = pd.MultiIndex.from_product([run_ids, defenses, shards], names=["run_id", "defense", "physical_shard"])
    per_run = counts.reindex(full_index, fill_value=0).reset_index()
    rows = []
    for _, row in per_run.iterrows():
        rows.append(
            {
                "group": ar.DEFENSE_LABELS.get(str(row["defense"]), str(row["defense"])),
                "series": ar.SHARD_LABELS.get(str(row["physical_shard"]), str(row["physical_shard"])),
                "value": float(row["value"]),
            }
        )
    return pd.DataFrame(rows)


def draw_panel_b(
    ax,
    pg_requests: pd.DataFrame,
    citus_requests: pd.DataFrame,
    tidb_requests: pd.DataFrame,
) -> None:
    data = exp1_p99_by_run(pg_requests, citus_requests, tidb_requests)
    if data.empty:
        ax.text(0.5, 0.5, "无数据", transform=ax.transAxes, ha="center", va="center")
        ax.set_title("b) 目标流量比例升高时 P99 延迟变化")
        return

    plot_data = data.copy()
    plot_data["group"] = plot_data["target_pct"].map(lambda value: f"{int(value)}%")
    plot_data["value"] = plot_data["p99_latency_ms"]
    labels = ["PostgreSQL确定性路由", "PostgreSQL混淆路由", "PostgreSQL+Citus", "TiDB"]
    draw_grouped_bar_boxplot(
        ax,
        plot_data,
        groups=["0%", "70%", "90%"],
        series=labels,
        colors=SERIES_COLORS,
        title="b) 目标流量比例升高时 P99 延迟变化",
        xlabel="目标请求比例(%)",
        ylabel="P99延迟(ms)",
        legend_loc="upper right",
        y_pad=0.22,
    )


def exp1_p99_by_run(
    pg_requests: pd.DataFrame,
    citus_requests: pd.DataFrame,
    tidb_requests: pd.DataFrame,
) -> pd.DataFrame:
    specs = [
        (
            "PostgreSQL确定性路由",
            pg_requests,
            "deterministic",
            {0: "uniform", 70: "hot70", 90: "hot90"},
        ),
        (
            "PostgreSQL混淆路由",
            pg_requests,
            "obfuscated",
            {0: "uniform", 70: "hot70", 90: "hot90"},
        ),
        (
            "PostgreSQL+Citus",
            citus_requests,
            None,
            {0: "citus_uniform", 70: "citus_hot70", 90: "citus_hot90"},
        ),
        (
            "TiDB",
            tidb_requests,
            None,
            {0: "tidb_uniform", 70: "tidb_hot70", 90: "tidb_hot90"},
        ),
    ]
    rows: List[Dict[str, object]] = []
    for label, frame, defense, scenarios in specs:
        if frame.empty:
            continue
        df = ar.ensure_run_id(frame).copy()
        if defense is not None and "defense" in df.columns:
            df = df[df["defense"] == defense]
        if df.empty:
            continue
        for target_pct, scenario in scenarios.items():
            subset = df[df["scenario"] == scenario]
            for run_id, group in subset.groupby("run_id", sort=True):
                if group.empty:
                    continue
                rows.append(
                    {
                        "series": label,
                        "run_id": run_id,
                        "target_pct": target_pct,
                        "p99_latency_ms": float(group["latency_ms"].astype(float).quantile(0.99)),
                    }
                )
    return pd.DataFrame(rows)


def draw_panel_c(ax, requests: pd.DataFrame) -> None:
    data = exp2_success_qps_by_run(requests)
    if data.empty:
        ax.text(0.5, 0.5, "无数据", transform=ax.transAxes, ha="center", va="center")
        ax.set_title("c) TiDB Leader 扰动下成功吞吐量变化")
        return
    draw_grouped_bar_boxplot(
        ax,
        data,
        groups=["CPU压力", "目标TiKV节点暂停", "CPU压力+\n应用侧限流"],
        series=["正常期", "扰动期", "恢复期"],
        colors={"正常期": PALETTE["blue"], "扰动期": PALETTE["red"], "恢复期": PALETTE["green"]},
        title="c) TiDB Leader 扰动下成功吞吐量变化",
        xlabel="扰动场景",
        ylabel="成功吞吐量(请求/秒)",
        legend_title="阶段",
        legend_loc="upper center",
        legend_ncol=3,
        x_rotation=0,
        y_pad=0.14,
    )


def exp2_success_qps_by_run(requests: pd.DataFrame) -> pd.DataFrame:
    if requests.empty:
        return pd.DataFrame()
    requests = ar.ensure_run_id(requests).copy()
    scenario_labels = {
        "leader_cpu_stress": "CPU压力",
        "leader_network_perturbation": "目标TiKV节点暂停",
        "leader_cpu_stress_limited": "CPU压力+\n应用侧限流",
    }
    rows: List[Dict[str, object]] = []
    for (run_id, scenario, phase), group in requests.groupby(["run_id", "scenario", "phase"], sort=False):
        if scenario not in scenario_labels:
            continue
        duration = ar.phase_duration(group)
        success = group[group["success"] == True]  # noqa: E712
        rows.append(
            {
                "group": scenario_labels[scenario],
                "series": ar.EXP2_PHASE_LABELS.get(phase, str(phase)),
                "run_id": run_id,
                "value": len(success) / duration,
            }
        )
    return pd.DataFrame(rows)


def draw_panel_d(ax, requests: pd.DataFrame) -> None:
    draw_exp2_dense_p99_curve_axis(ax, requests, "d) TiDB Leader 短时扰动前后 P99 恢复曲线")
    ax.legend(fontsize=12.0, title_fontsize=13.0, loc="upper left", framealpha=0.86)


def draw_exp2_dense_p99_curve_axis(
    ax,
    requests: pd.DataFrame,
    title: str,
    bin_s: float = 0.25,
) -> None:
    if requests.empty:
        ax.text(0.5, 0.5, "无数据", transform=ax.transAxes, ha="center", va="center")
        ax.set_title(title)
        return
    df = ar.ensure_run_id(requests).copy()
    successful = df[df["success"] == True].copy()  # noqa: E712
    if not successful.empty:
        df = successful
    df["time_bin"] = (df["relative_s"].astype(float) / bin_s).astype(int) * bin_s
    per_run = (
        df.groupby(["run_id", "scenario", "time_bin"])["latency_ms"]
        .quantile(0.99)
        .reset_index(name="p99_latency_ms")
    )
    stats = per_run.groupby(["scenario", "time_bin"])["p99_latency_ms"].agg(["mean", "std", "count"]).reset_index()
    stats["ci95"] = stats["std"].fillna(0) * 1.96 / stats["count"].pow(0.5)
    baseline_s = float(df["baseline_s"].dropna().iloc[0]) if "baseline_s" in df.columns else 4.0
    perturb_s = float(df["perturb_s"].dropna().iloc[0]) if "perturb_s" in df.columns else 6.0
    scenarios = ["baseline", "leader_cpu_stress", "leader_network_perturbation", "leader_cpu_stress_limited"]
    ax.axvspan(baseline_s, baseline_s + perturb_s, color=PALETTE["gray"], alpha=0.18)
    for scenario in scenarios:
        subset = stats[stats["scenario"] == scenario].sort_values("time_bin")
        if subset.empty:
            continue
        x = subset["time_bin"].astype(float)
        mean = subset["mean"].astype(float)
        ci = subset["ci95"].fillna(0).astype(float)
        color = EXP2_SCENARIO_COLORS.get(scenario)
        smooth_mean = smooth_series(mean)
        smooth_lower = smooth_series((mean - ci).clip(lower=0))
        smooth_upper = smooth_series(mean + ci)
        ax.plot(
            x,
            smooth_mean,
            label=EXP2_FIGURE_SCENARIO_LABELS.get(scenario, scenario),
            color=color,
            linewidth=2,
            marker="o",
            markersize=4.2,
            markerfacecolor=color,
            markeredgecolor="white",
            markeredgewidth=0.7,
            zorder=3,
        )
        ax.fill_between(
            x,
            smooth_lower,
            smooth_upper,
            color=color,
            alpha=0.12,
            zorder=1,
        )
    ax.axvline(baseline_s, color=PALETTE["gray"], linewidth=1, linestyle="--")
    ax.axvline(baseline_s + perturb_s, color=PALETTE["gray"], linewidth=1, linestyle="--")
    ax.set_xlabel("短时故障注入相对时间(s)")
    ax.set_ylabel("成功请求P99延迟(ms)")
    ax.set_title(title)
    ax.grid(alpha=0.25)


def smooth_series(values: pd.Series, window: int = 5) -> pd.Series:
    if len(values) < 3:
        return values
    actual_window = min(window, len(values))
    if actual_window % 2 == 0:
        actual_window -= 1
    actual_window = max(actual_window, 3)
    return values.rolling(window=actual_window, center=True, min_periods=1).mean()


def draw_panel_e(ax, summary: pd.DataFrame) -> None:
    data = exp3_plot_data(summary)
    if data.empty:
        ax.text(0.5, 0.5, "无数据", transform=ax.transAxes, ha="center", va="center")
        ax.set_title("e) 跨分片抢占结果构成")
        return

    labels = full_exp3_labels(data.index)
    front = data["front_run_success_pct"].astype(float).clip(lower=0, upper=100)
    rollback = data["rollback_rate_pct"].astype(float).clip(lower=0, upper=100)
    constrained = (100.0 - front - rollback).clip(lower=0, upper=100)
    y = list(range(len(data.index)))

    colors = {
        "normal": PALETTE["green"],
        "front": PALETTE["red"],
        "rollback": PALETTE["orange"],
    }
    ax.barh(y, front.values, color=colors["front"], alpha=0.48, edgecolor="white", linewidth=0.8, label="抢占提交")
    ax.barh(
        y,
        rollback.values,
        left=front.values,
        color=colors["rollback"],
        alpha=0.48,
        edgecolor="white",
        linewidth=0.8,
        label="事务回滚",
    )
    ax.barh(
        y,
        constrained.values,
        left=(front + rollback).values,
        color=colors["normal"],
        alpha=0.48,
        edgecolor="white",
        linewidth=0.8,
        label="正常完成/顺序约束",
    )

    for idx, defense in enumerate(data.index):
        segments = [
            (float(front.loc[defense]), 0.0, "front"),
            (float(rollback.loc[defense]), float(front.loc[defense]), "rollback"),
            (float(constrained.loc[defense]), float(front.loc[defense] + rollback.loc[defense]), "normal"),
        ]
        for value, left, kind in segments:
            if value < 4:
                continue
            text_color = "white" if kind in {"front", "rollback"} and value > 18 else "black"
            ax.text(
                left + value / 2,
                idx,
                f"{value:.1f}%",
                ha="center",
                va="center",
                fontsize=12.4,
                color=text_color,
            )
        if float(front.loc[defense]) > 0 and float(front.loc[defense]) < 4:
            ax.text(2.6, idx - 0.28, f"{float(front.loc[defense]):.2f}%", ha="left", va="center", fontsize=11.4)

    ax.set_title("e) 跨分片抢占结果构成")
    ax.set_xlabel("事务对占比(%)")
    ax.set_yticks(y, labels)
    ax.invert_yaxis()
    ax.set_xlim(0, 100)
    ax.grid(axis="x", alpha=0.24)
    ax.legend(loc="lower right", ncol=1, framealpha=0.86, fontsize=12.0)


def draw_panel_f(ax, summary: pd.DataFrame) -> None:
    data = exp3_plot_data(summary)
    if data.empty:
        ax.text(0.5, 0.5, "无数据", transform=ax.transAxes, ha="center", va="center")
        ax.set_title("f) 跨分片事务防御效果与代价")
        return

    ax.set_title("f) 跨分片事务防御效果与代价矩阵")
    ax.axis("off")

    metric_specs = [
        ("抢占\n成功率", "front_run_success_pct", "pct", "higher_bad"),
        ("一致性\n违规率", "consistency_violation_pct", "pct", "higher_bad"),
        ("事务\n回滚率", "rollback_rate_pct", "pct", "higher_bad"),
        ("吞吐量\n(tx/s)", "throughput_txn_s", "num1", "lower_bad"),
        ("P95\n(ms)", "p95_latency_ms", "num0", "higher_bad"),
    ]
    labels = compact_exp3_labels(data.index)
    n_rows = len(data.index)
    n_cols = len(metric_specs)
    ax.set_xlim(-0.22, n_cols)
    ax.set_ylim(n_rows + 0.42, -0.62)

    for col, (label, _, _, _) in enumerate(metric_specs):
        ax.text(col + 0.5, -0.22, label, ha="center", va="center", fontsize=12.4, color="black")

    risk_cmap = mcolors.LinearSegmentedColormap.from_list(
        "exp3_risk",
        [
            mcolors.to_rgba(PALETTE["gray"], 0.16),
            mcolors.to_rgba(PALETTE["orange"], 0.58),
            mcolors.to_rgba(PALETTE["red"], 0.92),
        ],
    )
    column_norms = {
        column: normalized_costs(data[column].astype(float), direction)
        for _, column, _, direction in metric_specs
    }

    for row, (defense, label) in enumerate(zip(data.index, labels)):
        ax.text(-0.05, row + 0.5, label, ha="right", va="center", fontsize=12.4, color="black", clip_on=False)
        for col, (_, column, fmt, _) in enumerate(metric_specs):
            value = float(data.loc[defense, column])
            cost = float(column_norms[column].loc[defense])
            facecolor = risk_cmap(0.10 + 0.82 * cost)
            ax.add_patch(
                patches.Rectangle(
                    (col, row),
                    1,
                    1,
                    facecolor=facecolor,
                    edgecolor="white",
                    linewidth=1.15,
                )
            )
            ax.text(
                col + 0.5,
                row + 0.5,
                format_exp3_matrix_value(value, fmt),
                ha="center",
                va="center",
                fontsize=11.8,
                color="white" if cost > 0.72 else "black",
            )

    ax.add_patch(
        patches.Rectangle(
            (0, 0),
            n_cols,
            n_rows,
            fill=False,
            edgecolor=PALETTE["gray"],
            linewidth=0.8,
        )
    )
    ax.text(
        n_cols - 0.02,
        n_rows + 0.22,
        "颜色越深表示风险或代价越高；吞吐量列按低吞吐着色",
        ha="right",
        va="center",
        fontsize=10.8,
        color=PALETTE["gray"],
    )


def exp3_plot_data(summary: pd.DataFrame) -> pd.DataFrame:
    if summary.empty:
        return pd.DataFrame()
    return summary.set_index("defense").reindex(ar.EXP3_DEFENSE_ORDER).dropna(how="all")


def full_exp3_labels(index) -> List[str]:
    labels = {
        "baseline": "无防御",
        "global_sequence": "全局序列号",
        "occ": "版本检查",
        "conflict_key_queue": "冲突键队列化",
        "two_phase_commit": "两阶段提交模拟",
    }
    return [labels.get(item, ar.EXP3_DEFENSE_LABELS.get(item, str(item))) for item in index]


def compact_exp3_labels(index) -> List[str]:
    labels = {
        "baseline": "无防御",
        "global_sequence": "全局\n序列号",
        "occ": "版本检查",
        "conflict_key_queue": "冲突键\n队列化",
        "two_phase_commit": "两阶段\n提交模拟",
    }
    return [labels.get(item, ar.EXP3_DEFENSE_LABELS.get(item, str(item))) for item in index]


def normalized_costs(values: pd.Series, direction: str) -> pd.Series:
    values = values.astype(float)
    min_value = float(values.min())
    max_value = float(values.max())
    if max_value - min_value <= 1e-12:
        return pd.Series(0.0, index=values.index)
    if direction == "lower_bad":
        costs = (max_value - values) / (max_value - min_value)
    else:
        costs = (values - min_value) / (max_value - min_value)
    return costs.clip(lower=0, upper=1)


def format_exp3_matrix_value(value: float, fmt: str) -> str:
    if fmt == "pct":
        return f"{value:.2f}%"
    if fmt == "num1":
        return f"{value:.1f}"
    return f"{value:.0f}"


def bubble_size(rollback_rate_pct: float) -> float:
    return 75.0 + float(rollback_rate_pct) * 10.0


def exp3_annotation_offset(defense: str) -> tuple[int, int, str]:
    offsets = {
        "baseline": (-8, 10, "right"),
        "global_sequence": (8, 7, "left"),
        "occ": (8, -9, "left"),
        "conflict_key_queue": (8, 8, "left"),
        "two_phase_commit": (8, -8, "left"),
    }
    return offsets.get(str(defense), (8, 8, "left"))


if __name__ == "__main__":
    raise SystemExit(main())
