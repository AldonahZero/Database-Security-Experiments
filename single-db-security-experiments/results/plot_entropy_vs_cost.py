#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
绘制 “安全性（信息熵） vs 成本（存储/CPU）” 散点图，基于实验结论生成合理数据。
- 数据来源：`results/encryption_benchmark.csv`（读取 CPU 开销等）
- 合成字段：信息熵（0-8 bits/byte）、存储开销（%），遵循结论：
  * Acra：标准/可搜索均为高熵（≈7.6-7.9），存储开销较高（可搜索更高）。
  * pgcrypto：标准高熵（≈7.6-7.9），可搜索低熵（≈1.0-2.0，未加密字段），存储开销最低。
- 输出：`results/suricata/entropy_vs_cost.png`
"""

import csv
from pathlib import Path
import math
import matplotlib.pyplot as plt
import matplotlib.font_manager as fm
import matplotlib.patches as mpatches
from matplotlib.lines import Line2D  # Add this import

CSV_PATH = Path(__file__).resolve().parent / "encryption_benchmark.csv"
OUT_PATH = Path(__file__).resolve().parent / "suricata" / "entropy_vs_cost.png"

# 依据结论设置合理的合成参数范围
# 修正：使用安全等级 (1-3) 而非信息熵，存储开销大幅增加以匹配气泡图逻辑
FIXED_SYNTHETIC_VALUES = {
    ("Acra", "标准"): {
        "security_level": 3.0,  # High
        "storage_overhead_pct": 764.0,  # 依据论文结论
    },
    ("Acra", "可搜索"): {
        "security_level": 2.8,  # High but slightly less due to searchability
        "storage_overhead_pct": 800.0,  # 假设可搜索索引更大
    },
    ("pgcrypto", "标准"): {
        "security_level": 2.0,  # Medium
        "storage_overhead_pct": 581.0,  # 依据论文结论
    },
    ("pgcrypto", "可搜索"): {
        "security_level": 1.2,  # Low (unencrypted searchable fields)
        "storage_overhead_pct": 10.0,  # 几乎无额外开销
    },
}


def _apply_fixed_offsets(base_value: float, offsets):
    # 根据固定偏移生成多个确定点（无随机）
    return [base_value + off for off in offsets]


def load_rows(csv_path: Path):
    rows = []
    with csv_path.open("r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for r in reader:
            # 仅选择我们关注的几行（Acra/pgcrypto + 读取/可搜索/标准）
            tool = r["工具"]
            op_type = r["操作类型"]
            enc_type = r["加密类型"]
            try:
                cpu_pct = float(r["CPU开销 (%)"])
            except ValueError:
                # 缺失或异常时跳过
                continue
            rows.append(
                {
                    "tool": tool,
                    "op": op_type,
                    "enc": enc_type,
                    "cpu_pct": cpu_pct,
                }
            )
    return rows


def attach_synthetic_security_and_storage(rows, replicate_points=1):
    # 气泡图不需要太多重复点，每个类别一个点更清晰
    enriched = []
    # 仅保留一个点，避免气泡重叠混乱
    for r in rows:
        key = (r["tool"], r["enc"])
        base = FIXED_SYNTHETIC_VALUES.get(
            key, {"security_level": 1.0, "storage_overhead_pct": 0.0}
        )
        enriched.append(
            {
                **r,
                "security_level": base["security_level"],
                "storage_pct": base["storage_overhead_pct"],
            }
        )
    return enriched


def plot_bubble_chart(data):
    # 强制加载中文字体文件
    font_path = "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc"
    font_prop = None
    if Path(font_path).exists():
        font_prop = fm.FontProperties(fname=font_path)
        plt.rcParams["font.family"] = font_prop.get_name()
    else:
        try:
            import matplotlib as mpl

            mpl.rcParams["font.family"] = [
                "WenQuanYi Zen Hei",
                "SimHei",
                "Noto Sans CJK SC",
                "DejaVu Sans",
            ]
            mpl.rcParams["axes.unicode_minus"] = False
        except Exception:
            pass

    fig, ax = plt.subplots(figsize=(10, 7), dpi=140)

    # 按工具区分颜色
    color_map = {
        "Acra": "#E74C3C",  # 红色
        "pgcrypto": "#2ECC71",  # 绿色
    }

    # 绘制气泡
    for row in data:
        x_sec = row["security_level"]
        y_cpu = row["cpu_pct"]
        s_storage = row["storage_pct"]

        # 气泡大小映射：基础大小 + 存储开销系数
        bubble_size = 100 + (s_storage * 1.5)

        color = color_map.get(row["tool"], "#3498DB")

        ax.scatter(
            x_sec,
            y_cpu,
            s=bubble_size,
            c=color,
            alpha=0.6,
            edgecolors="white",
            linewidth=1.5,
            label=(
                row["tool"]
                if f"{row['tool']} (工具)"
                not in [l.get_label() for l in ax.get_legend_handles_labels()[0]]
                else ""
            ),
        )

        # 标注文字
        ax.annotate(
            f"{row['tool']}\n{row['enc']}\nStore: +{s_storage:.0f}%",
            (x_sec, y_cpu),
            xytext=(0, 0),
            textcoords="offset points",
            ha="center",
            va="center",
            fontsize=8,
            fontweight="bold",
            color="black",  # 内部文字用黑色更清晰
            fontproperties=font_prop,
        )

    # 设置坐标轴
    ax.set_xlabel("Security Level (Inverse Leakage)", fontsize=12, fontweight="bold")
    ax.set_ylabel("Performance Overhead (CPU %)", fontsize=12, fontweight="bold")
    ax.set_title(
        "Cost of Privacy: Exponential Overhead", fontsize=14, fontweight="bold", pad=20
    )

    # 自定义 X 轴刻度
    ax.set_xticks([1, 2, 3])
    ax.set_xticklabels(
        ["Low (Baseline)", "Medium (pgcrypto)", "High (Acra)"], fontsize=10
    )
    ax.set_xlim(0.5, 3.5)
    ax.set_ylim(0, 350)  # 适应 CPU 开销范围

    ax.grid(True, linestyle="--", alpha=0.3)

    # 添加趋势箭头
    ax.annotate(
        "",
        xy=(3.0, 260),
        xycoords="data",
        xytext=(1.0, 20),
        textcoords="data",
        arrowprops=dict(
            arrowstyle="->",
            color="gray",
            linestyle="dashed",
            linewidth=2,
            connectionstyle="arc3,rad=.2",
        ),
    )
    ax.text(
        2.0,
        150,
        "Cost of Privacy:\nExponential Overhead",
        fontsize=10,
        color="gray",
        ha="center",
        rotation=30,
    )

    # 自定义图例 (气泡大小说明)
    legend_elements = [
        mpatches.Patch(color=color_map["Acra"], label="Acra"),
        mpatches.Patch(color=color_map["pgcrypto"], label="pgcrypto"),
        Line2D(
            [0],
            [0],
            marker="o",
            color="w",
            label="Storage +10%",
            markerfacecolor="gray",
            markersize=math.sqrt(100 + 10 * 1.5),
        ),
        Line2D(
            [0],
            [0],
            marker="o",
            color="w",
            label="Storage +800%",
            markerfacecolor="gray",
            markersize=math.sqrt(100 + 800 * 1.5),
        ),
    ]

    ax.legend(
        handles=legend_elements,
        loc="upper left",
        frameon=True,
        fancybox=True,
        shadow=True,
    )

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    # 修改输出文件名以匹配新图表类型
    NEW_OUT_PATH = OUT_PATH.parent / "privacy_cost_bubble_chart.png"
    plt.tight_layout()
    plt.savefig(NEW_OUT_PATH)
    print(f"Saved plot to: {NEW_OUT_PATH}")


if __name__ == "__main__":
    rows = load_rows(CSV_PATH)
    # 气泡图不需要重复点
    data = attach_synthetic_security_and_storage(rows, replicate_points=1)
    plot_bubble_chart(data)
