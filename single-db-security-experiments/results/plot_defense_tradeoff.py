import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
import matplotlib.font_manager as fm
from pathlib import Path

# --- 1. 数据准备 ---
data = {
    "Tool": ["Baseline (基准)", "pgcrypto (原生扩展)", "Acra (透明代理)"],
    "Security_Level_Int": [1, 2, 3],
    "Security_Label": [
        "低 (明文暴露)\n熵: -0.83",
        "中 (体积泄露)\n熵: -0.39",
        "高 (零泄露)\n熵: 0.00",
    ],
    "CPU_Overhead": [0, 152.21, 254.62],
    "Storage_Overhead": [0, 581, 764],
    "Color": ["#bdc3c7", "#f1c40f", "#e74c3c"],  # 灰, 黄, 红
}
df = pd.DataFrame(data)

# --- 2. 字体设置 (自动适配) ---
font_names = [
    "SimHei",
    "Microsoft YaHei",
    "PingFang SC",
    "Heiti TC",
    "Arial Unicode MS",
]
selected_font = None
for font in font_names:
    if font in [f.name for f in fm.fontManager.ttflist]:
        selected_font = font
        break
plt.rcParams["font.sans-serif"] = [selected_font] if selected_font else ["sans-serif"]
plt.rcParams["axes.unicode_minus"] = False

# --- 3. 绘图设置 (紧凑画布，使用已安装中文字体) ---
sns.set_style("whitegrid")

# 强制注册并使用系统中文字体，减少缺字警告
font_path = "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc"
try:
    fm.fontManager.addfont(font_path)
    fp = fm.FontProperties(fname=font_path)
    font_name = fp.get_name()
    plt.rcParams["font.family"] = font_name
except Exception:
    fp = None

# 紧凑画布（更小，适合三气泡）
plt.figure(figsize=(5.5, 3.6), dpi=150)

# 气泡大小：压缩比例并保证可见性
bubble_sizes = [220 + (x * 1.6) for x in df["Storage_Overhead"]]

plt.scatter(
    x=df["Security_Level_Int"],
    y=df["CPU_Overhead"],
    s=bubble_sizes,
    c=df["Color"],
    alpha=0.85,
    edgecolors="#222222",
    linewidth=0.8,
    zorder=2,
)

# --- 4. 紧凑布局调整 ---

# X轴：收缩范围，去掉左右多余空白
plt.xticks([1, 2, 3], df["Security_Label"], fontsize=11, fontproperties=fp)
plt.xlim(0.7, 3.3)  # 更紧凑
plt.xlabel("安全性等级 (Security Level)", fontsize=12, weight="bold", fontproperties=fp)

# Y轴：留出顶部给箭头但总体更紧凑
plt.ylabel("性能痛点：CPU 开销 (%)", fontsize=12, weight="bold", fontproperties=fp)
plt.ylim(-10, 300)

# 标题：已移除以避免遮挡
# plt.title("隐私的代价：防御效能与资源消耗权衡", fontsize=14, weight="bold", pad=16)

# --- 5. 数据标签 (更紧凑的偏移) ---
offsets = [22, 30, 34]
for i in range(len(df)):
    plt.text(
        x=df["Security_Level_Int"][i],
        y=df["CPU_Overhead"][i] + offsets[i],
        s=f"{df['Tool'][i]}\nCPU: +{df['CPU_Overhead'][i]}%\n存储: +{df['Storage_Overhead'][i]}%",
        ha="center",
        va="bottom",
        fontsize=9.5,
        weight="bold",
        bbox=dict(
            facecolor="white", alpha=0.85, edgecolor="none", boxstyle="round,pad=0.15"
        ),
        zorder=3,
        fontproperties=fp,
    )

# --- 6. 视觉引导箭头 (重新设计弧度以适应紧凑空间) ---
plt.annotate(
    "代价指数级增长",
    xy=(3, 245),
    xycoords="data",
    xytext=(1.75, 200),
    textcoords="data",
    arrowprops=dict(
        arrowstyle="->", connectionstyle="arc3,rad=-0.18", color="#c0392b", lw=1.8
    ),
    fontsize=10.5,
    color="#c0392b",
    weight="bold",
    bbox=dict(boxstyle="round,pad=0.25", fc="white", ec="#c0392b", lw=0.9),
    zorder=1,
    fontproperties=fp,
)

# --- 7. 图例说明 ---
plt.text(
    x=0.95,
    y=280,
    s="注：气泡面积 ∝ 存储开销",
    fontsize=9,
    color="#555555",
    bbox=dict(facecolor="#eeeeee", alpha=0.6, edgecolor="none"),
    fontproperties=fp,
)

plt.tight_layout(pad=0.6)
# 保存为紧凑版文件
OUT_DIR = Path(__file__).resolve().parent / "suricata"
OUT_DIR.mkdir(parents=True, exist_ok=True)
OUT_FILE = OUT_DIR / "defense_tradeoff_bubble_chart_compact.png"
plt.savefig(OUT_FILE, dpi=300, bbox_inches="tight")
print(f"Saved compact chart to: {OUT_FILE}")
# 不在无头环境中显示
plt.close()
