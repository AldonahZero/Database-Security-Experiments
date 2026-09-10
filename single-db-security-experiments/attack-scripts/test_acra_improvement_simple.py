#!/usr/bin/env python3
"""
Acra 改进方案模拟测试
由于 Acra 0.94.0 的透明模式限制，这里模拟实现固定长度填充方案
展示改进后的体积泄漏防护效果

模拟内容：
1. 原始 Acra 透明模式（通过代理查询）
2. 模拟改进方案：应用层填充 + pgcrypto 加密（模拟非透明 Acra）
"""

import psycopg2
import statistics
from collections import Counter
import csv
from enron_test_data import ENRON_TEST_USERS

# 数据库配置
CONFIGS = {
    "acra_original": {
        "host": "localhost",
        "port": 9393,  # 通过 Acra 代理
        "user": "acrauser",
        "password": "acra_password123",
        "database": "acra_db",
    },
    "postgres_direct": {
        "host": "localhost",
        "port": 5434,  # 直连 PostgreSQL
        "user": "acrauser",
        "password": "acra_password123",
        "database": "acra_db",
    },
}


def pad_to_fixed_length(text, target_length=32):
    """
    固定长度填充
    模拟 Acra 改进方案的填充策略
    使用空格字符填充（PostgreSQL TEXT 不支持 \x00）
    """
    if len(text) >= target_length:
        return text[:target_length]
    # 使用空格填充（可以是任意字符，加密后不影响长度统一性）
    return text.ljust(target_length, " ")


def setup_original_acra_db(conn):
    """设置原始 Acra 透明加密数据库"""
    cursor = conn.cursor()

    cursor.execute("DROP TABLE IF EXISTS users_original CASCADE")
    cursor.execute(
        """
        CREATE TABLE users_original (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email VARCHAR(255) NOT NULL
        )
    """
    )

    # 通过 Acra 代理插入数据（透明加密）
    for username, password, email in ENRON_TEST_USERS:
        cursor.execute(
            """
            INSERT INTO users_original (username, password, email)
            VALUES (%s, %s, %s)
        """,
            (username, password, email),
        )

    conn.commit()
    print(f"✓ 原始模式: 插入 {len(ENRON_TEST_USERS)} 条数据（Acra透明加密）")


def setup_improved_acra_db(conn):
    """
    设置改进版 Acra 数据库（模拟非透明模式）
    使用 pgcrypto + 固定长度填充
    """
    cursor = conn.cursor()

    # 确保 pgcrypto 扩展已安装
    cursor.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    cursor.execute("DROP TABLE IF EXISTS users_improved CASCADE")
    cursor.execute(
        """
        CREATE TABLE users_improved (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            password BYTEA NOT NULL,  -- 存储加密后的二进制数据
            email VARCHAR(255) NOT NULL
        )
    """
    )

    # 应用层实现：固定长度填充 + 加密
    encryption_key = "acra_improved_encryption_key_2024"

    for username, password, email in ENRON_TEST_USERS:
        # 步骤1: 固定长度填充到32字符
        padded_password = pad_to_fixed_length(password, 32)

        # 步骤2: 使用 pgcrypto 加密（模拟 Acra AES-256-GCM）
        cursor.execute(
            """
            INSERT INTO users_improved (username, password, email)
            VALUES (%s, pgp_sym_encrypt(%s, %s), %s)
        """,
            (username, padded_password, encryption_key, email),
        )

    conn.commit()
    print(f"✓ 改进模式: 插入 {len(ENRON_TEST_USERS)} 条数据（固定填充+加密）")


def analyze_volume_leakage(conn, env_name, table_name, field_name="password"):
    """分析体积泄漏"""
    cursor = conn.cursor()

    print(f"\n{'='*70}")
    print(f"环境: {env_name}")
    print(f"{'='*70}")

    # 查询密码字段长度
    cursor.execute(f"SELECT LENGTH({field_name}) FROM {table_name}")
    password_lengths = [row[0] for row in cursor.fetchall()]

    # 查询邮箱字段长度
    cursor.execute(f"SELECT LENGTH(email) FROM {table_name}")
    email_lengths = [row[0] for row in cursor.fetchall()]

    # 统计分析
    pwd_stats = analyze_length_distribution(password_lengths)
    email_stats = analyze_length_distribution(email_lengths)

    # 打印结果
    print(f"\n总记录数: {len(password_lengths)}\n")
    print_statistics("密码字段", pwd_stats, password_lengths)

    return {
        "environment": env_name,
        "total_records": len(password_lengths),
        "pwd_min": pwd_stats["min"],
        "pwd_max": pwd_stats["max"],
        "pwd_mean": pwd_stats["mean"],
        "pwd_unique": pwd_stats["unique_count"],
        "pwd_leakage": pwd_stats["leakage_level"],
        "pwd_entropy": pwd_stats["entropy"],
        "email_unique": email_stats["unique_count"],
    }


def analyze_length_distribution(lengths):
    """分析长度分布统计"""
    counter = Counter(lengths)
    total = len(lengths)

    # 计算信息熵
    entropy = sum((count / total) * ((count / total) - 1) for count in counter.values())

    # 评估泄漏级别
    unique_ratio = len(counter) / total
    if unique_ratio >= 0.9:
        leakage = "High"
    elif unique_ratio >= 0.5:
        leakage = "Medium-High"
    elif unique_ratio >= 0.1:
        leakage = "Medium"
    elif unique_ratio >= 0.05:
        leakage = "Low-Medium"
    elif len(counter) == 1:
        leakage = "Low (理想状态)"
    else:
        leakage = "Low"

    return {
        "min": min(lengths),
        "max": max(lengths),
        "mean": statistics.mean(lengths),
        "median": statistics.median(lengths),
        "unique_count": len(counter),
        "distribution": counter,
        "entropy": entropy,
        "leakage_level": leakage,
    }


def print_statistics(label, stats, lengths):
    """打印统计信息"""
    print(f"{label}长度统计:")
    print(f"  最小长度: {stats['min']} 字符")
    print(f"  最大长度: {stats['max']} 字符")
    print(f"  平均长度: {stats['mean']:.2f} 字符")
    print(f"  中位数: {stats['median']} 字符")
    print(
        f"  唯一长度数: {stats['unique_count']}/{len(lengths)} ({stats['unique_count']/len(lengths)*100:.2f}%)"
    )

    print(f"\n{label}长度分布（Top 10）:")
    for length, count in stats["distribution"].most_common(10):
        percentage = count / len(lengths) * 100
        print(f"  {length} 字符: {count} 条记录 ({percentage:.2f}%)")

    print(f"\n信息熵: {stats['entropy']:.4f}")
    print(f"泄漏级别: {stats['leakage_level']}")


def run_comparison_test():
    """运行对比测试"""
    results = []

    print("=" * 70)
    print("Acra 改进方案对比测试")
    print("=" * 70)
    print(f"\n测试数据: {len(ENRON_TEST_USERS)} 个 Enron 员工")
    print("\n方案对比:")
    print("  1. 原始方案: Acra 透明加密（无填充）")
    print("  2. 改进方案: 固定长度填充(32字符) + 加密\n")

    # 测试1: 原始 Acra 透明模式
    print("\n[1/2] 测试原始 Acra 透明模式...")
    try:
        conn = psycopg2.connect(**CONFIGS["acra_original"])
        setup_original_acra_db(conn)
        result1 = analyze_volume_leakage(
            conn, "Acra原始模式（透明加密）", "users_original"
        )
        results.append(result1)
        conn.close()
        print("✓ 原始模式测试完成")
    except Exception as e:
        print(f"❌ 原始模式测试失败: {e}")

    # 测试2: 改进方案（固定填充 + 加密）
    print("\n[2/2] 测试改进方案（固定填充 + 加密）...")
    try:
        conn = psycopg2.connect(**CONFIGS["postgres_direct"])
        setup_improved_acra_db(conn)
        result2 = analyze_volume_leakage(
            conn, "Acra改进方案（固定填充32字符）", "users_improved"
        )
        results.append(result2)
        conn.close()
        print("✓ 改进方案测试完成")
    except Exception as e:
        print(f"❌ 改进方案测试失败: {e}")

    # 保存结果
    if len(results) >= 2:
        save_and_compare_results(results)
    else:
        print("\n⚠️  测试不完整，无法生成完整对比")

    return results


def save_and_compare_results(results):
    """保存结果并打印对比"""
    # 保存到 CSV
    output_file = "results/acra_improvement_comparison.csv"
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        if results:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
    print(f"\n✓ 结果已保存到: {output_file}")

    # 打印对比总结
    print("\n" + "=" * 70)
    print("改进效果对比总结")
    print("=" * 70)

    original = results[0]
    improved = results[1]

    print(f"\n{'指标':<25} {'原始方案':<20} {'改进方案':<20} {'改进效果':<20}")
    print("-" * 90)

    # 密码长度范围
    original_range = f"{original['pwd_min']}-{original['pwd_max']}"
    improved_range = f"{improved['pwd_min']}-{improved['pwd_max']}"
    print(f"{'密码长度范围':<25} {original_range:<20} {improved_range:<20} ", end="")
    if improved["pwd_max"] == improved["pwd_min"]:
        print("✅ 完全统一")
    else:
        print("⚠️  仍有差异")

    # 唯一长度数
    print(
        f"{'唯一长度数':<25} {original['pwd_unique']:<20} {improved['pwd_unique']:<20} ",
        end="",
    )
    if improved["pwd_unique"] == 1:
        print("✅ 理想状态（仅1种）")
    elif improved["pwd_unique"] < original["pwd_unique"]:
        reduction = (1 - improved["pwd_unique"] / original["pwd_unique"]) * 100
        print(f"✅ 减少 {reduction:.0f}%")
    else:
        print("❌ 无改善")

    # 泄漏级别
    print(
        f"{'泄漏级别':<25} {original['pwd_leakage']:<20} {improved['pwd_leakage']:<20} ",
        end="",
    )
    if "理想" in improved["pwd_leakage"]:
        print("✅ 达到理想状态")
    elif improved["pwd_leakage"] in ["Low", "Low (理想状态)"]:
        print("✅ 显著改善")
    else:
        print("⚠️  部分改善")

    # 信息熵
    print(
        f"{'信息熵':<25} {original['pwd_entropy']:.4f}{' '*15} {improved['pwd_entropy']:.4f}{' '*15} ",
        end="",
    )
    if abs(improved["pwd_entropy"]) < abs(original["pwd_entropy"]):
        improvement = (
            1 - abs(improved["pwd_entropy"]) / abs(original["pwd_entropy"])
        ) * 100
        print(f"✅ 改善 {improvement:.0f}%")
    elif improved["pwd_entropy"] == 0:
        print("✅ 完美（熵=0）")
    else:
        print("❌ 无改善")

    print("\n" + "=" * 70)
    print("核心结论:")
    print("-" * 70)

    if improved["pwd_unique"] == 1:
        print("🎉 改进效果: 优秀")
        print("   ✅ 所有密码长度完全统一")
        print("   ✅ 攻击者无法通过长度推断任何信息")
        print("   ✅ 体积泄漏攻击完全失效")
    elif improved["pwd_unique"] <= 3:
        print("✅ 改进效果: 良好")
        print(
            f"   ✅ 长度种类从 {original['pwd_unique']} 种减少到 {improved['pwd_unique']} 种"
        )
        print("   ⚠️  仍存在少量泄漏，建议进一步优化")
    else:
        print("⚠️  改进效果: 有限")
        print("   ⚠️  需要调整填充策略（增加目标长度或使用分桶）")

    print("\n建议:")
    if improved["pwd_unique"] > 1:
        print("  - 增加填充目标长度（如64字符）")
        print("  - 考虑使用分桶填充策略")
        print("  - 检查是否有超长密码导致填充失效")


if __name__ == "__main__":
    try:
        results = run_comparison_test()
    except KeyboardInterrupt:
        print("\n\n⚠️  测试被用户中断")
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback

        traceback.print_exc()
