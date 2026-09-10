#!/usr/bin/env python3
"""
体积泄漏攻击测试 (Volume Leakage Attack)

测试目标:
通过观察加密数据的存储体积变化，推断数据库中的敏感信息
即使数据被加密，不同长度的明文会产生不同长度的密文，攻击者可以利用这一点推断信息

测试场景:
1. 密码长度泄漏: 通过密文长度推断密码复杂度
2. 邮箱长度泄漏: 通过密文长度推断邮箱地址长度
3. 数据分布泄漏: 通过体积分布推断数据特征

数据集: 150个真实Enron员工
"""

import psycopg2
import sys
from typing import Dict, List, Tuple, Set
import csv
from collections import Counter
import statistics

# 导入完整的Enron数据集（150个真实员工）
from enron_test_data import ENRON_TEST_USERS

# 数据库配置
DB_CONFIGS = {
    "baseline": {
        "host": "localhost",
        "port": 5433,
        "user": "youruser",
        "password": "password123",
        "database": "juiceshop_db",
    },
    "acra": {
        "host": "localhost",
        "port": 9393,  # Acra代理端口
        "user": "acrauser",
        "password": "acra_password123",
        "database": "acra_db",
        "backend_port": 5434,  # 后端数据库端口
    },
    "pgcrypto": {
        "host": "localhost",
        "port": 5435,
        "user": "pgcrypto",
        "password": "pgcrypto_pass",
        "database": "pgcrypto_db",
    },
}


def connect_db(config: Dict) -> psycopg2.extensions.connection:
    """连接数据库"""
    return psycopg2.connect(
        host=config["host"],
        port=config["port"],
        user=config["user"],
        password=config["password"],
        database=config["database"],
    )


def setup_baseline_db(conn):
    """设置基线数据库（明文存储）"""
    cursor = conn.cursor()

    # 删除旧表
    cursor.execute("DROP TABLE IF EXISTS users CASCADE")

    # 创建用户表
    cursor.execute(
        """
        CREATE TABLE users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100),
            password VARCHAR(200),
            email VARCHAR(200)
        )
    """
    )

    # 插入150个Enron员工数据
    for username, password, email in ENRON_TEST_USERS:
        cursor.execute(
            "INSERT INTO users (username, password, email) VALUES (%s, %s, %s)",
            (username, password, email),
        )

    conn.commit()
    print(f"✓ 插入 {len(ENRON_TEST_USERS)} 条测试数据")


def setup_acra_db(conn):
    """设置Acra数据库（透明加密）"""
    cursor = conn.cursor()

    # 删除旧表
    cursor.execute("DROP TABLE IF EXISTS users CASCADE")

    # 创建用户表（TEXT类型支持Acra加密）
    cursor.execute(
        """
        CREATE TABLE users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100),
            password TEXT,
            email TEXT
        )
    """
    )

    # 插入150个Enron员工数据（Acra自动加密）
    for username, password, email in ENRON_TEST_USERS:
        cursor.execute(
            "INSERT INTO users (username, password, email) VALUES (%s, %s, %s)",
            (username, password, email),
        )

    conn.commit()
    print(f"✓ 插入 {len(ENRON_TEST_USERS)} 条测试数据（自动加密）")


def setup_pgcrypto_db(conn):
    """设置pgcrypto数据库（字段级加密）"""
    cursor = conn.cursor()

    # 启用pgcrypto扩展
    cursor.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # 删除旧表
    cursor.execute("DROP TABLE IF EXISTS users CASCADE")

    # 创建用户表
    cursor.execute(
        """
        CREATE TABLE users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100),
            password BYTEA,
            email VARCHAR(200)
        )
    """
    )

    # 插入150个Enron员工数据（password加密，email明文）
    for username, password, email in ENRON_TEST_USERS:
        cursor.execute(
            "INSERT INTO users (username, password, email) VALUES (%s, pgp_sym_encrypt(%s, 'my-secret-key'), %s)",
            (username, password, email),
        )

    conn.commit()
    print(f"✓ 插入 {len(ENRON_TEST_USERS)} 条测试数据（password加密，email明文）")


def analyze_volume_leakage(conn, env_name: str, check_backend: bool = False) -> Dict:
    """
    分析体积泄漏

    返回:
    - password_lengths: 密码密文长度分布
    - email_lengths: 邮箱密文长度分布
    - length_entropy: 长度熵（信息泄漏量）
    - leakage_level: 泄漏级别
    """
    cursor = conn.cursor()

    # 查询所有数据的存储长度
    if env_name == "baseline":
        # 明文存储，直接测量字符长度
        cursor.execute(
            """
            SELECT 
                username,
                LENGTH(password) as password_len,
                LENGTH(email) as email_len,
                password,
                email
            FROM users
            ORDER BY id
        """
        )
    elif env_name == "pgcrypto":
        # pgcrypto使用BYTEA存储，测量字节长度
        cursor.execute(
            """
            SELECT 
                username,
                LENGTH(password) as password_len,
                LENGTH(email) as email_len,
                password,
                email
            FROM users
            ORDER BY id
        """
        )
    else:  # acra
        # Acra使用TEXT存储，测量字符长度
        cursor.execute(
            """
            SELECT 
                username,
                LENGTH(password) as password_len,
                LENGTH(email) as email_len,
                password,
                email
            FROM users
            ORDER BY id
        """
        )

    rows = cursor.fetchall()

    # 统计长度分布
    password_lengths = []
    email_lengths = []
    username_to_data = {}

    for username, pwd_len, email_len, pwd_data, email_data in rows:
        password_lengths.append(pwd_len)
        email_lengths.append(email_len)
        username_to_data[username] = {
            "password_len": pwd_len,
            "email_len": email_len,
            "password_sample": str(pwd_data)[:50] if pwd_data else "NULL",
            "email_sample": str(email_data)[:50] if email_data else "NULL",
        }

    # 计算统计指标
    result = {
        "environment": env_name,
        "total_records": len(rows),
        "password_length_stats": {
            "min": min(password_lengths) if password_lengths else 0,
            "max": max(password_lengths) if password_lengths else 0,
            "mean": statistics.mean(password_lengths) if password_lengths else 0,
            "median": statistics.median(password_lengths) if password_lengths else 0,
            "unique_lengths": len(set(password_lengths)),
            "distribution": dict(Counter(password_lengths)),
        },
        "email_length_stats": {
            "min": min(email_lengths) if email_lengths else 0,
            "max": max(email_lengths) if email_lengths else 0,
            "mean": statistics.mean(email_lengths) if email_lengths else 0,
            "median": statistics.median(email_lengths) if email_lengths else 0,
            "unique_lengths": len(set(email_lengths)),
            "distribution": dict(Counter(email_lengths)),
        },
        "sample_data": username_to_data,
    }

    # 计算信息熵（长度多样性）
    def calculate_entropy(lengths):
        """计算长度分布的熵"""
        if not lengths:
            return 0
        counter = Counter(lengths)
        total = len(lengths)
        entropy = 0
        for count in counter.values():
            p = count / total
            if p > 0:
                entropy -= p * (p**0.5)  # 简化的熵计算
        return entropy

    result["password_length_entropy"] = calculate_entropy(password_lengths)
    result["email_length_entropy"] = calculate_entropy(email_lengths)

    # 评估泄漏级别
    def assess_leakage_level(unique_lengths, total_records, entropy):
        """评估体积泄漏级别"""
        if unique_lengths == total_records:
            return "High（每条记录长度不同）"
        elif unique_lengths > total_records * 0.5:
            return "Medium-High（超过50%记录长度不同）"
        elif unique_lengths > total_records * 0.1:
            return "Medium（10-50%记录长度不同）"
        elif unique_lengths > 1:
            return "Low-Medium（少量长度变化）"
        else:
            return "Low（所有记录长度相同）"

    result["password_leakage_level"] = assess_leakage_level(
        result["password_length_stats"]["unique_lengths"],
        result["total_records"],
        result["password_length_entropy"],
    )

    result["email_leakage_level"] = assess_leakage_level(
        result["email_length_stats"]["unique_lengths"],
        result["total_records"],
        result["email_length_entropy"],
    )

    return result


def compare_with_actual_lengths():
    """
    对比真实数据长度与加密后长度
    用于验证是否可以通过密文长度推断明文长度
    """
    actual_lengths = {}

    for username, password, email in ENRON_TEST_USERS:
        actual_lengths[username] = {"password": len(password), "email": len(email)}

    return actual_lengths


def print_analysis(result: Dict, actual_lengths: Dict):
    """打印分析结果"""
    env = result["environment"]

    print(f"\n{'='*70}")
    print(f"体积泄漏分析: {env.upper()}")
    print(f"{'='*70}")
    print(f"总记录数: {result['total_records']}")

    print(f"\n📊 密码字段长度统计:")
    pwd_stats = result["password_length_stats"]
    print(f"  范围: {pwd_stats['min']} - {pwd_stats['max']} 字符")
    print(f"  平均: {pwd_stats['mean']:.2f} 字符")
    print(f"  中位数: {pwd_stats['median']:.2f} 字符")
    print(f"  唯一长度数: {pwd_stats['unique_lengths']}")
    print(f"  泄漏级别: {result['password_leakage_level']}")
    print(f"  长度熵: {result['password_length_entropy']:.4f}")

    # 显示前10个最常见的长度
    print(f"\n  前10个最常见的密码长度:")
    sorted_dist = sorted(
        pwd_stats["distribution"].items(), key=lambda x: x[1], reverse=True
    )[:10]
    for length, count in sorted_dist:
        percentage = count / result["total_records"] * 100
        print(f"    {length:3d} 字符: {count:3d} 条记录 ({percentage:5.2f}%)")

    print(f"\n📧 邮箱字段长度统计:")
    email_stats = result["email_length_stats"]
    print(f"  范围: {email_stats['min']} - {email_stats['max']} 字符")
    print(f"  平均: {email_stats['mean']:.2f} 字符")
    print(f"  中位数: {email_stats['median']:.2f} 字符")
    print(f"  唯一长度数: {email_stats['unique_lengths']}")
    print(f"  泄漏级别: {result['email_leakage_level']}")
    print(f"  长度熵: {result['email_length_entropy']:.4f}")

    # 显示前10个最常见的长度
    print(f"\n  前10个最常见的邮箱长度:")
    sorted_dist = sorted(
        email_stats["distribution"].items(), key=lambda x: x[1], reverse=True
    )[:10]
    for length, count in sorted_dist:
        percentage = count / result["total_records"] * 100
        print(f"    {length:3d} 字符: {count:3d} 条记录 ({percentage:5.2f}%)")

    # 对比真实长度（显示是否可以通过密文长度推断明文）
    print(f"\n🔍 长度相关性分析（前5个样本）:")
    sample_count = 0
    for username, data in result["sample_data"].items():
        if sample_count >= 5:
            break
        if username in actual_lengths:
            actual = actual_lengths[username]
            encrypted_pwd_len = data["password_len"]
            encrypted_email_len = data["email_len"]
            actual_pwd_len = actual["password"]
            actual_email_len = actual["email"]

            print(f"  {username}:")
            print(
                f"    密码: 明文 {actual_pwd_len} 字符 → 密文 {encrypted_pwd_len} 字符 (增长: {encrypted_pwd_len - actual_pwd_len:+d})"
            )
            print(
                f"    邮箱: 明文 {actual_email_len} 字符 → 密文 {encrypted_email_len} 字符 (增长: {encrypted_email_len - actual_email_len:+d})"
            )
            sample_count += 1


def save_results(
    results: List[Dict], filename: str = "results/volume_leakage_test.csv"
):
    """保存测试结果到CSV"""
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "environment",
                "total_records",
                "password_min_len",
                "password_max_len",
                "password_mean_len",
                "password_unique_lengths",
                "password_leakage_level",
                "password_entropy",
                "email_min_len",
                "email_max_len",
                "email_mean_len",
                "email_unique_lengths",
                "email_leakage_level",
                "email_entropy",
            ]
        )

        for result in results:
            writer.writerow(
                [
                    result["environment"],
                    result["total_records"],
                    result["password_length_stats"]["min"],
                    result["password_length_stats"]["max"],
                    f"{result['password_length_stats']['mean']:.2f}",
                    result["password_length_stats"]["unique_lengths"],
                    result["password_leakage_level"],
                    f"{result['password_length_entropy']:.4f}",
                    result["email_length_stats"]["min"],
                    result["email_length_stats"]["max"],
                    f"{result['email_length_stats']['mean']:.2f}",
                    result["email_length_stats"]["unique_lengths"],
                    result["email_leakage_level"],
                    f"{result['email_length_entropy']:.4f}",
                ]
            )

    print(f"\n✓ 结果已保存到: {filename}")


def main():
    """主函数"""
    print("=" * 70)
    print("体积泄漏攻击测试 (Volume Leakage Attack)")
    print("测试数据: 150个Enron员工")
    print("=" * 70)

    results = []
    actual_lengths = compare_with_actual_lengths()

    # 测试Baseline
    print(f"\n{'='*70}")
    print("测试环境: BASELINE (明文存储)")
    print(f"{'='*70}")
    try:
        conn = connect_db(DB_CONFIGS["baseline"])
        print(
            f"✓ 连接成功: {DB_CONFIGS['baseline']['host']}:{DB_CONFIGS['baseline']['port']}"
        )
        print("\n[Baseline] 设置明文数据库...")
        setup_baseline_db(conn)

        print("\n[Baseline] 分析体积泄漏...")
        result = analyze_volume_leakage(conn, "baseline")
        results.append(result)
        print_analysis(result, actual_lengths)

        conn.close()
    except Exception as e:
        print(f"❌ Baseline测试失败: {e}")
        import traceback

        traceback.print_exc()

    # 测试Acra
    print(f"\n{'='*70}")
    print("测试环境: ACRA (透明加密)")
    print(f"{'='*70}")
    try:
        conn = connect_db(DB_CONFIGS["acra"])
        print(f"✓ 连接成功: {DB_CONFIGS['acra']['host']}:{DB_CONFIGS['acra']['port']}")
        print("\n[Acra] 设置透明加密数据库...")
        setup_acra_db(conn)

        print("\n[Acra] 分析体积泄漏...")
        result = analyze_volume_leakage(conn, "acra")
        results.append(result)
        print_analysis(result, actual_lengths)

        conn.close()
    except Exception as e:
        print(f"❌ Acra测试失败: {e}")
        import traceback

        traceback.print_exc()

    # 测试pgcrypto
    print(f"\n{'='*70}")
    print("测试环境: PGCRYPTO (字段级加密)")
    print(f"{'='*70}")
    try:
        conn = connect_db(DB_CONFIGS["pgcrypto"])
        print(
            f"✓ 连接成功: {DB_CONFIGS['pgcrypto']['host']}:{DB_CONFIGS['pgcrypto']['port']}"
        )
        print("\n[pgcrypto] 设置字段级加密数据库...")
        setup_pgcrypto_db(conn)

        print("\n[pgcrypto] 分析体积泄漏...")
        result = analyze_volume_leakage(conn, "pgcrypto")
        results.append(result)
        print_analysis(result, actual_lengths)

        conn.close()
    except Exception as e:
        print(f"❌ pgcrypto测试失败: {e}")
        import traceback

        traceback.print_exc()

    # 保存结果
    if results:
        save_results(results)

        # 打印总结
        print(f"\n{'='*70}")
        print("测试总结")
        print(f"{'='*70}")
        for result in results:
            print(f"\n{result['environment'].upper()}:")
            print(f"  密码字段: {result['password_leakage_level']}")
            print(f"  邮箱字段: {result['email_leakage_level']}")
            print(
                f"  密码唯一长度数: {result['password_length_stats']['unique_lengths']}/150"
            )
            print(
                f"  邮箱唯一长度数: {result['email_length_stats']['unique_lengths']}/150"
            )


if __name__ == "__main__":
    main()
