#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
测试加密工具对SQL注入数据窃取的防护能力
Test encryption tools' protection against SQL injection data theft
"""

import psycopg2
import time
import csv
import os

# 数据库连接配置
DB_CONFIGS = {
    "baseline": {
        "host": "localhost",
        "port": 5433,
        "database": "juiceshop_db",
        "user": "youruser",
        "password": "password123",
        "backend_port": None,  # baseline没有后端
    },
    "acra": {
        "host": "localhost",
        "port": 9393,  # Acra代理端口
        "database": "acra_db",
        "user": "acrauser",
        "password": "acra_password123",
        "backend_port": 5434,  # 后端PostgreSQL端口
    },
    "pgcrypto": {
        "host": "localhost",
        "port": 5435,
        "database": "pgcrypto_db",
        "user": "pgcrypto",
        "password": "pgcrypto_pass",
        "backend_port": None,  # pgcrypto直接连接
    },
}

# Enron数据集 - 真实员工数据样本
# 数据来源: https://www.cs.cmu.edu/~enron/
import psycopg2
import sys
from typing import Dict, List, Tuple
import csv

# 导入完整的Enron数据集（50个真实员工）
from enron_test_data import ENRON_TEST_USERS

# 使用真实的Enron员工数据（50人）
# 数据来源: https://www.cs.cmu.edu/~enron/
TEST_USERS = ENRON_TEST_USERS


def setup_baseline_db(conn):
    """设置基线数据库（无加密）"""
    print("\n[Baseline] 设置无加密数据库...")
    cur = conn.cursor()

    # 删除旧表
    cur.execute("DROP TABLE IF EXISTS users CASCADE")

    # 创建表（无加密）
    cur.execute(
        """
        CREATE TABLE users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) NOT NULL,
            password VARCHAR(100) NOT NULL,
            email VARCHAR(100) NOT NULL
        )
    """
    )

    # 插入测试数据
    for username, password, email in TEST_USERS:
        cur.execute(
            "INSERT INTO users (username, password, email) VALUES (%s, %s, %s)",
            (username, password, email),
        )

    conn.commit()
    cur.close()
    print(f"✓ 插入 {len(TEST_USERS)} 条测试数据")


def setup_acra_db(conn):
    """设置Acra加密数据库"""
    print("\n[Acra] 设置透明加密数据库...")
    cur = conn.cursor()

    # 删除旧表
    cur.execute("DROP TABLE IF EXISTS users CASCADE")

    # 创建表（Acra会自动加密）
    cur.execute(
        """
        CREATE TABLE users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL
        )
    """
    )

    # 插入测试数据（Acra会自动加密）
    for username, password, email in TEST_USERS:
        cur.execute(
            "INSERT INTO users (username, password, email) VALUES (%s, %s, %s)",
            (username, password, email),
        )

    conn.commit()
    cur.close()
    print(f"✓ 插入 {len(TEST_USERS)} 条测试数据（自动加密）")


def setup_pgcrypto_db(conn):
    """设置pgcrypto加密数据库"""
    print("\n[pgcrypto] 设置应用层加密数据库...")
    cur = conn.cursor()

    # 删除旧表
    cur.execute("DROP TABLE IF EXISTS users CASCADE")

    # 创建表
    cur.execute(
        """
        CREATE TABLE users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) NOT NULL,
            password BYTEA NOT NULL,
            email VARCHAR(100) NOT NULL
        )
    """
    )

    # 插入测试数据（password加密，email不加密）
    encryption_key = "test_encryption_key_123"
    for username, password, email in TEST_USERS:
        cur.execute(
            "INSERT INTO users (username, password, email) VALUES (%s, encrypt_text(%s, %s), %s)",
            (username, password, encryption_key, email),
        )

    conn.commit()
    cur.close()
    print(f"✓ 插入 {len(TEST_USERS)} 条测试数据（password加密，email明文）")


def perform_sql_injection(conn, env_name, check_backend=False):
    """执行SQL注入攻击，尝试窃取数据"""
    tag = "后端数据库" if check_backend else "应用层"
    print(f"\n[{env_name}] 通过{tag}执行联合查询注入攻击...")
    cur = conn.cursor()

    # 模拟SQL注入：通过UNION SELECT窃取所有用户密码和邮箱
    # 正常查询: SELECT id, username, password, email FROM users WHERE username = 'alice'
    # 注入载荷: ' UNION SELECT id, username, password, email FROM users --

    try:
        # 先获取表结构
        cur.execute(
            "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = 'users' ORDER BY ordinal_position"
        )
        columns = cur.fetchall()
        print(f"  表结构: {columns}")

        # 构造注入查询（使用正确的类型）
        malicious_input = "' UNION SELECT id, username, password, email FROM users --"

        # 执行注入（故意构造不安全的查询）
        query = f"SELECT id, username, password, email FROM users WHERE username = '{malicious_input}'"
        cur.execute(query)

        results = cur.fetchall()

        # 分析窃取的数据
        stolen_data = []
        for row in results:
            # row格式: (id, username, password, email)
            if len(row) >= 4:
                stolen_data.append(
                    {
                        "id": row[0],
                        "username": row[1],
                        "password": row[2],
                        "email": row[3],
                    }
                )

        cur.close()
        return True, stolen_data

    except Exception as e:
        cur.close()
        print(f"✗ 注入失败: {e}")
        return False, []


def analyze_data_readability(data, env_name):
    """分析窃取数据的可读性"""
    results = []

    for item in data:
        password = item["password"]
        email = item["email"]

        # 将字节数据转换为字符串进行分析
        if isinstance(password, bytes):
            password_str = password.hex()
            password_readable = "Encrypted (Hex)"
            password_protection = "High"
        elif isinstance(password, memoryview):
            password_str = bytes(password).hex()
            password_readable = "Encrypted (Hex)"
            password_protection = "High"
        else:
            password_str = str(password)
            # 检查是否是明文密码
            if env_name == "baseline":
                password_readable = "Plaintext"
                password_protection = "None"
            elif password_str.startswith("\\x"):
                # pgcrypto的加密数据
                password_readable = "Encrypted (Base64)"
                password_protection = "High"
            elif len(password_str) > 100 or any(
                ord(c) > 127 for c in password_str if isinstance(c, str)
            ):
                # Acra的AcraStruct格式（包含非ASCII字符）
                password_readable = "Encrypted (AcraStruct)"
                password_protection = "High"
            else:
                password_readable = "Plaintext"
                password_protection = "None"

        # 判断邮箱字段的可读性
        email_str = str(email)
        if "@" in email_str and "." in email_str:
            email_readable = "Plaintext"
            email_protection = "None"
        else:
            email_readable = "Encrypted"
            email_protection = "High"

        results.append(
            {
                "username": item["username"],
                "password": (
                    password_str[:50] if len(password_str) > 50 else password_str
                ),  # 截断长密文
                "password_readable": password_readable,
                "password_protection": password_protection,
                "email_readable": email_readable,
                "email_protection": email_protection,
            }
        )

    return results


def main():
    """主函数"""
    print("=" * 70)
    print("加密工具对SQL注入数据窃取的防护能力测试")
    print("=" * 70)

    results = []

    # 测试所有环境
    for env_name, config in DB_CONFIGS.items():
        print(f"\n{'=' * 70}")
        print(f"测试环境: {env_name.upper()}")
        print(f"{'=' * 70}")

        try:
            # 连接数据库（移除backend_port参数）
            conn_config = {k: v for k, v in config.items() if k != "backend_port"}
            conn = psycopg2.connect(**conn_config)
            print(f"✓ 连接成功: {config['host']}:{config['port']}")

            # 设置数据库
            if env_name == "baseline":
                setup_baseline_db(conn)
            elif env_name == "acra":
                setup_acra_db(conn)
            elif env_name == "pgcrypto":
                setup_pgcrypto_db(conn)

            # 执行SQL注入攻击
            time.sleep(1)
            success, stolen_data = perform_sql_injection(
                conn, env_name, check_backend=False
            )

            # 对于Acra，还需要检查后端数据库的真实存储（绕过代理）
            backend_stolen_data = None
            if env_name == "acra" and config.get("backend_port"):
                print(f"\n  >>> 额外检查：直接查询后端数据库（绕过Acra代理）")
                try:
                    backend_config = config.copy()
                    backend_config["port"] = config["backend_port"]
                    backend_conn = psycopg2.connect(
                        **{
                            k: v
                            for k, v in backend_config.items()
                            if k != "backend_port"
                        }
                    )
                    backend_success, backend_data_raw = perform_sql_injection(
                        backend_conn, env_name, check_backend=True
                    )
                    if backend_success and backend_data_raw:
                        print(f"  >>> 后端数据库返回 {len(backend_data_raw)} 条记录")
                        # 显示第一条记录的密码样本
                        if len(backend_data_raw) > 0:
                            sample_password = str(backend_data_raw[0]["password"])
                            # 检查是否是AcraStruct格式（包含特殊字节）
                            if isinstance(
                                backend_data_raw[0]["password"], (bytes, memoryview)
                            ):
                                password_bytes = (
                                    bytes(backend_data_raw[0]["password"])
                                    if isinstance(
                                        backend_data_raw[0]["password"], memoryview
                                    )
                                    else backend_data_raw[0]["password"]
                                )
                                password_hex = password_bytes.hex()
                                print(f"  >>> 后端存储格式: AcraStruct (加密)")
                                print(
                                    f"  >>> 密码样本(Hex前50字符): {password_hex[:50]}..."
                                )
                                print(f"  >>> 密码长度: {len(password_hex)} 字符")
                                backend_stolen_data = backend_data_raw
                            else:
                                print(f"  >>> 后端存储格式: 明文（未加密）")
                                print(
                                    f"  >>> 密码样本(前50字符): {sample_password[:50]}..."
                                )
                                print(f"  >>> 密码长度: {len(sample_password)} 字符")
                    backend_conn.close()
                except Exception as e:
                    print(f"  >>> 后端查询失败: {e}")

            if success and stolen_data:
                print(f"✓ 成功窃取 {len(stolen_data)} 条数据")

                # 对于Acra，如果有后端数据，使用后端数据进行分析
                data_to_analyze = (
                    backend_stolen_data
                    if (env_name == "acra" and backend_stolen_data)
                    else stolen_data
                )
                analysis_tag = (
                    "（后端加密数据）"
                    if (env_name == "acra" and backend_stolen_data)
                    else "（应用层数据）"
                )

                # 分析数据可读性
                analysis = analyze_data_readability(data_to_analyze, env_name)

                # 输出分析结果
                print(f"\n数据可读性分析{analysis_tag}:")
                for item in analysis:
                    print(f"  用户: {item['username']}")
                    print(f"    密码样本: {item['password']}")
                    print(
                        f"    密码可读性: {item['password_readable']} (防护: {item['password_protection']})"
                    )
                    print(
                        f"    邮箱可读性: {item['email_readable']} (防护: {item['email_protection']})"
                    )

                # 统计结果
                password_protected = sum(
                    1 for item in analysis if item["password_protection"] == "High"
                )
                email_protected = sum(
                    1 for item in analysis if item["email_protection"] == "High"
                )

                # 对于Acra，添加特殊说明
                protection_note = ""
                if env_name == "acra":
                    if backend_stolen_data and password_protected > 0:
                        protection_note = "（后端加密，但通过代理可解密）"
                    else:
                        protection_note = "（透明解密）"

                results.append(
                    {
                        "environment": env_name,
                        "injection_success_rate": 100.0,
                        "records_stolen": len(stolen_data),
                        "password_field_readable": (
                            "Encrypted" if password_protected > 0 else "Plaintext"
                        )
                        + protection_note,
                        "password_protection": (
                            "High" if password_protected > 0 else "None"
                        ),
                        "email_field_readable": (
                            "Encrypted" if email_protected > 0 else "Plaintext"
                        )
                        + protection_note,
                        "email_protection": "High" if email_protected > 0 else "None",
                    }
                )
            else:
                print(f"✗ 注入攻击失败")
                results.append(
                    {
                        "environment": env_name,
                        "injection_success_rate": 0.0,
                        "records_stolen": 0,
                        "password_field_readable": "N/A",
                        "password_protection": "N/A",
                        "email_field_readable": "N/A",
                        "email_protection": "N/A",
                    }
                )

            conn.close()

        except Exception as e:
            print(f"✗ 测试失败: {e}")
            results.append(
                {
                    "environment": env_name,
                    "injection_success_rate": 0.0,
                    "records_stolen": 0,
                    "password_field_readable": "Error",
                    "password_protection": "Error",
                    "email_field_readable": "Error",
                    "email_protection": "Error",
                    "error": str(e),
                }
            )

    # 保存结果
    output_file = "results/encryption_protection_test.csv"
    os.makedirs("results", exist_ok=True)

    print(f"\n{'=' * 70}")
    print("测试总结")
    print(f"{'=' * 70}")

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "environment",
            "injection_success_rate",
            "records_stolen",
            "password_field_readable",
            "password_protection",
            "email_field_readable",
            "email_protection",
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for result in results:
            writer.writerow({k: result.get(k, "N/A") for k in fieldnames})
            print(f"\n{result['environment'].upper()}:")
            print(f"  注入成功率: {result['injection_success_rate']}%")
            print(f"  窃取记录数: {result['records_stolen']}")
            print(
                f"  密码字段: {result['password_field_readable']} (防护: {result['password_protection']})"
            )
            print(
                f"  邮箱字段: {result['email_field_readable']} (防护: {result['email_protection']})"
            )

    print(f"\n✓ 结果已保存到: {output_file}")
    print("=" * 70)


if __name__ == "__main__":
    main()
