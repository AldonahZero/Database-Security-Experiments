#!/usr/bin/env python3
"""
从Enron邮件数据集中提取员工信息并生成测试数据

数据来源: https://www.cs.cmu.edu/~enron/
数据集: Enron Email Dataset (2015版本)
"""

import os
import re
import email
from email.parser import Parser
from pathlib import Path
from typing import List, Dict, Set
import random
import string

# Enron数据集路径
ENRON_DATA_PATH = Path(__file__).parent.parent / "data" / "maildir"


def generate_strong_password(username: str) -> str:
    """
    为每个用户生成强密码（模拟真实场景）
    格式: 首字母大写+基础名+特殊字符+数字
    """
    base = username.split("-")[0].capitalize()
    special_chars = ["!", "@", "#", "$", "%", "&", "*"]
    special = random.choice(special_chars)
    number = random.randint(2020, 2025)
    return f"{base}{number}{special}"


def extract_email_from_file(file_path: Path) -> str:
    """从邮件文件中提取发件人邮箱地址"""
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            # 解析邮件头
            msg = Parser().parsestr(content)

            # 提取 X-From 字段（这是实际的Enron内部邮箱）
            x_from = msg.get("X-From", "")
            if "@" in x_from:
                # 直接提取邮箱地址
                email_match = re.search(r"[\w\.-]+@[\w\.-]+", x_from)
                if email_match:
                    return email_match.group(0)

            # 备用方案：从 From 字段提取
            from_field = msg.get("From", "")
            if "@" in from_field:
                email_match = re.search(r"[\w\.-]+@[\w\.-]+", from_field)
                if email_match:
                    return email_match.group(0)
    except Exception as e:
        pass
    return None


def scan_employee_emails(limit: int = 50) -> List[Dict[str, str]]:
    """
    扫描Enron数据集，提取员工信息

    Args:
        limit: 最多提取的员工数量

    Returns:
        员工信息列表 [{'username': 'allen-p', 'email': 'phillip.allen@enron.com', 'password': 'Allen2023!'}]
    """
    employees = []
    email_cache = {}  # 缓存已提取的邮箱地址

    if not ENRON_DATA_PATH.exists():
        print(f"❌ Enron数据集路径不存在: {ENRON_DATA_PATH}")
        return []

    # 获取所有员工目录
    employee_dirs = sorted([d for d in ENRON_DATA_PATH.iterdir() if d.is_dir()])
    print(f"📊 发现 {len(employee_dirs)} 个员工目录")

    for emp_dir in employee_dirs[:limit]:
        username = emp_dir.name  # 例如: allen-p

        # 尝试从多个文件夹中提取邮箱地址
        email_address = None
        for folder in ["sent", "sent_items", "_sent_mail", "inbox"]:
            folder_path = emp_dir / folder
            if folder_path.exists():
                # 从前几封邮件中提取
                email_files = list(folder_path.glob("*"))[:5]
                for email_file in email_files:
                    if email_file.is_file():
                        email_address = extract_email_from_file(email_file)
                        if email_address and "@enron.com" in email_address.lower():
                            break
                if email_address:
                    break

        if not email_address:
            # 如果无法提取，生成默认邮箱
            email_address = f"{username}@enron.com"

        # 生成强密码
        password = generate_strong_password(username)

        employees.append(
            {"username": username, "email": email_address.lower(), "password": password}
        )

        print(f"✓ {len(employees):3d}. {username:20s} | {email_address:40s}")

    return employees


def generate_test_data_file(
    employees: List[Dict[str, str]], output_file: str = "enron_test_data.py"
):
    """生成可导入的Python测试数据文件"""
    output_path = Path(__file__).parent / output_file

    with open(output_path, "w", encoding="utf-8") as f:
        f.write('"""\n')
        f.write("Enron数据集测试数据\n")
        f.write("数据来源: https://www.cs.cmu.edu/~enron/\n")
        f.write(f"员工数量: {len(employees)}\n")
        f.write('"""\n\n')
        f.write("# 格式: (username, password, email)\n")
        f.write("ENRON_TEST_USERS = [\n")

        for emp in employees:
            f.write(
                f"    ('{emp['username']}', '{emp['password']}', '{emp['email']}'),\n"
            )

        f.write("]\n\n")
        f.write(f"# 总计: {len(employees)} 个真实Enron员工账户\n")

    print(f"\n✅ 测试数据已保存到: {output_path}")
    return output_path


def generate_sql_insert_file(
    employees: List[Dict[str, str]], output_file: str = "enron_test_data.sql"
):
    """生成SQL INSERT语句文件"""
    output_path = Path(__file__).parent.parent / "results" / output_file

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("-- Enron数据集测试数据\n")
        f.write("-- 数据来源: https://www.cs.cmu.edu/~enron/\n")
        f.write(f"-- 员工数量: {len(employees)}\n\n")
        f.write("-- 基线数据库插入语句\n")
        f.write("INSERT INTO users (username, password, email) VALUES\n")

        for i, emp in enumerate(employees):
            comma = "," if i < len(employees) - 1 else ";"
            f.write(
                f"('{emp['username']}', '{emp['password']}', '{emp['email']}'){comma}\n"
            )

        f.write("\n-- pgcrypto数据库插入语句（密码字段加密）\n")
        f.write("INSERT INTO users (username, password, email) VALUES\n")

        for i, emp in enumerate(employees):
            comma = "," if i < len(employees) - 1 else ";"
            f.write(
                f"('{emp['username']}', pgp_sym_encrypt('{emp['password']}', 'my-secret-key'), '{emp['email']}'){comma}\n"
            )

    print(f"✅ SQL插入语句已保存到: {output_path}")
    return output_path


def print_summary(employees: List[Dict[str, str]]):
    """打印数据摘要"""
    print("\n" + "=" * 80)
    print("📊 Enron数据集加载摘要")
    print("=" * 80)
    print(f"总员工数: {len(employees)}")
    print(f"数据来源: {ENRON_DATA_PATH}")
    print(f"\n前10个员工示例:")
    print("-" * 80)
    print(f"{'用户名':<20} {'邮箱':<40} {'密码长度'}")
    print("-" * 80)

    for emp in employees[:10]:
        print(f"{emp['username']:<20} {emp['email']:<40} {len(emp['password'])} chars")

    print("-" * 80)
    print(f"\n邮箱域名分布:")
    domains = {}
    for emp in employees:
        domain = emp["email"].split("@")[-1]
        domains[domain] = domains.get(domain, 0) + 1

    for domain, count in sorted(domains.items(), key=lambda x: x[1], reverse=True):
        print(f"  @{domain}: {count} ({count/len(employees)*100:.1f}%)")

    print("=" * 80)


def main():
    """主函数"""
    print("🚀 开始加载Enron数据集...")
    print()

    # 扫描并提取员工信息（全部150个员工）
    employees = scan_employee_emails(limit=150)

    if not employees:
        print("❌ 未能提取任何员工信息")
        return

    # 生成测试数据文件
    print("\n" + "=" * 80)
    generate_test_data_file(employees)
    generate_sql_insert_file(employees)

    # 打印摘要
    print_summary(employees)

    print("\n✅ Enron数据集加载完成！")
    print("💡 提示: 可在 test_encryption_protection.py 中导入使用:")
    print("   from enron_test_data import ENRON_TEST_USERS")


if __name__ == "__main__":
    main()
