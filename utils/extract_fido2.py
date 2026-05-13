#!/usr/bin/env python3
"""
从 Bitwarden 导出的 JSON 文件中提取 FIDO2/WebAuthn 凭据。

用法：
    python utils/extract_fido2.py bitwarden_export.json              # 列出所有 FIDO2 凭据
    python utils/extract_fido2.py bitwarden_export.json --rp authserver.nwafu.edu.cn  # 按 rpId 筛选
    python utils/extract_fido2.py bitwarden_export.json --name NWAFU  # 按条目名筛选
    python utils/extract_fido2.py bitwarden_export.json --name NWAFU --full-key  # 显示完整 keyValue
    python utils/extract_fido2.py bitwarden_export.json --name NWAFU --save  # 保存到 .data/fido2_credential.json
"""

import argparse
import json
import os
import sys


def find_fido2_items(data: dict) -> list[dict]:
    """遍历 Bitwarden 导出数据，返回所有包含 FIDO2 凭据的条目信息。"""
    results = []
    for item in data.get("items", []):
        if item.get("type") != 1:  # type=1 是登录类型
            continue
        login = item.get("login", {})
        credentials = login.get("fido2Credentials", [])
        if not credentials:
            continue

        for cred in credentials:
            results.append({
                "entry_name": item.get("name", "?"),
                "username": login.get("username", ""),
                "credential_id": cred.get("credentialId", ""),
                "rp_id": cred.get("rpId", ""),
                "rp_name": cred.get("rpName", ""),
                "key_algorithm": cred.get("keyAlgorithm", ""),
                "key_curve": cred.get("keyCurve", ""),
                "raw": cred,
            })
    return results


def save_credential(cred: dict, target_dir: str) -> str:
    """保存单个凭据到 JSON 文件。"""
    os.makedirs(target_dir, exist_ok=True)
    path = os.path.join(target_dir, "fido2_credential.json")
    with open(path, "w") as f:
        json.dump(cred, f, indent=2, ensure_ascii=False)
    return path


def main():
    parser = argparse.ArgumentParser(
        description="从 Bitwarden 导出 JSON 中提取 FIDO2/WebAuthn 凭据",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("file", help="Bitwarden 导出的 JSON 文件路径")
    parser.add_argument("--rp", "-r", help="按 rpId 筛选 (如 authserver.nwafu.edu.cn)")
    parser.add_argument("--name", "-n", help="按条目名筛选 (如 NWAFU)")
    parser.add_argument("--full-key", "-k", action="store_true", help="显示完整 keyValue")
    parser.add_argument("--save", "-s", action="store_true", help="保存到 .data/fido2_credential.json")
    parser.add_argument("--device-id", "-d", help="设备绑定 ID（anonbiometricsd），从浏览器 localStorage 获取")

    args = parser.parse_args()

    # 读取导出文件
    try:
        with open(args.file, "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"错误：文件不存在 — {args.file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"错误：JSON 解析失败 — {e}")
        sys.exit(1)

    if data.get("encrypted", True):
        print("错误：Bitwarden 导出文件是加密的，请使用未加密格式重新导出")
        sys.exit(1)

    # 提取
    items = find_fido2_items(data)

    # 筛选
    if args.rp:
        items = [i for i in items if i["rp_id"] == args.rp]
    if args.name:
        items = [i for i in items if i["entry_name"] == args.name]

    if not items:
        print(f"未找到匹配的 FIDO2 凭据")
        if not args.rp and not args.name:
            print("（该导出文件中没有 FIDO2 凭据）")
        sys.exit(0)

    # 输出
    for i, item in enumerate(items):
        print(f"\n{'=' * 60}")
        print(f"条目名称:  {item['entry_name']}")
        print(f"用户名:    {item['username']}")
        print(f"RP ID:     {item['rp_id']}")
        print(f"RP Name:   {item['rp_name']}")
        print(f"算法:      {item['key_algorithm']} {item['key_curve']}")
        print(f"凭据 ID:   {item['credential_id']}")
        if args.full_key:
            print(f"keyValue:  {item['raw'].get('keyValue', '')}")
        else:
            key_val = item['raw'].get('keyValue', '')
            print(f"keyValue:  {key_val[:40]}...{key_val[-20:]} (共 {len(key_val)} 字符)")

    # 保存
    if args.save:
        if len(items) > 1:
            print(f"\n警告：匹配到 {len(items)} 个凭据，仅保存第一个 ({items[0]['entry_name']})")

        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        target_dir = os.path.join(repo_root, ".data")
        cred = items[0]["raw"]
        if args.device_id:
            cred["deviceBindingId"] = args.device_id
            print(f"已注入 deviceBindingId: {args.device_id}")
        path = save_credential(cred, target_dir)
        print(f"\n已保存到: {path}")


if __name__ == "__main__":
    main()
