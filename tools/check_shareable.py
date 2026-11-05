#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""分享/分发前卫生检查：扫描目录或压缩包中的敏感文件。

背景：``.gitignore`` 只约束 git；把整个工作目录"顺手打包"发给客户、上传网盘或
交给第三方审计时，密钥、配置与数据库会照常进门。本工具把这类事故拦在门外。

用法::

    python tools/check_shareable.py <目录或 .zip> [--fail-on critical|high|medium|low|never]
                                     [--json] [--max-report N]

级别定义：

- ``critical`` 发布签名私钥、服务器配置（含全部密钥）、授权数据库、签名密钥库
- ``high``     客户端配置、备份目录、通用私钥/凭据文件
- ``medium``   崩溃日志、构建状态文件（release_identity / release_pubkey）
- ``low``      测试缓存、构建日志、.git 历史等"含本机信息"项

退出码：0=未发现达到阈值的项；1=发现；2=用法/路径错误。默认 ``--fail-on high``。

扫描规则对目录与 zip 一致（zip 扫描一层内容；内层压缩包单独提示人工复核）。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import zipfile
from pathlib import Path

__all__ = ["check_path", "main"]

# --------------------------------------------------------------------------- #
# 规则表
# --------------------------------------------------------------------------- #
# 每条规则 = (匹配方式, 模式, 级别, 说明)
#   匹配方式: name=文件名精确 | ext=扩展名 | dir=路径段精确 | dir_prefix=路径段前缀
RULES: list[tuple[str, str, str, str]] = [
    ("name", "release_key.json", "critical", "发布签名私钥（泄露=可伪造任意发布清单）"),
    ("dir", "release_keys", "critical", "发布签名密钥目录（必须离线保管）"),
    ("dir_prefix", "backup_secrets", "critical", "旧密钥/数据备份目录（切勿随包分发）"),
    ("name", "server_config.json", "critical", "服务器配置（含 HMAC / 离线签名 / 响应签名全部私钥）"),
    ("name", "admin_config.json", "high", "管理端配置（含固定公钥与用户偏好）"),
    ("name", "master_config.json", "high", "主控端配置（含固定公钥与用户偏好）"),
    ("name", "verification_config.json", "high", "验证端配置（含固定公钥与离线缓存）"),
    ("name", "config.json", "high", "旧版共享配置（可能残留密钥字段）"),
    ("ext", ".db", "critical", "授权数据库（含卡密与设备绑定）"),
    ("ext", ".db-shm", "critical", "授权数据库 WAL 共享内存"),
    ("ext", ".db-wal", "critical", "授权数据库 WAL 日志"),
    ("ext", ".sqlite", "critical", "授权数据库"),
    ("ext", ".sqlite3", "critical", "授权数据库"),
    ("ext", ".p12", "critical", "签名密钥库（私钥）"),
    ("ext", ".pfx", "critical", "签名密钥库（私钥）"),
    ("ext", ".jks", "critical", "Java 密钥库（私钥）"),
    ("ext", ".keystore", "critical", "密钥库（私钥）"),
    ("ext", ".key", "high", "私钥文件"),
    ("ext", ".pem", "high", "PEM 文件（可能是私钥，需人工确认）"),
    ("name", "release_identity.py", "medium", "构建标识（随源码分发会与发布清单绑定校验冲突）"),
    ("name", "release_pubkey.py", "medium", "构建期固定公钥（发布卫生要求独立于源码分发）"),
    ("dir", "crash_logs", "medium", "崩溃日志（含本机路径与调用栈）"),
    ("name", "build_log.txt", "low", "构建日志（可能含本机路径）"),
    ("dir", ".pytest_cache", "low", "测试缓存（含本机路径）"),
    ("dir", ".git", "low", "版本库历史（分发前确认历史中无敏感内容）"),
]

_LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "never": 99}
_SKIP_DIRS = {"__pycache__", "node_modules"}


def _match_rule(parts: tuple[str, ...], rule: tuple[str, str, str, str]) -> bool:
    kind, pattern, _level, _desc = rule
    name = parts[-1] if parts else ""
    if kind == "name":
        return name == pattern
    if kind == "ext":
        return name.lower().endswith(pattern)
    if kind == "dir":
        return any(part == pattern for part in parts[:-1])
    if kind == "dir_prefix":
        return any(part.startswith(pattern) for part in parts[:-1]) or name.startswith(pattern)
    return False


def _scan_entries(entries: list[str]) -> list[dict]:
    """对一组相对路径应用规则表，返回命中列表。"""
    findings: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for raw in entries:
        parts = tuple(p for p in str(raw).replace("\\", "/").split("/") if p and p != ".")
        if not parts:
            continue
        if any(part in _SKIP_DIRS for part in parts[:-1]):
            continue
        for rule in RULES:
            if _match_rule(parts, rule):
                key = ("/".join(parts), rule[2])
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    {"path": "/".join(parts), "level": rule[2], "reason": rule[3]}
                )
    return findings


def _scan_directory(root: Path) -> tuple[list[dict], list[str]]:
    entries: list[str] = []
    notes: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        rel_base = base.relative_to(root)
        if str(rel_base) != ".":
            entries.append(str(rel_base))
        keep: list[str] = []
        for name in dirnames:
            if name in _SKIP_DIRS:
                continue
            if name == ".git":
                # 只记录 .git 存在（low 提示），不递归进去（历史条目海量且无法按名匹配）。
                child = rel_base / name if str(rel_base) != "." else Path(name)
                entries.append(str(child))
                continue
            keep.append(name)
        dirnames[:] = keep
        for name in filenames:
            child = rel_base / name if str(rel_base) != "." else Path(name)
            entries.append(str(child))
    return _scan_entries(entries), notes


def _scan_zip(path: Path) -> tuple[list[dict], list[str]]:
    notes: list[str] = []
    with zipfile.ZipFile(path) as archive:
        raw_names = archive.namelist()
    normalized = [n.replace("\\", "/") for n in raw_names]
    names = [n for n in normalized if "/.git/" not in f"/{n}" and not n.startswith(".git/")]
    if any("/.git/" in f"/{n}" or n.startswith(".git/") for n in normalized):
        names.append(".git")
    findings = _scan_entries(names)
    for name in normalized:
        lower = name.lower()
        if lower.endswith((".zip", ".7z", ".tar", ".tar.gz", ".tgz", ".rar")):
            notes.append(f"嵌套压缩包需人工复核：{name}")
    return findings, notes


def check_path(target: str) -> dict:
    """扫描单个目录或 zip；返回结构化结果（含 findings / notes / summary）。"""
    path = Path(target).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"路径不存在：{path}")
    if path.is_dir():
        findings, notes = _scan_directory(path)
        kind = "directory"
    elif path.is_file() and path.suffix.lower() == ".zip":
        findings, notes = _scan_zip(path)
        kind = "zip"
    elif path.is_file():
        findings, notes = _scan_entries([path.name]), []
        kind = "file"
    else:
        raise ValueError(f"不支持的目标类型：{path}")

    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for item in findings:
        counts[item["level"]] = counts.get(item["level"], 0) + 1
    findings.sort(key=lambda f: (_LEVEL_ORDER.get(f["level"], 9), f["path"]))
    return {
        "target": str(path),
        "kind": kind,
        "findings": findings,
        "notes": notes,
        "summary": counts,
    }


def _print_report(result: dict, max_report: int) -> None:
    icons = {"critical": "!!", "high": "! ", "medium": "~ ", "low": ". "}
    print(f"目标：{result['target']}（{result['kind']}）")
    if result["findings"]:
        print(f"发现 {len(result['findings'])} 项（按级别排序）：")
        for item in result["findings"][:max_report]:
            print(f"  [{item['level']:>8}] {icons.get(item['level'], '  ')} {item['path']}")
            print(f"              -> {item['reason']}")
        if len(result["findings"]) > max_report:
            print(f"  ...（其余 {len(result['findings']) - max_report} 项省略，--max-report 调整）")
    else:
        print("✓ 未发现敏感文件。")
    for note in result["notes"]:
        print(f"  提示: {note}")
    s = result["summary"]
    print(f"汇总：critical={s['critical']} high={s['high']} medium={s['medium']} low={s['low']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="分享/分发前卫生检查：扫描目录或 zip 中的敏感文件",
    )
    parser.add_argument("target", help="目录或 .zip 路径")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "never"],
        default="high",
        help="达到该级别即退出码 1（默认 high）",
    )
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    parser.add_argument("--max-report", type=int, default=200, help="控制台最多列出多少项")
    args = parser.parse_args(argv)

    try:
        result = check_path(args.target)
    except (FileNotFoundError, ValueError, zipfile.BadZipFile) as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        _print_report(result, max(1, args.max_report))

    threshold = _LEVEL_ORDER[args.fail_on]
    hit = any(_LEVEL_ORDER.get(item["level"], 9) <= threshold for item in result["findings"])
    if hit and args.fail_on != "never":
        print(f"结论：发现达到 [{args.fail_on}] 及以上的敏感项——请先清理再分享。")
        return 1
    print("结论：通过（未发现达到阈值的敏感项）。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
