#!/usr/bin/env python3
"""
Ghost Bits Detector - Java Ghost Bits 漏洞代码审计工具

扫描 Java 源代码中可能触发 Ghost Bits 漏洞的危险写法：
  - (byte) char 强制类型转换
  - ch & 0xFF / ch & 255 位运算截断
  - OutputStream.write(int) / ByteArrayOutputStream.write(int)
  - DataOutputStream.writeBytes(String)
  - URLDecoder.decode 宽松解码
  - Character.digit 宽松数字转换
  - String.getBytes(int,int,byte[],int) 废弃API

用法:
  python ghost_bits_scanner.py <目录或文件>
  python ghost_bits_scanner.py ./src
  python ghost_bits_scanner.py ./project --ext .java,.jsp
"""
import os
import re
import sys
import argparse
import json
from pathlib import Path

# 危险代码模式 (正则表达式)
DANGEROUS_PATTERNS = [
    {
        "id": "GB-001",
        "name": "byte 强制转换",
        "pattern": r"\(\s*byte\s*\)\s*\w+",
        "severity": "HIGH",
        "description": "char 到 byte 的直接强制转换会丢弃高 8 位",
        "fix": "使用指定编码的 getBytes() 或检查字符范围",
    },
    {
        "id": "GB-002",
        "name": "& 0xFF 位运算截断",
        "pattern": r"&\s*0[xX][fF][fF]\b|&\s*255\b",
        "severity": "HIGH",
        "description": "ch & 0xFF 只保留低 8 位，高位静默丢失",
        "fix": "先检查字符是否在 ASCII 范围内再做位运算",
    },
    {
        "id": "GB-003",
        "name": "OutputStream.write(int)",
        "pattern": r"\.write\s*\(\s*\w+\s*\)",
        "severity": "MEDIUM",
        "description": "OutputStream.write(int) 和 ByteArrayOutputStream.write(int) 只写入低 8 位",
        "fix": "使用 write(byte[]) 或 write(byte[], int, int)",
    },
    {
        "id": "GB-004",
        "name": "DataOutputStream.writeBytes",
        "pattern": r"writeBytes\s*\(",
        "severity": "HIGH",
        "description": "DataOutputStream.writeBytes(String) 丢弃每个字符的高 8 位",
        "fix": "使用 writeUTF() 或 writeChars()",
    },
    {
        "id": "GB-005",
        "name": "废弃 String.getBytes",
        "pattern": r"getBytes\s*\(\s*\d+\s*,",
        "severity": "HIGH",
        "description": "String.getBytes(int, int, byte[], int) 已废弃，存在 Ghost Bits 风险",
        "fix": "使用 String.getBytes(Charset) 或 String.getBytes(String charsetName)",
    },
    {
        "id": "GB-006",
        "name": "URLDecoder 宽松解码",
        "pattern": r"URLDecoder\.decode\s*\(",
        "severity": "MEDIUM",
        "description": "URLDecoder.decode 可能对非法编码做宽松处理",
        "fix": "验证输入只包含合法的 URL 编码字符",
    },
    {
        "id": "GB-007",
        "name": "Character.digit 宽松转换",
        "pattern": r"Character\.digit\s*\(",
        "severity": "MEDIUM",
        "description": "Character.digit 接受 Unicode 数字字符，可能被利用",
        "fix": "先检查字符范围 (0-9, a-f, A-F) 再做转换",
    },
    {
        "id": "GB-008",
        "name": "RandomAccessFile.writeBytes",
        "pattern": r"RandomAccessFile.*writeBytes",
        "severity": "HIGH",
        "description": "RandomAccessFile.writeBytes 丢弃字符高位",
        "fix": "使用 writeUTF() 或先转为 byte[]",
    },
    {
        "id": "GB-009",
        "name": "StringBufferInputStream",
        "pattern": r"StringBufferInputStream",
        "severity": "HIGH",
        "description": "StringBufferInputStream.read() 只返回低 8 位，已废弃",
        "fix": "使用 ByteArrayInputStream 配合 getBytes()",
    },
    {
        "id": "GB-010",
        "name": "宽松 Hex 解码",
        "pattern": r"fromHex|hexToBytes|hexDecode",
        "severity": "LOW",
        "description": "自定义 Hex 解码可能对非法字符做宽松处理",
        "fix": "严格校验输入只包含 0-9a-fA-F",
    },
]


class GhostBitsScanner:
    def __init__(self, extensions=None):
        self.extensions = extensions or [".java", ".jsp", ".kt", ".scala"]
        self.findings = []

    def scan_file(self, filepath):
        """扫描单个文件"""
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            return []

        file_findings = []
        for lineno, line in enumerate(lines, 1):
            for pattern_def in DANGEROUS_PATTERNS:
                matches = re.finditer(pattern_def["pattern"], line)
                for match in matches:
                    # 过滤注释行
                    stripped = line.strip()
                    if stripped.startswith("//") or stripped.startswith("*"):
                        continue

                    finding = {
                        "file": filepath,
                        "line": lineno,
                        "column": match.start() + 1,
                        "rule_id": pattern_def["id"],
                        "rule_name": pattern_def["name"],
                        "severity": pattern_def["severity"],
                        "match": match.group(),
                        "code": line.rstrip(),
                        "description": pattern_def["description"],
                        "fix": pattern_def["fix"],
                    }
                    file_findings.append(finding)

        return file_findings

    def scan_directory(self, dirpath):
        """递归扫描目录"""
        all_findings = []
        for root, dirs, files in os.walk(dirpath):
            # 跳过常见无关目录
            dirs[:] = [d for d in dirs if d not in
                       (".git", "node_modules", "target", "build", ".idea", ".gradle")]

            for filename in files:
                ext = os.path.splitext(filename)[1]
                if ext in self.extensions:
                    filepath = os.path.join(root, filename)
                    findings = self.scan_file(filepath)
                    all_findings.extend(findings)

        return all_findings

    def scan(self, path):
        """扫描文件或目录"""
        if os.path.isfile(path):
            return self.scan_file(path)
        elif os.path.isdir(path):
            return self.scan_directory(path)
        else:
            print(f"[-] Path not found: {path}")
            return []

    def print_report(self, findings):
        """打印扫描报告"""
        if not findings:
            print("\n[+] No Ghost Bits vulnerabilities found!")
            return

        # 按严重程度分组统计
        severity_count = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            severity_count[f["severity"]] += 1

        print("\n" + "=" * 70)
        print("  Ghost Bits Vulnerability Scan Report")
        print("=" * 70)
        print(f"  Total findings: {len(findings)}")
        print(f"  HIGH:   {severity_count['HIGH']}")
        print(f"  MEDIUM: {severity_count['MEDIUM']}")
        print(f"  LOW:    {severity_count['LOW']}")
        print("=" * 70)

        # 按文件分组显示
        current_file = None
        for f in findings:
            if f["file"] != current_file:
                current_file = f["file"]
                print(f"\n  [{current_file}]")

            severity_icon = {"HIGH": "!!!", "MEDIUM": "!! ", "LOW": "!  "}
            print(f"  {severity_icon[f['severity']]} {f['rule_id']} "
                  f"Line {f['line']}:{f['column']} "
                  f"[{f['severity']}] {f['rule_name']}")
            print(f"      {f['code'].strip()[:100]}")
            print(f"      Fix: {f['fix']}")


def main():
    parser = argparse.ArgumentParser(
        description="Ghost Bits Vulnerability Scanner for Java")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--ext", default=".java,.jsp,.kt,.scala",
                        help="File extensions to scan (comma-separated)")
    parser.add_argument("--json", action="store_true",
                        help="Output findings as JSON")
    parser.add_argument("--rules", action="store_true",
                        help="List all detection rules")
    args = parser.parse_args()

    if args.rules:
        print("Ghost Bits Detection Rules:")
        for p in DANGEROUS_PATTERNS:
            print(f"  {p['id']} [{p['severity']}] {p['name']}")
            print(f"    Pattern: {p['pattern']}")
            print(f"    Desc:    {p['description']}")
        return

    extensions = ["." + e.strip() if not e.strip().startswith(".")
                  else e.strip() for e in args.ext.split(",")]

    scanner = GhostBitsScanner(extensions=extensions)
    findings = scanner.scan(args.path)

    if args.json:
        print(json.dumps(findings, indent=2, ensure_ascii=False))
    else:
        scanner.print_report(findings)


if __name__ == "__main__":
    main()
