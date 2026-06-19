#!/usr/bin/env python3
"""Ghost Bits Scanner 测试用例"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
from ghost_bits_scanner import GhostBitsScanner, DANGEROUS_PATTERNS

# 测试用 Java 代码
TEST_CODE = '''
import java.io.*;

public class Vulnerable {
    public void bad1(char ch) {
        byte b = (byte) ch;  // GB-001
    }

    public void bad2(char ch) {
        int v = ch & 0xFF;   // GB-002
    }

    public void bad3(OutputStream out, char ch) throws IOException {
        out.write(ch);        // GB-003
    }

    public void bad4(DataOutputStream dos, String str) throws IOException {
        dos.writeBytes(str); // GB-004
    }
}
'''


def test_scanner():
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.java',
                                     delete=False, encoding='utf-8') as f:
        f.write(TEST_CODE)
        filepath = f.name

    scanner = GhostBitsScanner()
    findings = scanner.scan_file(filepath)

    os.unlink(filepath)

    assert len(findings) >= 4, f"Expected at least 4 findings, got {len(findings)}"
    for f in findings:
        assert "rule_id" in f
        assert "severity" in f
        assert "code" in f

    rule_ids = [f["rule_id"] for f in findings]
    assert "GB-001" in rule_ids, "Should detect (byte) cast"
    assert "GB-002" in rule_ids, "Should detect & 0xFF"
    assert "GB-004" in rule_ids, "Should detect writeBytes"

    print(f"[+] Scanner test passed: {len(findings)} findings")


def test_exploit():
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
    from ghost_bits_exploit import GhostBitsGenerator, find_ghost_chars

    # 测试 Ghost Bits 字符查找
    chars = find_ghost_chars(0x2E, count=5)  # '.'
    assert len(chars) == 5
    for c in chars:
        assert (ord(c) & 0xFF) == 0x2E

    # 测试路径穿越 payload
    gen = GhostBitsGenerator()
    payload = gen.gen_path_traversal("/etc/passwd", depth=3)
    assert "/etc/passwd" in payload

    # 验证 (byte) 还原
    decoded = "".join(chr(ord(c) & 0xFF) for c in payload if (ord(c) & 0xFF) < 0x80)
    assert ".%u002e" in decoded

    # 测试文件上传
    upload_payload = gen.gen_file_upload("shell.jsp")
    decoded_upload = "".join(chr(ord(c) & 0xFF) for c in upload_payload)
    assert "jsp" in decoded_upload

    print(f"[+] Exploit test passed")
    print(f"    Path traversal payload length: {len(payload)}")
    print(f"    File upload payload: {upload_payload}")


if __name__ == "__main__":
    test_scanner()
    test_exploit()
    print("\n[+] All tests passed!")
