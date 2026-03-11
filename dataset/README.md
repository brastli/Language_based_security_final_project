# Dataset 使用说明

本目录用于**手动收集漏洞代码**，便于后续接入扫描/修复流水线或做评估。数据可来自 SARD、GitHub、各类 training apps 等。

---

## 目录结构

```
dataset/
├── README.md          # 本说明
├── case_001/
│   ├── vulnerable.py  # 漏洞代码（你粘贴的位置）
│   ├── metadata.json  # 该 case 的元信息
│   └── test_case.py   # 功能用例（验证行为）
├── case_002/
│   └── ...
...
└── case_025/
    └── ...
```

---

## 每个 case 的作用

- **case_001 ~ case_025**：每个 case 对应**一个**漏洞样本。
- 收集到新漏洞时，选一个未使用的 case 文件夹，把漏洞代码填进该 case 即可。

---

## 每个文件的作用

| 文件 | 作用 |
|------|------|
| **vulnerable.py** | 存放**漏洞代码**。将来自 SARD/GitHub/training app 的漏洞代码整段粘贴到这里，保留或补全必要的 `import`。 |
| **metadata.json** | 记录该 case 的**元数据**：CWE、来源、漏洞行号、函数名等，方便后续统计或流水线使用。 |
| **test_case.py** | **功能用例**。对 `vulnerable.py` 里的函数做一次或多次合法输入调用，用 pytest 等运行，用于验证“修复后行为是否保持”。 |

---

## 如何填写

### 1. vulnerable.py

- 用你收集到的**完整漏洞代码**替换模板内容。
- 保留该文件中的**函数定义**（可多个），确保至少有一个是“含漏洞”的入口，供 Bandit 扫描和后续切片/修复使用。

### 2. metadata.json

按实际填写各字段（可先空着，收集后再补）：

| 字段 | 含义 | 示例 |
|------|------|------|
| `case_id` | 与文件夹名一致 | `"case_001"` |
| `cwe` | CWE 编号 | `"CWE-89"` |
| `bandit_issue` | Bandit 规则 ID 或简短描述 | `"B608"` 或 `"SQL injection"` |
| `source` | 来源 | `"SARD"` / `"GitHub"` / 具体 URL |
| `vuln_line` | 漏洞所在行号（Bandit 报错行） | `5` |
| `function` | 漏洞所在函数名 | `"get_user"` |
| `description` | 简短描述 | `"SQL 拼接导致注入"` |

### 3. test_case.py

- 将 `from vulnerable import example` 中的 **example** 改成你 `vulnerable.py` 里实际的**函数名**。
- 在测试里用**合法输入**调用该函数，断言返回值或副作用（不写死实现细节），确保修复前后都可跑通。

**注意**：`vulnerable.py` 里若改了函数名，这里必须同步改 import 和调用，否则运行会报错。

---

## 使用流程建议

1. 从 SARD/GitHub/training app 复制漏洞代码 → 粘贴到某个 case 的 `vulnerable.py`。
2. 补全或新增该 case 的 `metadata.json`。
3. 根据 `vulnerable.py` 的接口编写/修改 `test_case.py`，保证在合法输入下能通过。
4. 需要跑流水线时，让扫描/切片逻辑指向 `dataset/case_xxx/vulnerable.py` 即可（具体接入方式由主项目决定）。
