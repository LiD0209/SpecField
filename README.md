# SpecTrace

SpecTrace 是一个面向协议规范（当前以 TLS 1.3 / RFC 8446 为例）的自动化抽取与代码关联项目，目标是把规范中的字段定义、取值约束、变化规则，逐步映射到代码上下文，辅助审查与条件追踪。

## 主要能力

- 对规范文本进行预处理与分块
- 抽取协议字段定义（definition）
- 抽取字段取值变化与判断规则（change / judgment）
- 汇总为结构化结果并生成后续分析输入
- 扫描代码符号并进行跨文件相关性检索

## 项目结构

```text
.
├─ document/                     # 规范原文（如 TLS1.3.txt）
├─ output/                       # 各阶段输出结果
├─ utils/                        # 辅助流程与二次分析脚本
├─ scan_symbols.py               # 扫描 C/Java 符号，输出 symbols.csv/json
├─ step0_preprocess.py           # 规范预处理与分块
├─ step1_variable_definitions.py # 抽取字段定义
├─ step2_variable_changes.py     # 抽取字段变化/约束规则
├─ step3_variable_summary.py     # 汇总输出
├─ step4_find_related_names.py   # 从变更记录检索相关文件/变量
├─ step5_describe_code_with_context.py # 结合代码上下文生成描述
├─ result.json                   # 聚合结果示例
└─ symbols.csv / symbols.json    # 符号索引
```

## 环境要求

- Python 3.10+
- 依赖包（按脚本使用情况安装）：
  - `tree-sitter`
  - `tree-sitter-c`
  - `tree-sitter-java`

示例安装：

```bash
pip install tree-sitter tree-sitter-c tree-sitter-java
```

## 快速开始

1. 预处理规范文本：

```bash
python step0_preprocess.py --doc document/TLS1.3.txt --output-dir output
```

2. 抽取字段定义（需要模型 API Key）：

```bash
python step1_variable_definitions.py --api-key YOUR_API_KEY
```

3. 抽取字段变化规则：

```bash
python step2_variable_changes.py --api-key YOUR_API_KEY
```

4. 汇总输出：

```bash
python step3_variable_summary.py --api-key YOUR_API_KEY
```

5. 扫描代码符号（用于后续代码关联）：

```bash
python scan_symbols.py . --csv symbols.csv --json symbols.json
```

## 输出说明

- `output/01_variable_definitions.json`：字段定义抽取结果
- `output/02_variable_changes.json`：字段变化/约束规则结果
- `output/03_variable_summary.md`：汇总表
- `output/04_related_files*.json`：相关文件检索结果
- `result.json`：聚合后的审查结果

## 说明

- 当前仓库已包含一批示例输出文件，便于离线查看流程产物。
- 部分脚本依赖外部 LLM API，请根据实际服务商填写 `--base-url` 与 `--model` 参数。
