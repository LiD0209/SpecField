# SpecField: Field-Level Conformance Checking Between Protocol Standards and Implementations

This repository contains the prototype code and selected artifacts for SpecField, a framework for checking field-level conformance between natural-language protocol standards and source-code implementations.

SpecField treats protocol fields as anchors between specification text and implementation behavior. It extracts structured field rules, retrieves related code contexts, and records traceable evidence for consistency judgments, reports, and follow-up validation.

## Main Modules

- Protocol standard preprocessing and chunking
- Field-space and field-rule extraction
- Code symbol scanning and context retrieval
- Rule-to-code alignment and evidence-bounded reasoning
- Validation artifact and issue-report generation
- Agent workflow support for multi-step auditing tasks
- Evaluation helpers for rule discovery, alignment, cost, and ablation studies

## Repository Layout

```text
.
|- agent/                          # Agent prompts, task plans, and workflow configurations
|- document/                       # Protocol standards and source documents
|  |- dtls/
|  |- mqtt/
|  |- quic/
|  \- coap/
|- specfield/                      # End-to-end SpecField pipeline
|  |- core.py                      # Field extraction, alignment, reasoning, validation, reports
|  |- experiments.py               # Component configurations for ablation runs
|  \- evaluate.py                  # RQ3/RQ4/RQ5 aggregation utilities
|- evalute/
|  |- field/                       # RQ1 field-rule discovery baselines and gold construction
|  \- context/                     # RQ2 rule-to-code alignment baselines and metrics
|- reports/                        # Confirmed issue analyses grouped by implementation
|  |- wolfssl/
|  |- wolfssl-dtls/
|  |- wolfmqtt/
|  |- openssl/
|  |- mbedtls/
|  |- libcoap/
|  \- quiche/
|- output/                         # Generated pipeline outputs and sample artifacts
|- utils/                          # Follow-up analysis and recheck utilities
|- wolfMQTT/                       # MQTT audit artifacts
|- step0_preprocess.py             # Standard preprocessing
|- step1_variable_definitions.py   # Field definition extraction
|- step2_variable_changes.py       # Field rule/change extraction
|- step3_variable_summary.py       # Summary generation
|- scan_symbols.py                 # Source symbol scanner
|- pipeline_utils.py               # Shared helpers
\- README.md
```

## Environment Setup

Python **3.10+** is recommended.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install tree-sitter tree-sitter-c tree-sitter-java
```

Some pipeline stages call an OpenAI-compatible LLM endpoint. Pass API settings on the command line, or set environment variables used by your local wrapper:

```powershell
$env:OPENAI_API_KEY="your_api_key"
```

Most scripts also accept:

```text
--api-key
--base-url
--model
```

## Reproducible Pipeline

The commands below use the included TLS 1.3 standard as a small starting point. Replace paths as needed for other protocol standards or implementations.

### 1) Preprocess the standard

```powershell
python .\step0_preprocess.py --doc .\document\TLS1.3.txt --output-dir .\output
```

Outputs:

- `output/preprocessed_text.txt`
- `output/preprocessed_chunks.json`

### 2) Extract field definitions

```powershell
python .\step1_variable_definitions.py --api-key YOUR_API_KEY
```

Typical output:

- `output/01_variable_definitions.json`

### 3) Extract field rules and changes

```powershell
python .\step2_variable_changes.py --api-key YOUR_API_KEY
```

Typical output:

- `output/02_variable_changes.json`

### 4) Generate a field summary

```powershell
python .\step3_variable_summary.py --api-key YOUR_API_KEY
```

## SpecField End-to-End Run

Run the paper-side SpecField workflow:

```powershell
python .\specfield\core.py `
  --standard-doc .\document\TLS1.3.txt `
  --repo-root . `
  --output-dir .\output\specfield_full `
  --max-rules 50
```

Useful outputs:

- `output/specfield_full/01_field_space.json`
- `output/specfield_full/02_field_rules.json`
- `output/specfield_full/03_alignments_and_judgments.json`
- `output/specfield_full/reports/`
- `output/specfield_full/summary.json`

## Evaluation Helpers

Build RQ1 gold field-level obligations from the curated rule files:

```powershell
python .\evalute\field\build_gold_obligations.py --repo-root .
```

Run RQ1 field-rule discovery baselines:

```powershell
python .\evalute\field\rule_discovery_baselines.py `
  --method schema-only `
  --chunks .\output\preprocessed_chunks.json `
  --output .\output\schema_only_field_rules.json `
  --api-key YOUR_API_KEY
```

Run RQ5 component configurations:

```powershell
python .\specfield\experiments.py `
  --config all `
  --rules .\output\specfield_full\02_field_rules.json `
  --repo-root . `
  --output-dir .\output\specfield_components
```

Aggregate evaluation outputs:

```powershell
python .\specfield\evaluate.py rq3 --input .\output\specfield_full\03_alignments_and_judgments.json
python .\specfield\evaluate.py rq4 --input .\output\specfield_full\03_alignments_and_judgments.json
```

## Notes

- Generated reports should be reviewed manually before disclosure or submission.
- Some artifacts may be partial or redacted when direct reproduction inputs cannot be shared safely.
