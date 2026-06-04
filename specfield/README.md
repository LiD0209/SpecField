# SpecField Pipeline

This directory implements the paper-side SpecField workflow that was not covered by the baseline scripts:

- field-space construction from the protocol standard
- field rule extraction into `(f, C, A, M, E, action_type)`
- rule-to-code alignment with ranked variables and code contexts
- iterative evidence-driven consistency reasoning
- validation-agent artifacts for inconsistent reports
- RQ3/RQ4/RQ5 aggregation utilities

The scripts run without an LLM by using deterministic fallbacks. Add `--use-llm` and API settings to use the prompt-driven paths.

## End-To-End Run

```powershell
python specfield\core.py `
  --standard-doc document\TLS1.3.txt `
  --repo-root . `
  --output-dir output\specfield_full `
  --max-rules 50
```

Useful outputs:

- `01_field_space.json`: extracted field space.
- `02_field_rules.json`: normalized field rules.
- `03_alignments_and_judgments.json`: aligned evidence and final judgments.
- `validation_artifacts\`: validation plans/results for inconsistent findings.
- `reports\` and `report_index.md`: issue-style Markdown reports.
- `summary.json`: counts of rules, judgments, and validation results.

## Component Experiments

RQ5 component buildup configurations:

```powershell
python specfield\experiments.py `
  --config all `
  --rules output\specfield_full\02_field_rules.json `
  --repo-root . `
  --output-dir output\specfield_components
```

Supported configurations:

- `direct-agent`
- `generic-rag`
- `field-rules`
- `iter-reasoning`
- `forced-binary`
- `full-system`

`full-system` includes iterative reasoning and the validation agent for inconsistent reports.

## Evaluation Tables

RQ3 bug-finding summary:

```powershell
python specfield\evaluate.py rq3 `
  --input output\specfield_full\03_alignments_and_judgments.json `
  --output-json output\specfield_rq3.json `
  --output-md output\specfield_rq3.md
```

RQ4 cost estimate:

```powershell
python specfield\evaluate.py rq4 `
  --input output\specfield_full\03_alignments_and_judgments.json `
  --output-json output\specfield_rq4.json `
  --output-md output\specfield_rq4.md
```

RQ5 component buildup:

```powershell
python specfield\evaluate.py rq5 `
  --config-file direct-agent=output\specfield_components\direct_agent.json `
  --config-file generic-rag=output\specfield_components\generic_rag.json `
  --config-file field-rules=output\specfield_components\field_rules.json `
  --config-file iter-reasoning=output\specfield_components\iter_reasoning.json `
  --config-file forced-binary=output\specfield_components\forced_binary.json `
  --config-file full-system=output\specfield_components\full_system.json
```

Maintainer adjudication labels can be included in input records with keys such as `maintainer_status`, `adjudication`, `outcome`, or `label`. The code aggregates those labels, but the paper's private submitted-report adjudication set is not included in this repository.
