# Field Rule Discovery Baselines

This directory contains the RQ1 field-rule discovery baselines described in the paper:

- `0-shot`: directly extracts field-level rules from each standard chunk.
- `2-shot`: uses the same direct extraction task with two examples in the prompt.
- `schema-only`: uses the structured rule schema, action families, and deterministic validators, but does not build or use a field space/catalog.

It also contains constructed protocol rule sets derived from the repository's existing step2 extraction outputs:

- `mqtt3_1_1_field_rules.json`: MQTT 3.1.1 field rules.
- `tls1_3_field_rules.json`: TLS 1.3 field rules.

Rebuild them with:

```bash
python evalute/field/build_protocol_rule_sets.py --protocol all --repo-root .
```

Run one method:

```bash
python evalute/field/rule_discovery_baselines.py \
  --method schema-only \
  --chunks output/preprocessed_chunks.json \
  --output output/schema_only_field_rules.json \
  --api-key YOUR_API_KEY \
  --base-url https://api.bltcy.ai/v1/ \
  --model gpt-5.4
```

Run all three methods:

```bash
python evalute/field/rule_discovery_baselines.py \
  --method all \
  --chunks output/preprocessed_chunks.json \
  --output output/field_baselines \
  --api-key YOUR_API_KEY
```

Each output file contains:

- `rules`: paper-style field rules with `f`, `C`, `A`, `M`, `E`, `action_type`, and `source_chunk_id`.
- `changes`: compatibility records using the existing pipeline fields such as `variable_name`, `change_condition`, and `change_action`.
- `logs`: per-chunk extraction metadata.
