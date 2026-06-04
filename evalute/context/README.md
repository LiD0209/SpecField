# Rule-to-Code Alignment Baselines

This directory implements the RQ2 baselines from the paper:

- `exact-match`: lexical overlap between the rule field/aliases and source code.
- `bm25`: sparse lexical retrieval over code chunks.
- `embedding`: dense retrieval over code chunks. It can call an OpenAI-compatible `/embeddings` endpoint, or use the local hash-vector fallback for offline checks.
- `llm-direct`: generic retrieval first, then a direct LLM ranking pass over the retrieved code snippets.

Run one method for a single rule from an existing change file:

```bash
python evalute/context/rule_to_code_alignment_baselines.py \
  --method bm25 \
  --repo-root D:/path/to/implementation \
  --changes output/TLS_02_variable_changes.json \
  --rule-index 1 \
  --output output/bm25_alignment.json
```

Run all non-LLM/LLM methods for a small batch:

```bash
python evalute/context/rule_to_code_alignment_baselines.py \
  --method all \
  --repo-root D:/path/to/implementation \
  --changes output/TLS_02_variable_changes.json \
  --limit 10 \
  --output output/context_alignment_baselines \
  --api-key YOUR_API_KEY
```

Run a single ad-hoc rule:

```bash
python evalute/context/rule_to_code_alignment_baselines.py \
  --method exact-match \
  --repo-root D:/path/to/implementation \
  --var-name cipher_suite \
  --condition "client processes server-selected PSK" \
  --desc "cipher_suite must indicate a hash associated with that PSK" \
  --output output/exact_alignment.json
```

For true API-backed dense retrieval, pass:

```bash
--method embedding --embedding-mode api --embedding-api-key YOUR_API_KEY \
--embedding-base-url https://api.bltcy.ai/v1/ --embedding-model text-embedding-3-large
```

Each output has:

- `ranked_variables`: candidate implementation identifiers.
- `contexts`: top code contexts for judging the rule.
- `candidate_snippets`: raw retrieved snippets with scores and reasons.

## Evaluation Metrics

Use `evaluate_alignment_metrics.py` to compute the paper-style RQ2 metrics:

```bash
python evalute/context/evaluate_alignment_metrics.py \
  --alignment output/bm25_alignment.json \
  --gold evalute/context/gold_alignment_sample.json \
  --output-json output/bm25_alignment_metrics.json \
  --output-md output/bm25_alignment_metrics.md
```

You can repeat `--alignment` to compare methods in one table.

Gold JSON example:

```json
[
  {
    "input_index": 1,
    "gold_variables": ["cipher_suite", "cs.cipherSuite"],
    "gold_contexts": [
      {
        "file": "src/tls13.c",
        "symbol": "FindPskSuiteFromExt",
        "start_line": 700,
        "end_line": 760
      }
    ]
  }
]
```

Metrics:

- `Var@1` / `Var@3`: whether a gold variable appears in the top 1 or top 3 ranked variables.
- `Ctx@1` / `Ctx@3`: whether a gold context overlaps the top 1 or top 3 contexts by file and line range.
- `MRR`: reciprocal rank of the first gold variable.
- `Tok.`: estimated average retrieved/model text tokens per rule, reported in K tokens.
