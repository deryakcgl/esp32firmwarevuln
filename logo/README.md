Place your application logo here as **`logo.png`** (recommended: square or wide PNG, ~256–512 px).

The desktop app loads `logo/logo.png` for the header and window icon.

## CWE Excel (training)

You can upload a **CWE catalog** spreadsheet with columns such as:
`record_type`, `cwe_id`, `cwe_name`, `use_as_label`, `llm_labeling_rule`, `detection_signals`, `esp32_relevance`, …

Ollama uses `llm_labeling_rule` and `detection_signals` when labeling functions.
Only rows with `use_as_label = 1` are included (default: include if empty).
