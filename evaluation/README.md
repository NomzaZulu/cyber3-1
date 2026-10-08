# CyberGuard Evaluation Suite

This directory contains a **separate evaluation layer** for the existing CyberGuard detection services.

The evaluation code does **not** run as part of the live website and does not modify the production frontend, APIs, detection engines, risk engines, or production datasets.

## Run

From the project root:

```bash
python evaluation/benchmark.py
```

The runner writes:

```text
evaluation/latest_benchmark_report.json
```

and prints the same report to the terminal.

## What is evaluated

### 1. Digital Impersonation

Uses the existing:

```text
cyberguard_impersonation_messages.csv
```

The 20 `borderline` records are reported separately. Only the 80 `malicious` and 20 `benign` records are used for binary classification metrics.

Reported metrics:

- Accuracy
- Precision
- Recall
- F1
- False-positive rate
- TP / TN / FP / FN
- Borderline flag count
- Risk-level distribution

Current result from this repository:

- Accuracy: **85.00%**
- Precision: **98.51%**
- Recall: **82.50%**
- F1: **89.80%**
- False-positive rate: **5.00%**
- TP: 66
- TN: 19
- FP: 1
- FN: 14

### 2. Account Takeover

Uses the existing Account Takeover service against the frozen:

```text
evaluation/ato_evaluation_cases.json
```

The dataset contains 24 controlled scenarios:

- 12 malicious scenarios
- 12 benign control scenarios
- 2 cases for each of the six ATO detectors

The six detector scenarios are:

1. Multiple Failed Login Attempts
2. Password Spraying
3. Unusual Login Location
4. Unknown / New Device
5. Suspicious Session Activity
6. Sudden Account Behaviour Change

Current controlled-validation result:

- Accuracy: **100.00%**
- Precision: **100.00%**
- Recall: **100.00%**
- F1: **100.00%**
- False-positive rate: **0.00%**
- TP: 12
- TN: 12
- FP: 0
- FN: 0

Each detector also reports its controlled scenario detection rate.

### Important limitation

The ATO dataset is **authored synthetic test data designed to exercise the existing detector thresholds and behaviours**. It is useful for engineering validation and regression testing, but it is **not an independent real-world benchmark** and must not be presented as production accuracy.

The current repository does not contain a local labelled phishing evaluation runner. Phishing inference is connected to the configured Hugging Face Space from the browser, so this suite deliberately reports phishing as **not locally benchmarked** rather than inventing metrics.

## What this suite does NOT do

It does not:

- change detector logic
- change risk scoring
- change API behaviour
- change frontend behaviour
- run during normal website usage
- alter production datasets
- claim that the three modules form one statistically comparable model benchmark
- invent a single overall CyberGuard accuracy number
