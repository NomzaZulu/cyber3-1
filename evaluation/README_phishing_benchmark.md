# CyberGuard Phishing Benchmark

## What changed

The phishing module is now benchmarkable through the **same Hugging Face Space used by the CyberGuard frontend**.

- Space: `saswatpatra/cyberguard_phishing`
- Endpoint: `/analyze_message`
- Dataset: `ealvaradob/phishing-dataset/test.json`
- Labels: `1 = phishing`, `0 = benign`
- Default unified-suite sample: **100 cases total, balanced 50 benign + 50 phishing**
- Sampling: deterministic, seed `42`
- Metrics: Accuracy, Precision, Recall, F1, FPR, TP, TN, FP, FN

The benchmark downloads the public test set once into `evaluation/.cache/`, selects a balanced sample, and sends every case through the remote Gradio API.

## Run only the phishing benchmark

```bash
python evaluation/phishing_benchmark.py --samples 100
```

For a larger run:

```bash
python evaluation/phishing_benchmark.py --samples 200
```

The report is written to:

```text
evaluation/phishing_benchmark_report.json
```

## Run the unified suite

```bash
python evaluation/benchmark.py
```

This runs:

1. Digital Impersonation benchmark
2. Account Takeover controlled validation
3. Phishing remote benchmark

To run only the two local modules:

```bash
python evaluation/benchmark.py --skip-phishing
```

## Important interpretation

The phishing numbers produced by this runner are **CyberGuard-specific remote inference evaluation results**. They are not the published model-card metrics and they are not independent production certification.

The test dataset is external/public, and the phishing inference service is hosted remotely. The benchmark therefore measures the behaviour of the configured CyberGuard phishing service on a frozen sample from that labelled test set.

Do not average the phishing, ATO, and digital-impersonation metrics into a single overall CyberGuard accuracy.
