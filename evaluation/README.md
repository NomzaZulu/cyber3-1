# CyberGuard Evaluation

Run:

```bash
python evaluation/benchmark.py
```

The benchmark reports:

- Digital Impersonation precision, recall and F1 against the labelled CSV.
- Number of high/medium/low impersonation classifications.
- Account Takeover smoke results.
- Which users received attributed Password Spraying evidence.

The evaluation data is separate from the production UI. Do not present benchmark percentages as official model performance unless the test set is frozen and independently reviewed.
