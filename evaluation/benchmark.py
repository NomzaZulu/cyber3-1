"""CyberGuard evaluation suite.

This module is intentionally separate from the live application. It calls the
existing Digital Impersonation and Account Takeover services without changing
those engines, APIs, frontend code, scoring rules, or production datasets.

Important:
- Digital Impersonation is evaluated against the bundled labelled CSV.
- Account Takeover is evaluated against a frozen, controlled synthetic
  scenario set stored in evaluation/ato_evaluation_cases.json.
- The ATO metrics are engineering-validation metrics, not real-world or
  independently collected production accuracy.
- Phishing is not executed here because the current phishing implementation
  runs through the configured Hugging Face Space from the browser and there
  is no local labelled phishing test runner in this repository.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
EVALUATION_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from digital_impersonation.digital_impersonation_service import analyze_digital_impersonation
from account_takeover.account_takeover_service import analyze_account_takeover


def binary_metrics(expected, predicted):
    tp = sum(bool(e) and bool(p) for e, p in zip(expected, predicted))
    tn = sum((not bool(e)) and (not bool(p)) for e, p in zip(expected, predicted))
    fp = sum((not bool(e)) and bool(p) for e, p in zip(expected, predicted))
    fn = sum(bool(e) and (not bool(p)) for e, p in zip(expected, predicted))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    accuracy = (tp + tn) / len(expected) if expected else 0.0
    false_positive_rate = fp / (fp + tn) if fp + tn else 0.0
    return {
        "samples": len(expected),
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(false_positive_rate, 4),
    }


def run_digital_impersonation():
    messages = pd.read_csv(ROOT / "cyberguard_impersonation_messages.csv")
    result = analyze_digital_impersonation(
        messages,
        organisation="Acme Corporation",
        organisation_domain="acme-corp.com",
    )

    flagged_ids = {
        str(item["message_id"])
        for item in result["messages"]
        if str(item.get("risk_level", "LOW")).upper() in {"HIGH", "MEDIUM"}
    }

    scored = messages[messages["expected_label"].isin(["malicious", "benign"])].copy()
    expected = [row.expected_label == "malicious" for _, row in scored.iterrows()]
    predicted = [str(row.message_id) in flagged_ids for _, row in scored.iterrows()]

    borderline = messages[messages["expected_label"] == "borderline"]
    borderline_flagged = sum(
        str(row.message_id) in flagged_ids
        for _, row in borderline.iterrows()
    )

    return {
        "module": "Digital Impersonation",
        "evaluation_type": "labelled bundled dataset",
        "dataset": "cyberguard_impersonation_messages.csv",
        "total_messages": len(messages),
        "scored_messages": len(scored),
        "binary_metrics": binary_metrics(expected, predicted),
        "borderline": {
            "total": len(borderline),
            "flagged": borderline_flagged,
        },
        "risk_distribution": {
            "high": result["summary"]["high_risk"],
            "medium": result["summary"]["medium_risk"],
            "low": result["summary"]["low_risk"],
        },
    }


def run_account_takeover():
    cases_path = EVALUATION_DIR / "ato_evaluation_cases.json"
    dataset = json.loads(cases_path.read_text())

    expected = []
    predicted = []
    detector_results = []

    for case in dataset["cases"]:
        events = pd.DataFrame(case["events"])
        profiles = pd.DataFrame(dataset["profiles"])
        result = analyze_account_takeover(
            events,
            profiles,
            "Acme Corporation",
            "acme-corp.com",
        )

        flagged = result["summary"]["accounts_flagged"] > 0
        expected_attack = case["expected_label"] == "malicious"
        expected.append(expected_attack)
        predicted.append(flagged)

        triggered = sorted({
            str(d.get("threat"))
            for d in result.get("detections", [])
            if d.get("threat")
        })
        expected_detector = case["expected_detector"]
        detector_hit = (
            expected_detector == "None"
            if not expected_attack
            else expected_detector in triggered
        )

        detector_results.append({
            "case_id": case["case_id"],
            "expected_label": case["expected_label"],
            "expected_detector": expected_detector,
            "flagged": flagged,
            "risk_levels": sorted({
                str(account.get("risk_level"))
                for account in result.get("accounts", [])
                if account.get("risk_level")
            }),
            "triggered_detectors": triggered,
            "expected_detector_hit": detector_hit,
        })

    per_detector = {}
    malicious_cases = [item for item in detector_results if item["expected_label"] == "malicious"]
    for detector in sorted({item["expected_detector"] for item in malicious_cases}):
        subset = [item for item in malicious_cases if item["expected_detector"] == detector]
        hits = sum(item["expected_detector_hit"] for item in subset)
        per_detector[detector] = {
            "cases": len(subset),
            "detected": hits,
            "detection_rate": round(hits / len(subset), 4) if subset else 0.0,
        }

    metrics = binary_metrics(expected, predicted)
    return {
        "module": "Account Takeover",
        "evaluation_type": dataset["dataset_type"],
        "dataset": cases_path.name,
        "warning": dataset["warning"],
        "cases": len(detector_results),
        "binary_metrics": metrics,
        "per_detector": per_detector,
        "case_results": detector_results,
    }


def run_phishing_status():
    return {
        "module": "Phishing",
        "status": "not_locally_benchmarked",
        "reason": (
            "The current repository connects phishing inference to the configured "
            "Hugging Face Space from the browser and does not contain a local labelled "
            "phishing evaluation runner. No phishing accuracy/precision/recall/F1 is "
            "invented by this suite."
        ),
    }


def main():
    report = {
        "suite": "CyberGuard Evaluation Suite v1",
        "scope": "Independent evaluation of existing detection services; production code is not modified by the benchmark.",
        "digital_impersonation": run_digital_impersonation(),
        "account_takeover": run_account_takeover(),
        "phishing": run_phishing_status(),
    }

    output_path = EVALUATION_DIR / "latest_benchmark_report.json"
    output_path.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    print(f"\nSaved report: {output_path}")


if __name__ == "__main__":
    main()
