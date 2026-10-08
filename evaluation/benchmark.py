"""CyberGuard local benchmark runner.

This benchmark intentionally keeps evaluation data separate from the live UI.
It measures the Digital Impersonation engine against the labelled CSV and runs
an Account Takeover smoke benchmark against the bundled telemetry.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from digital_impersonation.digital_impersonation_service import analyze_digital_impersonation
from account_takeover.account_takeover_service import analyze_account_takeover


def binary_metrics(expected, predicted):
    tp = sum(e and p for e, p in zip(expected, predicted))
    tn = sum((not e) and (not p) for e, p in zip(expected, predicted))
    fp = sum((not e) and p for e, p in zip(expected, predicted))
    fn = sum(e and (not p) for e, p in zip(expected, predicted))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "tn": tn, "fp": fp, "fn": fn, "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(f1, 4)}


def main():
    messages = pd.read_csv(ROOT / "cyberguard_impersonation_messages.csv")
    result = analyze_digital_impersonation(messages, organisation="Acme Corporation", organisation_domain="acme-corp.com")
    report = {"digital_impersonation": {}}

    flagged_ids = {str(item["message_id"]) for item in result["messages"] if str(item.get("risk_level", "LOW")).upper() in {"HIGH", "MEDIUM"}}
    scored = messages[messages["expected_label"].isin(["malicious", "benign"])].copy()
    expected = [row.expected_label == "malicious" for _, row in scored.iterrows()]
    predicted = [str(row.message_id) in flagged_ids for _, row in scored.iterrows()]
    report["digital_impersonation"]["binary_metrics"] = binary_metrics(expected, predicted)
    borderline = messages[messages["expected_label"] == "borderline"]
    borderline_flagged = sum(str(row.message_id) in flagged_ids for _, row in borderline.iterrows())
    report["digital_impersonation"]["borderline"] = {
        "total": len(borderline),
        "flagged": borderline_flagged,
        "high": sum(1 for _, row in borderline.iterrows() if str(row.message_id) in flagged_ids and next((m for m in result["messages"] if str(m["message_id"]) == str(row.message_id)), {}).get("risk_level") == "HIGH")
    }
    report["digital_impersonation"]["messages"] = len(messages)
    report["digital_impersonation"]["high"] = result["summary"]["high_risk"]
    report["digital_impersonation"]["medium"] = result["summary"]["medium_risk"]
    report["digital_impersonation"]["low"] = result["summary"]["low_risk"]

    events = pd.read_csv(ROOT / "cyberguard_login_events.csv")
    profiles = pd.read_csv(ROOT / "cyberguard_organisation_profiles.csv")
    ato = analyze_account_takeover(events, profiles, "Acme Corporation", "acme-corp.com")
    report["account_takeover"] = {
        "users": ato["summary"]["users_analyzed"],
        "flagged": ato["summary"]["accounts_flagged"],
        "high": ato["summary"]["high_risk"],
        "medium": ato["summary"]["medium_risk"],
        "low": ato["summary"]["low_risk"],
        "detectors": ato["summary"]["detector_types"],
        "password_spraying_attributed_users": sorted({
            str(d["user_id"]) for d in ato["detections"]
            if d.get("threat") == "Password Spraying" and d.get("user_id")
        }),
    }

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
