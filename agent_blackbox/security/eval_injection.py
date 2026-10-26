from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
from pydantic import BaseModel

from agent_blackbox.security.injection import InjectionScanner


class MetricsReport(BaseModel):
    total_samples: int
    malicious_count: int
    benign_count: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    details: List[Dict[str, Any]]


def evaluate_corpus(corpus_path: str | Path, threshold_score: int = 40) -> MetricsReport:
    p = Path(corpus_path)
    if not p.exists():
        raise FileNotFoundError(f"Corpus file not found: {p}")

    with open(p, "r", encoding="utf-8") as f:
        samples = json.load(f)

    scanner = InjectionScanner(threshold_score=threshold_score)

    tp = fp = tn = fn = 0
    details = []

    for item in samples:
        sample_id = item.get("id")
        text = item.get("text", "")
        ground_truth = item.get("label", "").lower() == "malicious"
        category = item.get("category", "")

        res = scanner.scan_text(text)
        predicted = res.is_flagged

        if ground_truth and predicted:
            tp += 1
            verdict = "TP"
        elif not ground_truth and predicted:
            fp += 1
            verdict = "FP"
        elif not ground_truth and not predicted:
            tn += 1
            verdict = "TN"
        else:
            fn += 1
            verdict = "FN"

        details.append({
            "id": sample_id,
            "category": category,
            "ground_truth": "malicious" if ground_truth else "benign",
            "predicted": "malicious" if predicted else "benign",
            "risk_score": res.risk_score,
            "verdict": verdict,
            "matched": res.matched_heuristics,
        })

    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    accuracy = ((tp + tn) / len(samples)) if len(samples) > 0 else 0.0

    return MetricsReport(
        total_samples=len(samples),
        malicious_count=tp + fn,
        benign_count=tn + fp,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        accuracy=round(accuracy, 4),
        details=details,
    )


def format_report_markdown(report: MetricsReport) -> str:
    lines = [
        "# AgentBlackbox Injection Scanner // Precision & Recall Evaluation Report",
        "",
        f"- **Total Samples:** {report.total_samples} (Malicious: {report.malicious_count}, Benign: {report.benign_count})",
        f"- **Accuracy:**  `{report.accuracy * 100:.2f}%`",
        f"- **Precision:** `{report.precision * 100:.2f}%` (TP: {report.true_positives}, FP: {report.false_positives})",
        f"- **Recall:**    `{report.recall * 100:.2f}%` (TP: {report.true_positives}, FN: {report.false_negatives})",
        f"- **F1 Score:**  `{report.f1_score * 100:.2f}%`",
        "",
        "## Detailed Confusion Matrix & Breakdown",
        "",
        "| ID | Ground Truth | Predicted | Verdict | Risk Score | Category |",
        "|---|---|---|---|---|---|",
    ]

    for d in report.details:
        lines.append(
            f"| `{d['id']}` | {d['ground_truth']} | {d['predicted']} | **{d['verdict']}** | {d['risk_score']}/100 | `{d['category']}` |"
        )

    return "\n".join(lines)


def main():
    corpus_file = Path(__file__).parent / "corpus" / "injection_corpus.json"
    rep = evaluate_corpus(corpus_file, threshold_score=35)
    print(format_report_markdown(rep))


if __name__ == "__main__":
    main()
