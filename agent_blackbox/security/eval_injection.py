from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
from pydantic import BaseModel

from agent_blackbox.security.injection import InjectionScanner


class MetricsReport(BaseModel):
    split_name: str = "all"
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


def evaluate_corpus(
    corpus_path: str | Path,
    threshold_score: int = 35,
    split_filter: Optional[str] = None,
) -> MetricsReport:
    p = Path(corpus_path)
    if not p.exists():
        raise FileNotFoundError(f"Corpus file not found: {p}")

    with open(p, "r", encoding="utf-8") as f:
        all_samples = json.load(f)

    if split_filter:
        samples = [s for s in all_samples if s.get("split") == split_filter]
    else:
        samples = all_samples

    scanner = InjectionScanner(threshold_score=threshold_score)

    tp = fp = tn = fn = 0
    details = []

    for item in samples:
        sample_id = item.get("id")
        text = item.get("text", "")
        ground_truth = item.get("label", "").lower() == "malicious"
        category = item.get("category", "")
        evasion_type = item.get("evasion_type", "none")

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
            "evasion_type": evasion_type,
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
        split_name=split_filter or "all",
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


def format_split_report_markdown(dev_report: MetricsReport, test_report: MetricsReport) -> str:
    lines = [
        "# AgentBlackbox Injection Scanner // Dual Split Precision & Recall Report",
        "",
        "## 1. Development Set (70% - Tuned / Exploration Set)",
        f"- **Samples:** {dev_report.total_samples} (Malicious: {dev_report.malicious_count}, Benign: {dev_report.benign_count})",
        f"- **Precision:** `{dev_report.precision * 100:.2f}%` (TP: {dev_report.true_positives}, FP: {dev_report.false_positives})",
        f"- **Recall:**    `{dev_report.recall * 100:.2f}%` (TP: {dev_report.true_positives}, FN: {dev_report.false_negatives})",
        f"- **F1 Score:**  `{dev_report.f1_score * 100:.2f}%`",
        f"- **Accuracy:**  `{dev_report.accuracy * 100:.2f}%`",
        "",
        "## 2. Held-Out Test Set (30% - Unseen Evaluation Set)",
        f"- **Samples:** {test_report.total_samples} (Malicious: {test_report.malicious_count}, Benign: {test_report.benign_count})",
        f"- **Precision:** `{test_report.precision * 100:.2f}%` (TP: {test_report.true_positives}, FP: {test_report.false_positives})",
        f"- **Recall:**    `{test_report.recall * 100:.2f}%` (TP: {test_report.true_positives}, FN: {test_report.false_negatives})",
        f"- **F1 Score:**  `{test_report.f1_score * 100:.2f}%`",
        f"- **Accuracy:**  `{test_report.accuracy * 100:.2f}%`",
        "",
        "## 3. Evasion Variants Performance Breakdown",
        "| Evasion Type | Split | Ground Truth | Verdict | Matched Heuristic |",
        "|---|---|---|---|---|",
    ]

    all_details = dev_report.details + test_report.details
    evasion_samples = [d for d in all_details if d.get("evasion_type") != "none"]
    for d in evasion_samples[:20]:
        lines.append(
            f"| `{d.get('evasion_type')}` | `{d.get('id')}` | {d['ground_truth']} | **{d['verdict']}** | {d['matched'][0] if d['matched'] else 'None'} |"
        )

    return "\n".join(lines)


def main():
    corpus_file = Path(__file__).parent / "corpus" / "injection_corpus.json"
    dev_rep = evaluate_corpus(corpus_file, threshold_score=35, split_filter="dev")
    test_rep = evaluate_corpus(corpus_file, threshold_score=35, split_filter="test")
    print(format_split_report_markdown(dev_rep, test_rep))


if __name__ == "__main__":
    main()
