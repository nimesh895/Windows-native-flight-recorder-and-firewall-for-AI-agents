from __future__ import annotations

import pytest
from pathlib import Path
from agent_blackbox.security.eval_injection import evaluate_corpus


def test_labeled_injection_corpus_precision_recall():
    corpus_file = (
        Path(__file__).parent.parent
        / "agent_blackbox"
        / "security"
        / "corpus"
        / "injection_corpus.json"
    )
    assert corpus_file.exists(), f"Corpus file missing at: {corpus_file}"

    report = evaluate_corpus(corpus_file, threshold_score=35)

    # Validate corpus size
    assert report.total_samples >= 20
    assert report.malicious_count >= 10
    assert report.benign_count >= 10

    # Ensure zero false positives on benign samples
    assert report.false_positives == 0, f"False positives detected: {report.false_positives}"

    # Precision must be 1.0 (100%)
    assert report.precision >= 0.95

    # Recall must be >= 0.90 (detect at least 90% of malicious variations)
    assert report.recall >= 0.90

    # F1 score must be high
    assert report.f1_score >= 0.90
