from __future__ import annotations

import pytest
from pathlib import Path
from agent_blackbox.security.eval_injection import evaluate_corpus


def test_labeled_injection_corpus_dual_split_evaluation():
    corpus_file = (
        Path(__file__).parent.parent
        / "agent_blackbox"
        / "security"
        / "corpus"
        / "injection_corpus.json"
    )
    assert corpus_file.exists(), f"Corpus file missing at: {corpus_file}"

    # 1. Dev Split Evaluation (70% of corpus)
    dev_rep = evaluate_corpus(corpus_file, threshold_score=35, split_filter="dev")
    assert dev_rep.total_samples >= 100
    assert dev_rep.false_positives == 0, f"Dev false positives: {dev_rep.false_positives}"
    assert dev_rep.precision >= 0.95
    assert dev_rep.recall >= 0.90
    assert dev_rep.f1_score >= 0.90

    # 2. Held-Out Test Split Evaluation (30% of corpus - detector never tuned on it)
    test_rep = evaluate_corpus(corpus_file, threshold_score=35, split_filter="test")
    assert test_rep.total_samples >= 50
    assert test_rep.false_positives == 0, f"Held-out false positives: {test_rep.false_positives}"
    assert test_rep.precision >= 0.95
    assert test_rep.recall >= 0.90
    assert test_rep.f1_score >= 0.90

    # Total corpus size must be 200+
    total_samples = dev_rep.total_samples + test_rep.total_samples
    assert total_samples >= 200
