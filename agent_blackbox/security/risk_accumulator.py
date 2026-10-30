from __future__ import annotations

import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CumulativeRiskEvent(BaseModel):
    timestamp: float
    tool_name: str
    delta_risk: int
    reason: str


class SessionRiskAccumulator:
    """
    Cumulative session risk tracker with exponential time-decay:
        R_cumulative(t) = R_previous * exp( - lambda * delta_t ) + delta_risk

    Detects slow-and-low reconnaissance, repetitive borderline actions,
    and threshold breaches that warrant quarantine or Human-In-The-Loop review.
    """

    def __init__(
        self,
        half_life_seconds: float = 300.0,  # 5-minute half-life
        quarantine_threshold: int = 150,
        review_threshold: int = 80,
    ):
        self.half_life_seconds = half_life_seconds
        # lambda = ln(2) / half_life
        self.decay_rate = 0.693147 / half_life_seconds
        self.quarantine_threshold = quarantine_threshold
        self.review_threshold = review_threshold

        self.current_score: float = 0.0
        self.last_updated_time: float = time.time()
        self.history: List[CumulativeRiskEvent] = []

    def get_decayed_score(self, current_time: Optional[float] = None) -> float:
        now = current_time if current_time is not None else time.time()
        dt = max(0.0, now - self.last_updated_time)
        import math
        return self.current_score * math.exp(-self.decay_rate * dt)

    def record_risk(
        self,
        tool_name: str,
        delta_risk: int,
        reason: str = "",
        event_time: Optional[float] = None,
    ) -> Dict[str, Any]:
        now = event_time if event_time is not None else time.time()
        decayed = self.get_decayed_score(now)
        new_total = decayed + delta_risk

        self.current_score = new_total
        self.last_updated_time = now

        event = CumulativeRiskEvent(
            timestamp=now,
            tool_name=tool_name,
            delta_risk=delta_risk,
            reason=reason,
        )
        self.history.append(event)

        needs_quarantine = new_total >= self.quarantine_threshold
        needs_review = new_total >= self.review_threshold

        return {
            "cumulative_score": round(new_total, 1),
            "decayed_prior_score": round(decayed, 1),
            "delta_risk": delta_risk,
            "needs_quarantine": needs_quarantine,
            "needs_review": needs_review,
        }

    def reset(self):
        self.current_score = 0.0
        self.last_updated_time = time.time()
        self.history.clear()
