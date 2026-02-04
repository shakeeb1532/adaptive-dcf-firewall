# traffic_baseline.py
"""
Simple EWMA-based traffic baseline learning and anomaly scoring.
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Dict, Tuple


@dataclass
class FlowState:
    ema_rate: float
    ema_var: float
    last_ts: float


class TrafficBaseline:
    def __init__(self, alpha: float = 0.2, min_var: float = 1e-3) -> None:
        self.alpha = alpha
        self.min_var = min_var
        self._state: Dict[Tuple[str, str, int], FlowState] = {}

    def update(self, src: str, dst: str, dport: int, byte_count: int) -> float:
        key = (src, dst, dport)
        now = time.time()
        st = self._state.get(key)
        if not st:
            st = FlowState(ema_rate=0.0, ema_var=self.min_var, last_ts=now)
            self._state[key] = st
            return 0.0

        dt = max(1e-3, now - st.last_ts)
        rate = byte_count / dt
        # EWMA mean
        st.ema_rate = (1 - self.alpha) * st.ema_rate + self.alpha * rate
        # EWMA variance
        diff = rate - st.ema_rate
        st.ema_var = max(self.min_var, (1 - self.alpha) * st.ema_var + self.alpha * (diff * diff))
        st.last_ts = now

        z = abs(diff) / math.sqrt(st.ema_var)
        return z
