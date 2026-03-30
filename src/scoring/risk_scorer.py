"""
scoring/risk_scorer.py
──────────────────────
Fuses the four detector scores into a single 0–100 risk score,
runs SHAP for explainability, and produces a structured Alert.
Updated for NF-UQ-NIDS NetFlow architecture.
"""

import time
import logging
import numpy as np
from dataclasses import dataclass, field
from typing import Optional

from config.settings import (
    ENSEMBLE_WEIGHTS, ALERT_THRESHOLD,
    BLOCK_THRESHOLD, JA3_BLOCKLIST,
)
from models.detectors import (
    IsolationForestDetector,
    RandomForestDetector,
    LSTMDetector,
    StatisticalDetector,
)

logger = logging.getLogger(__name__)

# ── Binary Labels (Mapped to NF-UQ-NIDS 'Label' column) ───────────────────────
ATTACK_LABELS = {
    0: "Benign",
    1: "Malicious Flow Detected"
}

# ── severity bands ────────────────────────────────────────────────────────────
def _severity(score: int) -> str:
    if score >= 85: return "critical"
    if score >= 70: return "high"
    if score >= ALERT_THRESHOLD: return "medium"
    return "low"

# ── Alert dataclass ───────────────────────────────────────────────────────────

@dataclass
class Alert:
    uid:         str
    timestamp:   float
    src_ip:      str
    dst_ip:      str
    src_port:    int
    dst_port:    int
    proto:       str

    risk_score:  int                       # 0-100
    severity:    str                       # low/medium/high/critical
    attack_type: str                       # from ATTACK_LABELS
    should_block: bool

    # per-detector contributions
    scores: dict[str, float] = field(default_factory=dict)

    # explainability
    shap_values:     list[tuple[str, float]] = field(default_factory=list)  # top-5
    plain_language:  str = ""

    # TLS Threat Intel (For the Hackathon Brownie Points)
    ja3_hash:    Optional[str] = None
    ja3_blocked: bool = False

    def to_dict(self) -> dict:
        return {
            "uid":          self.uid,
            "timestamp":    self.timestamp,
            "src":          f"{self.src_ip}:{self.src_port}",
            "dst":          f"{self.dst_ip}:{self.dst_port}",
            "proto":        self.proto,
            "risk_score":   self.risk_score,
            "severity":     self.severity,
            "attack_type":  self.attack_type,
            "should_block": self.should_block,
            "detector_scores": self.scores,
            "top_features": self.shap_values,
            "explanation":  self.plain_language,
            "ja3":          self.ja3_hash,
            "ja3_blocked":  self.ja3_blocked,
        }

# ── plain-language templates ──────────────────────────────────────────────────

def _plain_language(alert: Alert) -> str:
    if alert.ja3_blocked:
        return f"CRITICAL: Device {alert.src_ip} used an encrypted connection (JA3) identical to known malware. Blocked immediately."
    
    if alert.risk_score > 85:
        return f"High-confidence anomaly detected from {alert.src_ip} to {alert.dst_ip}. Traffic volume and timing strongly indicate an automated attack."
        
    return f"Suspicious network behavior detected from {alert.src_ip} to {alert.dst_ip} (Risk Score: {alert.risk_score})."

# ── main scorer ───────────────────────────────────────────────────────────────

class RiskScorer:
    """
    Orchestrates the detectors and produces Alert objects.
    """

    def __init__(self):
        self._iso  = IsolationForestDetector()
        self._rf   = RandomForestDetector()
        self._lstm = LSTMDetector()
        self._stat = StatisticalDetector()
        
        # Default fallback weights if config is missing
        self._weights = getattr(ENSEMBLE_WEIGHTS, "weights", {
            "isolation_forest": 0.2,
            "random_forest": 0.6,
            "lstm": 0.0,
            "statistical": 0.2
        })
        self._shap_explainer = None 

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def load_models(self):
        for det in (self._iso, self._rf, self._lstm, self._stat):
            try:
                det.load()
            except Exception as exc:
                logger.warning("Could not load %s: %s", det.name, exc)

    def save_models(self):
        for det in (self._iso, self._rf, self._lstm, self._stat):
            try:
                det.save()
            except Exception as exc:
                logger.warning("Could not save %s: %s", det.name, exc)

    def fit_all(self, X: np.ndarray, y: np.ndarray):
        """
        Train all models. Automatically separates normal traffic for 
        unsupervised models (Isolation Forest/Statistical).
        """
        logger.info("Splitting dataset for Unsupervised vs Supervised training...")
        
        # Isolate Benign traffic (Label == 0) for the anomaly detectors
        normal_mask = (y == 0)
        X_normal = X[normal_mask]

        logger.info(f"Training Anomaly Detectors on {len(X_normal)} benign samples...")
        self._iso.fit(X_normal)
        self._stat.fit(X_normal)
        
        logger.info(f"Training Random Forest on full {len(X)} samples...")
        self._rf.fit(X, y)
        
        logger.info("All models trained successfully.")

    # ── evaluation ────────────────────────────────────────────────────────────

    def evaluate(self, flow: dict, feature_vec: np.ndarray) -> Optional[Alert]:
        
        # 1. Individual detector scores (0.0–1.0)
        scores = {
            "isolation_forest": self._iso.score(feature_vec),
            "random_forest":    self._rf.score(feature_vec),
            "lstm":             self._lstm.score(feature_vec),
            "statistical":      self._stat.score(feature_vec),
        }

        # 2. Weighted fusion
        fused = sum(
            self._weights.get(name, 0) * val
            for name, val in scores.items()
        )
        risk_score = int(np.clip(fused * 100, 0, 100))

        # 3. The Threat Intel Bypass (JA3 Hash Check)
        ja3 = flow.get("JA3_HASH", "")
        ja3_blocked = False
        if ja3 and ja3 in JA3_BLOCKLIST:
            ja3_blocked = True
            risk_score = max(risk_score, 100) # Instant max risk

        if risk_score < ALERT_THRESHOLD:
            return None

        # 4. Attack Classification
        atk_class = self._rf.predict_class(feature_vec)
        attack_type = ATTACK_LABELS.get(atk_class, "Unknown Anomaly")

        # 5. SHAP Explainability (Disabled for Hackathon Speed unless specifically configured)
        shap_values = self._rf.top_features(n=3)

        # 6. Build the Alert (Mapped to NetFlow Keys)
        alert = Alert(
            uid         = str(flow.get("uid", time.time())),
            timestamp   = float(flow.get("ts", time.time())),
            src_ip      = str(flow.get("IPV4_SRC_ADDR", "Unknown")),
            dst_ip      = str(flow.get("IPV4_DST_ADDR", "Unknown")),
            src_port    = int(flow.get("L4_SRC_PORT", 0)),
            dst_port    = int(flow.get("L4_DST_PORT", 0)),
            proto       = str(flow.get("PROTOCOL", "")),
            risk_score  = risk_score,
            severity    = _severity(risk_score),
            attack_type = attack_type,
            should_block= risk_score >= BLOCK_THRESHOLD,
            scores      = {k: round(v, 3) for k, v in scores.items()},
            shap_values = shap_values,
            ja3_hash    = str(ja3) if ja3 else None,
            ja3_blocked = ja3_blocked,
        )
        alert.plain_language = _plain_language(alert)
        return alert