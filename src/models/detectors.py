"""
models/detectors.py
───────────────────
Four detector classes, each wrapping a different algorithm.
They all share the same interface:

    score(feature_vec: np.ndarray) -> float   # returns 0.0–1.0
    fit(X: np.ndarray, y=None)                # train / fine-tune
    save() / load()                           # persist to disk

The ensemble in scoring/risk_scorer.py calls all four and fuses
their outputs into a single 0-100 risk score.
"""

import logging
import joblib
import numpy as np
from pathlib import Path
from typing import Optional

from config.settings import (
    RF_MODEL_PATH, ISOFOREST_MODEL_PATH,
    SCALER_PATH, LSTM_MODEL_PATH,
)

logger = logging.getLogger(__name__)


# ── base class ────────────────────────────────────────────────────────────────

class BaseDetector:
    name: str = "base"

    def score(self, feature_vec: np.ndarray) -> float:
        raise NotImplementedError

    def fit(self, X: np.ndarray, y: Optional[np.ndarray] = None):
        raise NotImplementedError

    def save(self):
        raise NotImplementedError

    def load(self):
        raise NotImplementedError

    def is_ready(self) -> bool:
        raise NotImplementedError


# ── 1. Isolation Forest (unsupervised anomaly) ────────────────────────────────

class IsolationForestDetector(BaseDetector):
    """
    Trained purely on NORMAL traffic. Anomaly score is inverted so that
    0 = normal, 1 = highly anomalous.

    Train it on 24h of baseline traffic:
        detector.fit(normal_feature_matrix)
    """
    name = "isolation_forest"

    def __init__(
        self,
        n_estimators: int = 100,
        contamination: float = 0.01,   # expected fraction of anomalies
        random_state: int = 42,
    ):
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        self._model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
            n_jobs=-1,
        )
        self._scaler = StandardScaler()
        self._fitted = False

    def fit(self, X: np.ndarray, y=None):
        logger.info("[%s] fitting on %d samples", self.name, len(X))
        Xs = self._scaler.fit_transform(X)
        self._model.fit(Xs)
        self._fitted = True
        logger.info("[%s] fit complete", self.name)

    def score(self, feature_vec: np.ndarray) -> float:
        if not self._fitted:
            return 0.5   # uncertain if not trained yet
        Xs = self._scaler.transform(feature_vec.reshape(1, -1))
        # decision_function: negative = more anomalous
        raw = self._model.decision_function(Xs)[0]
        # map to [0, 1]: lower raw → higher anomaly score
        normalised = 1.0 - (raw - (-0.5)) / (0.5 - (-0.5))
        return float(np.clip(normalised, 0.0, 1.0))

    def save(self):
        ISOFOREST_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({"model": self._model, "scaler": self._scaler},
                    ISOFOREST_MODEL_PATH)
        logger.info("[%s] saved to %s", self.name, ISOFOREST_MODEL_PATH)

    def load(self):
        if not ISOFOREST_MODEL_PATH.exists():
            logger.warning("[%s] model file not found — will need fit()", self.name)
            return
        bundle = joblib.load(ISOFOREST_MODEL_PATH)
        self._model  = bundle["model"]
        self._scaler = bundle["scaler"]
        self._fitted = True
        logger.info("[%s] loaded from %s", self.name, ISOFOREST_MODEL_PATH)

    def is_ready(self) -> bool:
        return self._fitted


# ── 2. Random Forest classifier (supervised) ──────────────────────────────────

class RandomForestDetector(BaseDetector):
    """
    Multi-class classifier trained on CICIDS-2017 / CICIDS-2018.
    Maps feature vectors to attack class probabilities; returns the
    probability of the flow NOT being benign (i.e. P(attack)).

    Attack classes (from CICIDS-2017):
        0=BENIGN, 1=DoS, 2=PortScan, 3=Botnet, 4=Infiltration,
        5=BruteForce, 6=WebAttack, 7=Heartbleed
    """
    name = "random_forest"
    BENIGN_CLASS = 0

    def __init__(
        self,
        n_estimators: int = 200,
        max_depth: int = 20,
        random_state: int = 42,
    ):
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.preprocessing import StandardScaler

        self._model = RandomForestClassifier(
            n_estimators=n_estimators,
            max_depth=max_depth,
            random_state=random_state,
            class_weight="balanced",
            n_jobs=-1,
        )
        self._scaler = StandardScaler()
        self._classes: list[int] = []
        self._fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray):
        logger.info("[%s] fitting on %d samples (%d classes)",
                    self.name, len(X), len(np.unique(y)))
        Xs = self._scaler.fit_transform(X)
        self._model.fit(Xs, y)
        self._classes = list(self._model.classes_)
        self._fitted = True
        logger.info("[%s] fit complete", self.name)

    def score(self, feature_vec: np.ndarray) -> float:
        if not self._fitted:
            return 0.5
        Xs = self._scaler.transform(feature_vec.reshape(1, -1))
        proba = self._model.predict_proba(Xs)[0]     # shape: (n_classes,)
        if self.BENIGN_CLASS in self._classes:
            benign_idx = self._classes.index(self.BENIGN_CLASS)
            return float(1.0 - proba[benign_idx])
        return float(np.max(proba))

    def predict_class(self, feature_vec: np.ndarray) -> int:
        """Return the predicted attack class label."""
        if not self._fitted:
            return self.BENIGN_CLASS
        Xs = self._scaler.transform(feature_vec.reshape(1, -1))
        return int(self._model.predict(Xs)[0])

    def top_features(self, n: int = 5) -> list[tuple[str, float]]:
        """Return top-n feature importances (for SHAP fallback)."""
        from features.extractor import FEATURE_NAMES
        if not self._fitted:
            return []
        importances = self._model.feature_importances_
        indices = np.argsort(importances)[::-1][:n]
        return [(FEATURE_NAMES[i], float(importances[i])) for i in indices]

    def save(self):
        RF_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump({
            "model": self._model,
            "scaler": self._scaler,
            "classes": self._classes,
        }, RF_MODEL_PATH)
        logger.info("[%s] saved to %s", self.name, RF_MODEL_PATH)

    def load(self):
        if not RF_MODEL_PATH.exists():
            logger.warning("[%s] model file not found — will need fit()", self.name)
            return
        bundle = joblib.load(RF_MODEL_PATH)
        self._model   = bundle["model"]
        self._scaler  = bundle["scaler"]
        self._classes = bundle["classes"]
        self._fitted  = True
        logger.info("[%s] loaded from %s", self.name, RF_MODEL_PATH)

    def is_ready(self) -> bool:
        return self._fitted


# ── 3. LSTM Autoencoder (temporal anomaly) ────────────────────────────────────

class LSTMDetector(BaseDetector):
    """
    Sequence autoencoder: trained to reconstruct NORMAL traffic sequences.
    High reconstruction error → anomaly.

    Uses TensorFlow Lite for Pi-friendly inference.
    Full training is done offline (train_lstm.py) and the .tflite file
    is deployed to the Pi.

    Sequence length: 10 consecutive flows from the same /24 subnet.
    """
    name = "lstm"
    SEQ_LEN = 10
    N_FEATURES = 40

    def __init__(self):
        self._interpreter = None
        self._threshold = 0.05      # reconstruction error threshold
        self._ready = False
        self._buffer: dict[str, list] = {}   # subnet → recent feature vecs

    def load(self):
        """Load TFLite model."""
        if not LSTM_MODEL_PATH.exists():
            logger.warning("[%s] .tflite file not found at %s", self.name, LSTM_MODEL_PATH)
            return
        try:
            import tflite_runtime.interpreter as tflite
        except ImportError:
            try:
                import tensorflow.lite as tflite
            except ImportError:
                logger.warning("[%s] neither tflite_runtime nor tensorflow found — LSTM disabled", self.name)
                return

        self._interpreter = tflite.Interpreter(model_path=str(LSTM_MODEL_PATH))
        self._interpreter.allocate_tensors()
        self._ready = True
        logger.info("[%s] TFLite model loaded", self.name)

    def _get_input_details(self):
        return self._interpreter.get_input_details()

    def _get_output_details(self):
        return self._interpreter.get_output_details()

    def score(self, feature_vec: np.ndarray) -> float:
        if not self._ready:
            return 0.5

        # buffer flows by /24 subnet for sequence context
        # (simplified: just use recent flows regardless of subnet)
        if not hasattr(self, "_global_buf"):
            self._global_buf: list = []
        self._global_buf.append(feature_vec)
        if len(self._global_buf) > self.SEQ_LEN:
            self._global_buf.pop(0)

        if len(self._global_buf) < self.SEQ_LEN:
            return 0.5   # not enough history yet

        seq = np.array(self._global_buf, dtype=np.float32)   # (SEQ_LEN, 40)
        seq = seq.reshape(1, self.SEQ_LEN, self.N_FEATURES)

        inp = self._get_input_details()
        out = self._get_output_details()

        self._interpreter.set_tensor(inp[0]["index"], seq)
        self._interpreter.invoke()
        reconstruction = self._interpreter.get_tensor(out[0]["index"])

        mse = float(np.mean((seq - reconstruction) ** 2))
        # normalise: MSE > threshold maps to 1.0
        normalised = min(1.0, mse / self._threshold)
        return normalised

    def fit(self, X: np.ndarray, y=None):
        """
        Full LSTM training is done offline — see train_lstm.py.
        This stub exists for API compatibility.
        """
        logger.warning("[%s] call train_lstm.py for full training", self.name)

    def save(self):
        logger.info("[%s] save TFLite model via train_lstm.py export", self.name)

    def is_ready(self) -> bool:
        return self._ready


# ── 4. Statistical detector (Z-score + EWMA baseline) ────────────────────────

class StatisticalDetector(BaseDetector):
    """
    Maintains per-feature exponentially weighted moving averages (EWMA)
    and standard deviations. Flags flows whose features deviate more
    than `z_threshold` standard deviations from the rolling baseline.

    No training data required — self-adapts to the network over time.
    Alpha controls how quickly the baseline adapts (lower = slower).
    """
    name = "statistical"

    def __init__(self, alpha: float = 0.05, z_threshold: float = 3.5):
        self._alpha   = alpha
        self._z_thr   = z_threshold
        self._mean    = None    # shape (40,)
        self._var     = None    # shape (40,)
        self._n       = 0

    def _update_baseline(self, x: np.ndarray):
        if self._mean is None:
            self._mean = x.copy()
            self._var  = np.zeros_like(x)
        else:
            delta = x - self._mean
            self._mean += self._alpha * delta
            self._var   = (1 - self._alpha) * (self._var + self._alpha * delta ** 2)
        self._n += 1

    def score(self, feature_vec: np.ndarray) -> float:
        if self._n < 30:
            # warm-up: update baseline but return neutral score
            self._update_baseline(feature_vec)
            return 0.0

        std  = np.sqrt(self._var + 1e-8)
        z    = np.abs((feature_vec - self._mean) / std)
        # fraction of features exceeding z_threshold
        frac = float(np.mean(z > self._z_thr))
        # max z-score contribution (capped)
        max_z = float(np.clip(np.max(z) / (self._z_thr * 3), 0, 1))
        combined = 0.6 * frac + 0.4 * max_z

        self._update_baseline(feature_vec)   # update after scoring
        return float(np.clip(combined, 0.0, 1.0))

    def fit(self, X: np.ndarray, y=None):
        """Pre-warm the baseline with a batch of normal traffic."""
        logger.info("[%s] pre-warming baseline on %d samples", self.name, len(X))
        for x in X:
            self._update_baseline(x)

    def save(self):
        path = Path("models/artefacts/statistical_baseline.npz")
        path.parent.mkdir(parents=True, exist_ok=True)
        np.savez(path, mean=self._mean, var=self._var, n=self._n)

    def load(self):
        path = Path("models/artefacts/statistical_baseline.npz")
        if not path.exists():
            logger.info("[%s] no saved baseline found — will self-adapt", self.name)
            return
        data = np.load(path)
        self._mean = data["mean"]
        self._var  = data["var"]
        self._n    = int(data["n"])
        logger.info("[%s] baseline loaded (%d samples)", self.name, self._n)

    def is_ready(self) -> bool:
        return True   # always ready (self-adapting)
