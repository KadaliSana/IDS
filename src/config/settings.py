"""
SHIELD — configuration and constants.
Edit these to match your deployment environment.
"""

from pathlib import Path

# ── Zeek log paths ────────────────────────────────────────────────────────────
ZEEK_LOG_DIR   = Path("/home/sana/IDS/src/models/data")   # live rotating logs
CONN_LOG       = ZEEK_LOG_DIR / "conn.log"
SSL_LOG        = ZEEK_LOG_DIR / "ssl.log"
DNS_LOG        = ZEEK_LOG_DIR / "dns.log"
WEIRD_LOG      = ZEEK_LOG_DIR / "weird.log"      # Zeek's own anomaly flag

# ── Network interface (used when launching Zeek from Python) ──────────────────
CAPTURE_IFACE  = "eth0"                          # change to wlan0 for Wi-Fi

# ── Feature extraction ────────────────────────────────────────────────────────
FLOW_WINDOW_SEC   = 30        # aggregate flows over this window
UID_CACHE_TTL_SEC = 120       # how long to keep unmatched uid entries
MIN_PKTS_THRESHOLD = 3        # ignore single-packet blips

# ── Risk scoring ──────────────────────────────────────────────────────────────
ALERT_THRESHOLD   = 60        # 0-100; fire alert above this
BLOCK_THRESHOLD   = 85        # auto-block above this (if enabled)

# Ensemble weights (must sum to 1.0)
ENSEMBLE_WEIGHTS = {
    "isolation_forest": 0.25,
    "random_forest":    0.35,
    "transformer":      0.25,
    "statistical":      0.15,
}

# ── Model artefacts ───────────────────────────────────────────────────────────
MODEL_DIR            = Path("models/artefacts")
RF_MODEL_PATH        = MODEL_DIR / "rf_classifier.joblib"
ISOFOREST_MODEL_PATH = MODEL_DIR / "isolation_forest.joblib"
SCALER_PATH          = MODEL_DIR / "scaler.joblib"
TRANSFORMER_MODEL_PATH = MODEL_DIR / "transformer_autoencoder.pt"

# ── JA3 threat-intel blocklist (hashes of known-malicious TLS fingerprints) ──
# Source: https://ja3er.com/  |  https://github.com/salesforce/ja3
JA3_BLOCKLIST: set[str] = {
    "e7d705a3286e19ea42f587b344ee6865",  # Emotet
    "6734f37431670b3ab4292b8f60f29984",  # TrickBot
    "51c64c77e60f3980eea90869b68c58a8",  # CobaltStrike default
    "b386946a5a44d1ddcc843bc75336dfce",  # Dridex
}

# ── Automated response ────────────────────────────────────────────────────────
AUTO_BLOCK_ENABLED  = True    # set True to enable iptables auto-block
BLOCK_DURATION_SECS = 1800    # 30 min auto-expiry

# ── API server ────────────────────────────────────────────────────────────────
API_HOST = "0.0.0.0"
API_PORT = 8000
