"""
features/extractor.py
─────────────────────
Turns a merged Zeek flow dict (conn + ssl + dns + weird) into a
fixed-length numeric feature vector for the ML ensemble.

No packet payloads are touched. Everything comes from Zeek metadata.

Feature groups
──────────────
  [0-4]   Volume          bytes, packets, rates
  [5-9]   Timing          duration, inter-arrival proxies
  [10-14] Ratio           upload/download asymmetry, flags
  [15-19] Port / service  port numbers, service class
  [20-24] TCP state       conn_state one-hot, history flags
  [25-29] TLS             version, cipher class, resumption, JA3 risk
  [30-34] Behavioral      beacon score, scan score, exfil score
  [35-39] Temporal        hour-of-day, day-of-week, is_weekend, etc.

Total: 40 features (all float32)
"""

import math
import time
import hashlib
import logging
from datetime import datetime
from typing import Optional

import numpy as np

from config.settings import JA3_BLOCKLIST

logger = logging.getLogger(__name__)

# ── feature names (index-aligned with the vector) ────────────────────────────
FEATURE_NAMES = [
    # volume
    "orig_bytes",           # 0
    "resp_bytes",           # 1
    "orig_pkts",            # 2
    "resp_pkts",            # 3
    "total_bytes",          # 4
    # timing
    "duration",             # 5
    "bytes_per_sec",        # 6
    "pkts_per_sec",         # 7
    "avg_pkt_size",         # 8
    "duration_log",         # 9  log1p(duration) — reduces skew
    # ratios
    "upload_ratio",         # 10  orig_bytes / total_bytes
    "pkt_size_asymmetry",   # 11  |orig_pkt_size - resp_pkt_size|
    "byte_pkt_ratio",       # 12  total_bytes / total_pkts
    "resp_orig_ratio",      # 13  resp_bytes / (orig_bytes+1)
    "missed_bytes_ratio",   # 14
    # port / service
    "orig_port_norm",       # 15  src port / 65535
    "resp_port_norm",       # 16  dst port / 65535
    "is_well_known_port",   # 17  dst port < 1024
    "is_ephemeral_src",     # 18  src port > 49151
    "service_class",        # 19  encoded: 0=other,1=http,2=dns,3=ssh,4=tls
    # TCP conn_state
    "conn_established",     # 20
    "conn_reset",           # 21
    "conn_no_reply",        # 22
    "history_has_syn",      # 23
    "history_has_rst",      # 24
    # TLS / SSL
    "is_tls",               # 25
    "tls_version_num",      # 26  encoded: SSLv3=0,TLS10=1,TLS11=2,TLS12=3,TLS13=4
    "tls_cipher_strength",  # 27  0=weak,1=medium,2=strong (from cipher name)
    "tls_resumed",          # 28
    "ja3_risk",             # 29  1.0 if JA3 in blocklist, 0.0 otherwise
    # behavioral scores (lightweight heuristics computed here)
    "scan_score",           # 30  high dst port diversity
    "beacon_score",         # 31  low-bytes + regular timing proxy
    "exfil_score",          # 32  large upload asymmetry
    "weird_score",          # 33  zeek weird.log hit
    "dns_tunnel_score",     # 34  long DNS query names
    # temporal
    "hour_sin",             # 35  sin(2π * hour/24) — cyclic encoding
    "hour_cos",             # 36
    "day_sin",              # 37  sin(2π * dow/7)
    "day_cos",              # 38
    "is_off_hours",         # 39  1 if 22:00–06:00
]

assert len(FEATURE_NAMES) == 40, "Feature name list must have exactly 40 entries"

# ── service → integer mapping ─────────────────────────────────────────────────
_SERVICE_MAP = {
    "http": 1, "http-alt": 1,
    "dns": 2,
    "ssh": 3,
    "ssl": 4, "tls": 4,
}

# ── TLS version → integer ─────────────────────────────────────────────────────
_TLS_VERSION_MAP = {
    "SSLv3": 0, "TLSv10": 1, "TLSv11": 2, "TLSv12": 3, "TLSv13": 4,
}

# Cipher strings that imply weak encryption
_WEAK_CIPHER_PATTERNS = ("RC4", "DES", "EXPORT", "NULL", "ANON", "MD5")
_STRONG_CIPHER_PATTERNS = ("AES_256", "CHACHA20", "AESGCM")


def _cipher_strength(cipher: Optional[str]) -> float:
    if not cipher:
        return 0.0
    cipher_upper = cipher.upper()
    if any(p in cipher_upper for p in _WEAK_CIPHER_PATTERNS):
        return 0.0
    if any(p in cipher_upper for p in _STRONG_CIPHER_PATTERNS):
        return 2.0
    return 1.0


def _safe(val, default=0.0) -> float:
    """Return float or default for None / nan / inf."""
    try:
        v = float(val)
        return v if math.isfinite(v) else default
    except (TypeError, ValueError):
        return default


def _history_flag(history: Optional[str], char: str) -> float:
    """Check if a Zeek history character appears in the history string."""
    if not history:
        return 0.0
    return 1.0 if char in history else 0.0


# ── main extractor ────────────────────────────────────────────────────────────

class FeatureExtractor:
    """
    Stateless converter: Zeek flow dict → numpy float32 vector of length 40.

    Example
    -------
        extractor = FeatureExtractor()
        vec = extractor.extract(flow_dict)   # shape (40,)
    """

    def extract(self, flow: dict) -> np.ndarray:
        """
        Convert a single Zeek flow dict to a feature vector.
        Returns np.ndarray of shape (40,) and dtype float32.
        Missing fields default to 0.0 — never raises.
        """
        vec = np.zeros(40, dtype=np.float32)

        try:
            self._volume(flow, vec)
            self._timing(flow, vec)
            self._ratios(flow, vec)
            self._ports(flow, vec)
            self._tcp_state(flow, vec)
            self._tls(flow, vec)
            self._behavioral(flow, vec)
            self._temporal(flow, vec)
        except Exception as exc:
            logger.warning("Feature extraction error for uid=%s: %s",
                           flow.get("uid", "?"), exc)

        return vec

    # ── feature groups ────────────────────────────────────────────────────────

    def _volume(self, f: dict, v: np.ndarray):
        ob = _safe(f.get("orig_bytes"))
        rb = _safe(f.get("resp_bytes"))
        op = _safe(f.get("orig_pkts"))
        rp = _safe(f.get("resp_pkts"))
        v[0] = ob
        v[1] = rb
        v[2] = op
        v[3] = rp
        v[4] = ob + rb

    def _timing(self, f: dict, v: np.ndarray):
        dur   = max(_safe(f.get("duration"), 1e-6), 1e-6)
        total_bytes = v[4]
        total_pkts  = v[2] + v[3]
        v[5] = dur
        v[6] = total_bytes / dur
        v[7] = total_pkts  / dur
        v[8] = (total_bytes / total_pkts) if total_pkts > 0 else 0.0
        v[9] = math.log1p(dur)

    def _ratios(self, f: dict, v: np.ndarray):
        ob = v[0]; rb = v[1]
        op = v[2]; rp = v[3]
        total_bytes = v[4]
        total_pkts  = op + rp
        missed = _safe(f.get("missed_bytes"))

        orig_pkt_size = (ob / op) if op > 0 else 0.0
        resp_pkt_size = (rb / rp) if rp > 0 else 0.0

        v[10] = (ob / total_bytes) if total_bytes > 0 else 0.5
        v[11] = abs(orig_pkt_size - resp_pkt_size)
        v[12] = (total_bytes / total_pkts) if total_pkts > 0 else 0.0
        v[13] = rb / (ob + 1.0)
        v[14] = (missed / total_bytes) if total_bytes > 0 else 0.0

    def _ports(self, f: dict, v: np.ndarray):
        orig_p = int(_safe(f.get("id.orig_p")))
        resp_p = int(_safe(f.get("id.resp_p")))
        service = str(f.get("service") or "").lower()

        v[15] = orig_p / 65535.0
        v[16] = resp_p / 65535.0
        v[17] = 1.0 if resp_p < 1024 else 0.0
        v[18] = 1.0 if orig_p > 49151 else 0.0
        v[19] = float(_SERVICE_MAP.get(service, 0))

    def _tcp_state(self, f: dict, v: np.ndarray):
        state   = str(f.get("conn_state") or "").upper()
        history = str(f.get("history") or "")

        v[20] = 1.0 if state == "SF"  else 0.0   # full established
        v[21] = 1.0 if state in ("REJ","RSTR","RSTO","RSTOS0") else 0.0
        v[22] = 1.0 if state in ("S0","S1","SH","SHR") else 0.0
        v[23] = _history_flag(history, "S")
        v[24] = _history_flag(history, "R")

    def _tls(self, f: dict, v: np.ndarray):
        is_tls    = 1.0 if f.get("ssl_ja3") or f.get("ssl_version") else 0.0
        version   = str(f.get("ssl_version") or "")
        cipher    = str(f.get("ssl_cipher") or "")
        resumed   = bool(f.get("ssl_resumed"))
        ja3_hash  = str(f.get("ssl_ja3") or "")

        v[25] = is_tls
        v[26] = float(_TLS_VERSION_MAP.get(version, 3))   # default TLS1.2
        v[27] = _cipher_strength(cipher)
        v[28] = 1.0 if resumed else 0.0
        v[29] = 1.0 if ja3_hash in JA3_BLOCKLIST else 0.0

    def _behavioral(self, f: dict, v: np.ndarray):
        """Lightweight heuristic scores — no ML, pure arithmetic."""

        # scan score: penalise when dst port is high/random & few bytes
        resp_p    = int(_safe(f.get("id.resp_p")))
        ob        = v[0]; rb = v[1]
        dur       = max(v[5], 1e-6)
        state     = str(f.get("conn_state") or "").upper()

        # short, low-data flows to non-standard ports → scan-like
        scan = 0.0
        if ob < 200 and rb < 200 and resp_p > 1024 and state in ("S0","REJ"):
            scan = 0.8
        elif ob < 500 and rb == 0 and state == "S0":
            scan = 0.5
        v[30] = scan

        # beacon score: very regular small flows → C2 beacon-like
        # (full beacon detection needs multi-flow history; this is a per-flow proxy)
        beacon = 0.0
        if 10 < ob < 500 and 10 < rb < 500:
            # small symmetric flows are suspicious if duration is very short
            if dur < 2.0:
                beacon = 0.6
            elif dur < 10.0:
                beacon = 0.3
        v[31] = beacon

        # exfil score: large upstream vs tiny downstream
        exfil = 0.0
        if ob > 500_000 and ob > (rb * 10):   # 10:1 upload ratio
            exfil = min(1.0, ob / 5_000_000)
        v[32] = exfil

        # weird score: zeek itself flagged something
        weird_name = f.get("weird_name")
        v[33] = 1.0 if weird_name else 0.0

        # DNS tunnel proxy: long query name → covert channel candidate
        dns_query = str(f.get("dns_query") or "")
        v[34] = min(1.0, len(dns_query) / 200.0) if dns_query else 0.0

    def _temporal(self, f: dict, v: np.ndarray):
        ts = f.get("ts") or f.get("_ingested_at") or time.time()
        try:
            dt = datetime.fromtimestamp(float(ts))
        except (TypeError, ValueError, OSError):
            dt = datetime.now()

        hour = dt.hour
        dow  = dt.weekday()   # 0=Monday … 6=Sunday

        v[35] = math.sin(2 * math.pi * hour / 24)
        v[36] = math.cos(2 * math.pi * hour / 24)
        v[37] = math.sin(2 * math.pi * dow  / 7)
        v[38] = math.cos(2 * math.pi * dow  / 7)
        v[39] = 1.0 if (hour >= 22 or hour < 6) else 0.0


# ── batch extraction helper ───────────────────────────────────────────────────

def extract_dataframe(df):
    """
    Apply feature extraction to every row of a pandas DataFrame
    (e.g. produced by merge_conn_ssl in zeek_reader.py).

    Returns a new DataFrame with columns = FEATURE_NAMES.
    """
    import pandas as pd
    extractor = FeatureExtractor()
    rows = [extractor.extract(row.to_dict()) for _, row in df.iterrows()]
    return pd.DataFrame(rows, columns=FEATURE_NAMES)
