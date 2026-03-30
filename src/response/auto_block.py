"""
response/auto_block.py
──────────────────────
Automated response: block suspicious IPs via iptables with
auto-expiry. Only activates when AUTO_BLOCK_ENABLED = True
and the alert's risk score exceeds BLOCK_THRESHOLD.

Requires: sudo privileges for iptables commands.
On a Pi, add this to /etc/sudoers (visudo):
    shield_user ALL=(root) NOPASSWD: /sbin/iptables
"""

import subprocess
import threading
import logging
import time
from collections import defaultdict

from config.settings import AUTO_BLOCK_ENABLED, BLOCK_DURATION_SECS
from scoring.risk_scorer import Alert

logger = logging.getLogger(__name__)

# ── block registry ────────────────────────────────────────────────────────────
# ip → expiry timestamp
_blocked: dict[str, float] = {}
_lock = threading.Lock()


def handle_alert(alert: Alert):
    """Entry point called by the main pipeline for every fired alert."""
    if not AUTO_BLOCK_ENABLED:
        return
    if not alert.should_block:
        return
    if _is_already_blocked(alert.src_ip):
        return
    _block_ip(alert.src_ip, alert.risk_score)


def _is_already_blocked(ip: str) -> bool:
    with _lock:
        expiry = _blocked.get(ip)
        if expiry is None:
            return False
        if time.time() < expiry:
            return True
        # expired — clean up
        del _blocked[ip]
        return False


def _block_ip(ip: str, score: int):
    """Add an iptables DROP rule and schedule auto-expiry."""
    try:
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

        if result.returncode == 0:
            with _lock:
                _blocked[ip] = time.time() + BLOCK_DURATION_SECS
            logger.warning(
                "BLOCKED %s (score=%d) for %ds via iptables",
                ip, score, BLOCK_DURATION_SECS,
            )
            # schedule automatic unblock
            t = threading.Timer(BLOCK_DURATION_SECS, _unblock_ip, args=(ip,))
            t.daemon = True
            t.start()
        else:
            logger.error("iptables block failed for %s: %s", ip, result.stderr)

    except subprocess.TimeoutExpired:
        logger.error("iptables command timed out for %s", ip)
    except FileNotFoundError:
        logger.error("iptables not found — is it installed?")


def _unblock_ip(ip: str):
    """Remove the DROP rule after expiry."""
    try:
        cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

        with _lock:
            _blocked.pop(ip, None)

        if result.returncode == 0:
            logger.info("Auto-unblocked %s", ip)
        else:
            logger.warning("Could not unblock %s: %s", ip, result.stderr)

    except Exception as exc:
        logger.error("Unblock error for %s: %s", ip, exc)


def blocked_ips() -> list[dict]:
    """Return current block list with time-remaining."""
    now = time.time()
    with _lock:
        return [
            {"ip": ip, "expires_in": int(exp - now)}
            for ip, exp in _blocked.items()
            if exp > now
        ]


def manual_unblock(ip: str) -> bool:
    """Unblock an IP manually (e.g. via dashboard action)."""
    if not _is_already_blocked(ip):
        return False
    _unblock_ip(ip)
    return True
