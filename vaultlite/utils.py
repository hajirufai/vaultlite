"""Utility functions for VaultLite."""

import secrets
import time


def constant_time_compare(a: str, b: str) -> bool:
    """Compare two strings in constant time to prevent timing attacks."""
    return secrets.compare_digest(a.encode(), b.encode())


def generate_id(prefix: str = "") -> str:
    """Generate a secure random identifier."""
    token = secrets.token_urlsafe(16)
    return f"{prefix}{token}" if prefix else token


def current_timestamp() -> float:
    """Current time as Unix timestamp."""
    return time.time()


def format_timestamp(ts: float) -> str:
    """Format a Unix timestamp as ISO 8601."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


def parse_duration(s: str) -> float:
    """Parse a human-readable duration string into seconds.

    Supports: "30s", "5m", "2h", "1d"
    """
    if not s:
        raise ValueError("Empty duration string")

    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}

    unit = s[-1].lower()
    if unit in multipliers:
        try:
            return float(s[:-1]) * multipliers[unit]
        except ValueError:
            raise ValueError(f"Invalid duration: {s}")

    # Try parsing as raw seconds
    try:
        return float(s)
    except ValueError:
        raise ValueError(f"Invalid duration: {s}")


def sanitize_path(path: str) -> str:
    """Sanitize a secret path — remove leading/trailing slashes,
    prevent directory traversal.
    """
    # Remove dangerous sequences
    path = path.replace("..", "").replace("//", "/")
    return path.strip("/")
