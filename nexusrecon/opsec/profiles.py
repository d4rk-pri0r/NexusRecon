"""
OPSEC stealth profiles.

Each profile controls outbound behavior: concurrency, delays,
proxy use, UA rotation, and per-source rate limits.

Profiles:
  paranoid — maximum stealth, Tor required, single thread, 3-10s delays
  high     — professional OSINT pace, proxy recommended, 1-3s delays
  normal   — standard pentest pace, optional proxy, 0.5-1s delays
  loud     — maximum speed, no delays, no proxy
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class ProfileName(StrEnum):
    PARANOID = "paranoid"
    HIGH = "high"
    NORMAL = "normal"
    LOUD = "loud"


@dataclass
class StealthProfile:
    name: ProfileName

    # Concurrency
    max_concurrent_tools: int = 5
    max_concurrent_requests: int = 10

    # Delays (seconds) between requests to the same host
    request_delay_min: float = 0.5
    request_delay_max: float = 1.5

    # Proxy settings
    use_proxy: bool = False
    prefer_tor: bool = False
    proxy_rotate: bool = False     # rotate per request if multiple available

    # UA rotation
    rotate_user_agent: bool = True
    ua_rotate_interval: int = 10   # rotate after N requests

    # DNS
    custom_dns_resolvers: list[str] = field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    avoid_system_resolver: bool = True

    # Per-source rate limits (requests per second)
    # Lower = more stealthy
    source_rates: dict[str, float] = field(default_factory=dict)

    # Burst detection self-throttle
    burst_detection_enabled: bool = True
    burst_threshold: int = 10      # requests in burst window
    burst_window_sec: float = 1.0  # burst window

    # Logging
    log_all_requests: bool = True


def _paranoid_rates() -> dict[str, float]:
    return {
        "shodan": 0.1,
        "censys": 0.05,
        "github": 0.1,
        "hunter": 0.05,
        "hibp": 0.1,
        "crtsh": 0.2,
        "virustotal": 0.05,
        "securitytrails": 0.05,
        "urlscan": 0.1,
        "default": 0.1,
    }


def _high_rates() -> dict[str, float]:
    return {
        "shodan": 0.5,
        "censys": 0.3,
        "github": 0.5,
        "hunter": 0.3,
        "hibp": 0.5,
        "crtsh": 1.0,
        "virustotal": 0.3,
        "securitytrails": 0.3,
        "urlscan": 0.5,
        "default": 0.5,
    }


def _normal_rates() -> dict[str, float]:
    return {
        "shodan": 1.0,
        "censys": 0.5,
        "github": 2.0,
        "hunter": 1.0,
        "hibp": 1.0,
        "crtsh": 3.0,
        "virustotal": 0.5,
        "securitytrails": 0.5,
        "urlscan": 1.0,
        "default": 2.0,
    }


def _loud_rates() -> dict[str, float]:
    return {
        "shodan": 5.0,
        "censys": 3.0,
        "github": 10.0,
        "hunter": 5.0,
        "hibp": 5.0,
        "crtsh": 10.0,
        "virustotal": 4.0,
        "securitytrails": 5.0,
        "urlscan": 5.0,
        "default": 10.0,
    }


PROFILES: dict[ProfileName, StealthProfile] = {
    ProfileName.PARANOID: StealthProfile(
        name=ProfileName.PARANOID,
        max_concurrent_tools=1,
        max_concurrent_requests=1,
        request_delay_min=3.0,
        request_delay_max=10.0,
        use_proxy=True,
        prefer_tor=True,
        proxy_rotate=True,
        rotate_user_agent=True,
        ua_rotate_interval=1,
        avoid_system_resolver=True,
        custom_dns_resolvers=["1.1.1.1", "9.9.9.9"],
        burst_detection_enabled=True,
        burst_threshold=3,
        burst_window_sec=5.0,
        source_rates=_paranoid_rates(),
    ),
    ProfileName.HIGH: StealthProfile(
        name=ProfileName.HIGH,
        max_concurrent_tools=3,
        max_concurrent_requests=5,
        request_delay_min=1.0,
        request_delay_max=3.0,
        use_proxy=True,
        prefer_tor=False,
        proxy_rotate=False,
        rotate_user_agent=True,
        ua_rotate_interval=5,
        avoid_system_resolver=True,
        custom_dns_resolvers=["1.1.1.1", "8.8.8.8"],
        burst_detection_enabled=True,
        burst_threshold=5,
        burst_window_sec=2.0,
        source_rates=_high_rates(),
    ),
    ProfileName.NORMAL: StealthProfile(
        name=ProfileName.NORMAL,
        max_concurrent_tools=10,
        max_concurrent_requests=20,
        request_delay_min=0.2,
        request_delay_max=0.8,
        use_proxy=False,
        prefer_tor=False,
        proxy_rotate=False,
        rotate_user_agent=True,
        ua_rotate_interval=10,
        avoid_system_resolver=False,
        custom_dns_resolvers=["1.1.1.1", "8.8.8.8"],
        burst_detection_enabled=True,
        burst_threshold=10,
        burst_window_sec=1.0,
        source_rates=_normal_rates(),
    ),
    ProfileName.LOUD: StealthProfile(
        name=ProfileName.LOUD,
        max_concurrent_tools=20,
        max_concurrent_requests=50,
        request_delay_min=0.0,
        request_delay_max=0.0,
        use_proxy=False,
        prefer_tor=False,
        proxy_rotate=False,
        rotate_user_agent=False,
        ua_rotate_interval=999,
        avoid_system_resolver=False,
        custom_dns_resolvers=[],
        burst_detection_enabled=False,
        burst_threshold=100,
        burst_window_sec=0.1,
        source_rates=_loud_rates(),
    ),
}


def get_profile(name: str) -> StealthProfile:
    """Return a StealthProfile by name string."""
    try:
        profile_name = ProfileName(name.lower())
        return PROFILES[profile_name]
    except (ValueError, KeyError):
        raise ValueError(
            f"Unknown stealth profile: {name!r}. "
            f"Valid options: {[p.value for p in ProfileName]}"
        )
