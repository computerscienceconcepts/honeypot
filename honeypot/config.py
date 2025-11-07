from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv


@dataclass
class Config:
    ssh_port: int = 22
    http_port: int = 80
    https_port: int = 443
    dashboard_port: int = 8080
    log_path: str = "logs/events.jsonl"
    max_concurrent_clients: int = 100
    rate_limit_per_min: int = 10
    respond_with_redirect_prob: float = 0.3


def _get_env_int(name: str, default: int) -> int:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _get_env_float(name: str, default: float) -> float:
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def load_config(env_path: Optional[str] = None) -> Config:
    """Load configuration from .env and environment variables with sane defaults."""
    if env_path:
        load_dotenv(dotenv_path=env_path)
    else:
        load_dotenv()

    cfg = Config(
        ssh_port=_get_env_int("SSH_PORT", 22),
        http_port=_get_env_int("HTTP_PORT", 80),
        https_port=_get_env_int("HTTPS_PORT", 443),
        dashboard_port=_get_env_int("DASHBOARD_PORT", 8080),
        log_path=os.getenv("LOG_PATH", "logs/events.jsonl"),
        max_concurrent_clients=_get_env_int("MAX_CONCURRENT_CLIENTS", 100),
        rate_limit_per_min=_get_env_int("RATE_LIMIT_PER_MIN", 10),
        respond_with_redirect_prob=_get_env_float("RESPOND_WITH_REDIRECT_PROB", 0.3),
    )

    # Ensure log directory exists
    log_path = Path(cfg.log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    return cfg


