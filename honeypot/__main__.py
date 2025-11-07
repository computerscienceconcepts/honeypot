from __future__ import annotations

import asyncio
import logging
import time
from logging.handlers import RotatingFileHandler

from aiohttp import web

from .config import load_config
from .dashboard import create_app as create_dashboard_app
from .listeners import HTTPListener, SSHListener
from .logger import JSONLLogger
from .rate_limiter import RateLimiter


def setup_logging() -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s UTC | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Ensure console/file times are UTC
    formatter.converter = time.gmtime

    sh = logging.StreamHandler()
    sh.setFormatter(formatter)
    root.addHandler(sh)

    fh = RotatingFileHandler("logs/app.log", maxBytes=1_000_000, backupCount=3)
    fh.setFormatter(formatter)
    root.addHandler(fh)


async def start_dashboard(log_path: str, port: int) -> None:
    app = create_dashboard_app(log_path)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host="0.0.0.0", port=port)
    await site.start()
    logging.getLogger("honeypot").info("Dashboard started on 0.0.0.0:%d", port)


async def main_async() -> None:
    setup_logging()
    logger = logging.getLogger("honeypot")
    
    # Startup banner
    banner = "=" * 50 + "\n" + "ShieldOne's Honeypot Started" + "\n" + "=" * 50
    logger.info(banner)
    
    cfg = load_config()

    event_logger = JSONLLogger(cfg.log_path)
    await event_logger.start()

    rate_limiter = RateLimiter(cfg.rate_limit_per_min)

    ssh = SSHListener(
        port=cfg.ssh_port,
        logger=event_logger,
        rate_limiter=rate_limiter,
        concurrency_limit=cfg.max_concurrent_clients,
    )

    http = HTTPListener(
        port=cfg.http_port,
        logger=event_logger,
        rate_limiter=rate_limiter,
        concurrency_limit=cfg.max_concurrent_clients,
        is_https=False,
        redirect_prob=cfg.respond_with_redirect_prob,
    )

    https = HTTPListener(
        port=cfg.https_port,
        logger=event_logger,
        rate_limiter=rate_limiter,
        concurrency_limit=cfg.max_concurrent_clients,
        is_https=True,
        redirect_prob=cfg.respond_with_redirect_prob,
    )

    await asyncio.gather(
        ssh.start(),
        http.start(),
        https.start(),
        start_dashboard(cfg.log_path, cfg.dashboard_port),
    )

    # Run forever
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass
    finally:
        await event_logger.stop()


def main() -> None:
    asyncio.run(main_async())


if __name__ == "__main__":
    main()


