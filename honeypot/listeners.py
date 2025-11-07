from __future__ import annotations

import asyncio
import logging
import random
from typing import Optional

from .logger import JSONLLogger, encode_payload, iso_timestamp
from .rate_limiter import RateLimiter


ReadLimit = 4096


class BaseListener:
    def __init__(
        self,
        name: str,
        port: int,
        logger: JSONLLogger,
        rate_limiter: RateLimiter,
        concurrency_limit: int,
    ) -> None:
        self.name = name
        self.port = port
        self.logger = logger
        self.rate_limiter = rate_limiter
        self._sem = asyncio.Semaphore(concurrency_limit)
        self._server: Optional[asyncio.AbstractServer] = None
        self._log = logging.getLogger(f"honeypot.{name}")

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_wrapped, port=self.port)
        sockets = ", ".join(str(s.getsockname()) for s in self._server.sockets or [])
        self._log.info("%s listener started on %s", self.name, sockets)

    async def _handle_wrapped(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        async with self._sem:
            try:
                await self.handle_client(reader, writer)
            except Exception:  # noqa: BLE001
                # We never act on attacker input; errors should be logged only.
                self._log.exception("Error in %s client handler", self.name)
            finally:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:  # noqa: D401
        """Handle a client connection. Must be implemented by subclasses."""
        raise NotImplementedError


class SSHListener(BaseListener):
    def __init__(
        self,
        port: int,
        logger: JSONLLogger,
        rate_limiter: RateLimiter,
        concurrency_limit: int,
    ) -> None:
        super().__init__("ssh", port, logger, rate_limiter, concurrency_limit)

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        sockname = writer.get_extra_info("sockname")
        src_ip, src_port = (peer[0], peer[1]) if peer else ("?", 0)
        dst_port = sockname[1] if sockname else self.port

        allowed = self.rate_limiter.allow(src_ip)
        if not allowed:
            # Still log the attempt but do not engage further.
            await self.logger.log_event(
                {
                    "timestamp": iso_timestamp(),
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": "SSH",
                    "raw_payload": "",
                    "user_agent": None,
                    "geoip": None,
                    "notes": "rate_limited",
                }
            )
            return

        # Read anything the client sends (non-blocking, short timeout)
        payload = b""
        try:
            payload = await asyncio.wait_for(reader.read(ReadLimit), timeout=1.0)
        except asyncio.TimeoutError:
            payload = b""

        # Send SSH-like banner then disconnect
        banner = b"SSH-2.0-OpenSSH_7.9p1\r\n"
        try:
            writer.write(banner)
            await writer.drain()
            await asyncio.sleep(0.5)
        except Exception:  # noqa: BLE001
            pass

        await self.logger.log_event(
            {
                "timestamp": iso_timestamp(),
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": "SSH",
                "raw_payload": encode_payload(payload),
                "user_agent": None,
                "geoip": None,
                "notes": "sent_banner_disconnect",
            }
        )


class HTTPListener(BaseListener):
    def __init__(
        self,
        port: int,
        logger: JSONLLogger,
        rate_limiter: RateLimiter,
        concurrency_limit: int,
        is_https: bool = False,
        redirect_prob: float = 0.3,
    ) -> None:
        name = "https" if is_https else "http"
        super().__init__(name, port, logger, rate_limiter, concurrency_limit)
        self.is_https = is_https
        self.redirect_prob = max(0.0, min(1.0, redirect_prob))

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        sockname = writer.get_extra_info("sockname")
        src_ip, src_port = (peer[0], peer[1]) if peer else ("?", 0)
        dst_port = sockname[1] if sockname else self.port

        allowed = self.rate_limiter.allow(src_ip)
        if not allowed:
            await self.logger.log_event(
                {
                    "timestamp": iso_timestamp(),
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": "HTTPS" if self.is_https else "HTTP",
                    "raw_payload": "",
                    "user_agent": None,
                    "geoip": None,
                    "notes": "rate_limited",
                }
            )
            return

        try:
            data = await asyncio.wait_for(reader.read(ReadLimit), timeout=2.0)
        except asyncio.TimeoutError:
            data = b""

        user_agent = _parse_user_agent(data)

        # Choose response: 302 redirect or 200 HTML
        if random.random() < self.redirect_prob:
            response = (
                "HTTP/1.1 302 Found\r\n"
                "Location: /login\r\n"
                "Content-Length: 0\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            note = "sent_302"
        else:
            body = (
                "<html><head><title>Welcome</title></head>"
                "<body><h1>Welcome</h1><p>It works.</p></body></html>"
            ).encode("utf-8")
            headers = (
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(body)}\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii")
            response = headers + body
            note = "sent_200"

        try:
            writer.write(response)
            await writer.drain()
        except Exception:  # noqa: BLE001
            pass

        await self.logger.log_event(
            {
                "timestamp": iso_timestamp(),
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": "HTTPS" if self.is_https else "HTTP",
                "raw_payload": encode_payload(data),
                "user_agent": user_agent,
                "geoip": None,
                "notes": note,
            }
        )


def _parse_user_agent(request_bytes: bytes) -> Optional[str]:
    try:
        text = request_bytes.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        return None
    # Very simple header scan
    # Limit to first 30 lines to avoid large payload scans
    for line in text.splitlines()[:30]:
        if line.lower().startswith("user-agent:"):
            # Return value after the colon
            return line.split(":", 1)[1].strip() or None
    return None


