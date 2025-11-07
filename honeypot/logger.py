from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


JsonDict = Dict[str, Any]


class JSONLLogger:
    """Async JSONL event logger with a background writer task.

    Each call to log_event enqueues a JSON-serializable dict. The background
    task writes each event as a single line to the configured file.
    """

    def __init__(self, file_path: str) -> None:
        self.file_path = Path(file_path)
        self._queue: "asyncio.Queue[JsonDict]" = asyncio.Queue()
        self._task: Optional[asyncio.Task[None]] = None
        self._stopped = asyncio.Event()

        # Developer logging
        self._logger = logging.getLogger("honeypot.events")

        # Ensure file exists
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        self.file_path.touch(exist_ok=True)

    async def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run_writer(), name="jsonl-writer")

    async def stop(self) -> None:
        self._stopped.set()
        if self._task:
            await self._task
            self._task = None

    async def log_event(self, event: JsonDict) -> None:
        await self._queue.put(event)

    async def _run_writer(self) -> None:
        # Use buffered write mode for performance
        with self.file_path.open("a", encoding="utf-8") as fp:
            while not self._stopped.is_set():
                try:
                    event = await asyncio.wait_for(self._queue.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue
                try:
                    line = json.dumps(event, ensure_ascii=False)
                    fp.write(line + "\n")
                    fp.flush()
                    self._logger.debug("Event written: %s", line)
                except Exception as exc:  # noqa: BLE001
                    self._logger.exception("Failed to write event: %s", exc)


def iso_timestamp() -> str:
    """Return a human-friendly UTC timestamp without microseconds.

    Example: "2025-11-02 13:20:53 UTC"
    """
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%d %H:%M:%S UTC")


def encode_payload(data: bytes) -> str:
    """Return payload as UTF-8 text when possible; otherwise base64-encoded string.

    The log field remains named 'raw_payload' as per requirements. Consumers
    should treat the value as opaque text which may be base64 if the incoming
    payload was binary.
    """
    try:
        return data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        import base64

        return base64.b64encode(data).decode("ascii")


