"""In-memory message bus for cross-agent breakthrough broadcasting."""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict

log = logging.getLogger("ctf-solver.broadcast")

# Per-challenge, per-run queues: _queues[challenge_id][run_id] = Queue
_queues: dict[str, dict[str, asyncio.Queue]] = defaultdict(dict)


def register_run(challenge_id: str, run_id: str) -> None:
    """Create a queue for this run to receive broadcasts."""
    _queues[challenge_id][run_id] = asyncio.Queue()


def unregister_run(challenge_id: str, run_id: str) -> None:
    """Remove the queue when run finishes."""
    _queues.get(challenge_id, {}).pop(run_id, None)
    if challenge_id in _queues and not _queues[challenge_id]:
        del _queues[challenge_id]


async def broadcast_to_teammates(
    challenge_id: str, source_run_id: str, message: str
) -> int:
    """Put message into every OTHER run's queue. Returns count sent."""
    runs = _queues.get(challenge_id, {})
    count = 0
    for run_id, queue in runs.items():
        if run_id != source_run_id:
            await queue.put(message)
            count += 1
    if count:
        log.info(
            "[%s/%s] Broadcast to %d teammates: %s",
            challenge_id[:8], source_run_id[:8], count,
            message[:100],
        )
    return count


async def get_pending_broadcast(
    challenge_id: str, run_id: str
) -> str | None:
    """Non-blocking check for pending messages. Returns combined or None."""
    queue = _queues.get(challenge_id, {}).get(run_id)
    if not queue or queue.empty():
        return None
    parts = []
    while not queue.empty():
        try:
            parts.append(queue.get_nowait())
        except asyncio.QueueEmpty:
            break
    return "\n\n".join(parts) if parts else None
