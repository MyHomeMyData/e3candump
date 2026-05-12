"""CAN monitor: reads frames, dispatches to decoders, yields events."""

from __future__ import annotations

import time
from typing import Iterator

import can

from e3candump.collect import CollectDecoder
from e3candump.event import CollectEvent, S77Event
from e3candump.service77 import S77Decoder

DEFAULT_COLLECT_IDS = (0x451, 0x693)

_TIMEOUT_CHECK_INTERVAL = 0.1


def _route(
    can_id: int,
    data: bytes,
    timestamp: float,
    collect_decoder: CollectDecoder,
    s77_decoder: S77Decoder | None,
) -> list[CollectEvent | S77Event]:
    """Route one CAN frame to the appropriate decoder and return any events."""
    if not data:
        return []

    b0 = data[0]
    nibble = (b0 >> 4) & 0x0F

    in_collect = can_id in collect_decoder.can_ids
    in_s77 = s77_decoder is not None and can_id in s77_decoder.monitored_ids

    # --- Unambiguous: only one decoder interested ---
    if in_collect and not in_s77:
        ev = collect_decoder.feed(can_id, data, timestamp)
        return [ev] if ev else []

    if in_s77 and not in_collect:
        return s77_decoder.feed(can_id, data, timestamp)  # type: ignore[union-attr]

    if not in_collect and not in_s77:
        return []

    # --- Shared CAN-ID: Collect + S77 both interested ---
    # ISO-TP FF nibble = 0x1 → unambiguously S77 (Collect never uses this)
    if nibble == 0x1:
        return s77_decoder.feed(can_id, data, timestamp)  # type: ignore[union-attr]

    # If S77 ISO-TP reassembly is in progress, route all 0x2x frames to S77
    if s77_decoder.ff_open(can_id) and nibble == 0x2:  # type: ignore[union-attr]
        return s77_decoder.feed(can_id, data, timestamp)  # type: ignore[union-attr]

    # byte0 == 0x21 and no S77 FF open → Collect FF or Collect CF
    # byte0 == 0x22..0x2F and Collect in progress → Collect CF
    ev = collect_decoder.feed(can_id, data, timestamp)
    return [ev] if ev else []


def monitor(
    interface: str,
    channel: str,
    collect_ids: tuple[int, ...],
    s77_pairs: list[tuple[int, int]],
    timeout: float,
) -> Iterator[CollectEvent | S77Event]:
    """Open a CAN bus and yield decoded events indefinitely.

    Raises KeyboardInterrupt when the user presses Ctrl+C.
    """
    collect_decoder = CollectDecoder(set(collect_ids))
    s77_decoder = S77Decoder(s77_pairs, timeout=timeout) if s77_pairs else None

    bus = can.Bus(interface=interface, channel=channel)
    try:
        last_timeout_check = time.monotonic()
        while True:
            msg = bus.recv(timeout=_TIMEOUT_CHECK_INTERVAL)
            now = time.monotonic()

            if s77_decoder and (now - last_timeout_check) >= _TIMEOUT_CHECK_INTERVAL:
                for event in s77_decoder.flush_timeouts(now):
                    yield event
                last_timeout_check = now

            if msg is None:
                continue

            for event in _route(
                msg.arbitration_id,
                bytes(msg.data),
                msg.timestamp,
                collect_decoder,
                s77_decoder,
            ):
                yield event

    finally:
        bus.shutdown()
