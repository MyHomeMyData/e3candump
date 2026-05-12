"""Collect protocol decoder.

Viessmann E3 devices broadcast data-point values autonomously using a
proprietary framing that looks like ISO-TP First/Continuation Frames but
uses a different length-code encoding and no Flow Control.

Frame format (8 bytes each):
  FF: byte0=0x21  byte1-2=DID(LE)  byte3=length_code  byte4+=payload
  CF: byte0=0x22..0x2F (wraps 0x2F->0x20)  byte1-7=payload

Length code (FF byte3):
  0xB1-0xBF : total payload = code - 0xB0 bytes, payload starts at byte4
  0xB0, next != 0xC1 : total payload = next byte (16-255), payload at byte5
  0xB0, next == 0xC1 : total payload = byte after 0xC1, payload at byte6
"""

from __future__ import annotations

from dataclasses import dataclass, field

from e3candump.event import CollectEvent


@dataclass
class _CollectState:
    did: int
    expected_length: int
    payload: bytearray = field(default_factory=bytearray)
    next_sn: int = 0x22          # expected byte0 of next CF
    timestamp: float = 0.0


class CollectDecoder:
    """Decode Collect frames for a set of CAN-IDs.

    Maintains per-CAN-ID reassembly state and an 'FF-open' flag used by the
    monitor to disambiguate Collect CF1 from Service 77 CF1 on shared IDs.
    """

    def __init__(self, can_ids: set[int]) -> None:
        self._can_ids = set(can_ids)
        self._state: dict[int, _CollectState | None] = {i: None for i in can_ids}

    @property
    def can_ids(self) -> set[int]:
        return self._can_ids

    def ff_open(self, can_id: int) -> bool:
        """True when a Collect FF has been received and CFs are expected."""
        return self._state.get(can_id) is not None

    def feed(self, can_id: int, data: bytes, timestamp: float) -> CollectEvent | None:
        if can_id not in self._can_ids:
            return None
        if len(data) < 1:
            return None

        b0 = data[0]

        # --- First Frame detection ---
        if b0 == 0x21:
            return self._handle_ff(can_id, data, timestamp)

        # --- Continuation Frame ---
        state = self._state.get(can_id)
        if state is not None and b0 == state.next_sn:
            return self._handle_cf(can_id, data, state)

        # Not a Collect frame for this CAN-ID right now
        return None

    def _handle_ff(self, can_id: int, data: bytes, timestamp: float) -> CollectEvent | None:
        if len(data) < 5:
            return None

        did = int.from_bytes(data[1:3], "little")
        length_code = data[3]

        if 0xB1 <= length_code <= 0xBF:
            total_length = length_code - 0xB0
            payload_start = 4
        elif length_code == 0xB0:
            if len(data) < 6:
                return None
            if data[4] == 0xC1:
                if len(data) < 7:
                    return None
                total_length = data[5]
                payload_start = 6
            else:
                total_length = data[4]
                payload_start = 5
        else:
            # Not a Collect FF — reset state
            self._state[can_id] = None
            return None

        payload_bytes = bytearray(data[payload_start:8])

        if len(payload_bytes) >= total_length:
            # Single-frame Collect (fits in one CAN frame)
            self._state[can_id] = None
            return CollectEvent(
                timestamp=timestamp,
                can_id=can_id,
                did=did,
                data_length=total_length,
                frame_type="SF",
                payload=bytes(payload_bytes[:total_length]),
            )

        self._state[can_id] = _CollectState(
            did=did,
            expected_length=total_length,
            payload=payload_bytes,
            next_sn=0x22,
            timestamp=timestamp,
        )
        return None

    def _handle_cf(self, can_id: int, data: bytes, state: _CollectState) -> CollectEvent | None:
        state.payload.extend(data[1:8])

        # Advance sequence number: 0x22..0x2F, then wraps to 0x20
        next_sn = state.next_sn + 1
        if next_sn > 0x2F:
            next_sn = 0x20
        state.next_sn = next_sn

        if len(state.payload) >= state.expected_length:
            event = CollectEvent(
                timestamp=state.timestamp,
                can_id=can_id,
                did=state.did,
                data_length=state.expected_length,
                frame_type="MF",
                payload=bytes(state.payload[: state.expected_length]),
            )
            self._state[can_id] = None
            return event

        return None
