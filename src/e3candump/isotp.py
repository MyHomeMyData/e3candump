"""ISO-TP (ISO 15765-2) reassembler for Service 77 and future UDS support.

One instance per (request_id, response_id) channel pair.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class _IsotpState:
    expected_length: int = 0
    payload: bytearray = field(default_factory=bytearray)
    next_sn: int = 0          # expected sequence number (low nibble)
    timestamp: float = 0.0
    frame_type: str = "SF"    # "SF" or "MF"


class IsotpReassembler:
    """Reassemble ISO-TP frames for a single CAN-ID channel.

    Handles Single Frame (SF) and Multi-Frame (FF + CFs) per ISO 15765-2.
    Does NOT handle Flow Control (passive monitor, never sends FC).
    """

    def __init__(self) -> None:
        self._state: _IsotpState | None = None

    def feed(self, data: bytes, timestamp: float) -> bytes | None:
        """Feed one CAN frame; return reassembled payload when complete."""
        if not data:
            return None

        frame_type_nibble = (data[0] >> 4) & 0x0F

        if frame_type_nibble == 0:
            # Single Frame
            length = data[0] & 0x0F
            if length == 0 and len(data) > 1:
                # Extended SF (ISO 15765-2:2016 §9.6.2.2)
                length = data[1]
                payload = bytes(data[2 : 2 + length])
            else:
                payload = bytes(data[1 : 1 + length])
            self._state = None
            return payload

        if frame_type_nibble == 1:
            # First Frame
            length = ((data[0] & 0x0F) << 8) | data[1]
            if length == 0 and len(data) >= 6:
                # Extended FF length (4-byte length field)
                length = int.from_bytes(data[2:6], "big")
                payload_start = 6
            else:
                payload_start = 2
            self._state = _IsotpState(
                expected_length=length,
                payload=bytearray(data[payload_start:]),
                next_sn=1,
                timestamp=timestamp,
                frame_type="MF",
            )
            return None

        if frame_type_nibble == 2:
            # Consecutive Frame
            if self._state is None:
                return None
            sn = data[0] & 0x0F
            if sn != self._state.next_sn:
                self._state = None
                return None
            self._state.payload.extend(data[1:])
            self._state.next_sn = (self._state.next_sn + 1) % 16
            if len(self._state.payload) >= self._state.expected_length:
                payload = bytes(self._state.payload[: self._state.expected_length])
                self._state = None
                return payload
            return None

        # FC or unknown — ignore
        return None

    def reset(self) -> None:
        self._state = None

    @property
    def in_progress(self) -> bool:
        return self._state is not None

    @property
    def frame_type(self) -> str:
        """Frame type of the current in-progress reassembly, or 'SF'."""
        return self._state.frame_type if self._state else "SF"
