"""Service 77 decoder.

Viessmann-proprietary write protocol using standard ISO-TP framing.
One S77Decoder instance handles all configured (request_id, response_id) pairs.

Reassembled request payload layout:
  byte0    = 0x77  (service ID)
  byte1-2  = CTR_L, CTR_H  (session counter, LE)
  byte3-5  = 0x43 0x01 0x82  (fixed client ID)
  byte6-7  = DID_L, DID_H  (little-endian)
  byte8    = length code  (same encoding as Collect FF byte3)
  byte9+   = data

Positive response (4 bytes):
  0x77 CTR_L CTR_H 0x44

Session frame (4 bytes, CTR = prev+1):
  client→device: 0x77 CTR_L CTR_H 0x21
  device→client: 0x77 CTR_L CTR_H 0x22

Device push (CTR = 0x0000): same payload as request, from response channel.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from e3candump.event import S77Event
from e3candump.isotp import IsotpReassembler


def _decode_length_code(payload: bytes, offset: int) -> tuple[int, int]:
    """Return (data_length, data_start_offset) from a Viessmann length code.

    Valid length codes have high nibble >= 0x8 (observed: 0x8x and 0xBx).
    If the byte at offset has high nibble < 0x8 it is not a length code;
    all remaining bytes starting at that offset are treated as raw data.
    Low nibble == 0 means the next byte carries the length (16–255 bytes),
    with the 0xC1 escape for values that would otherwise be ambiguous.
    """
    if offset >= len(payload):
        return 0, offset
    code = payload[offset]
    if (code & 0xF0) < 0x80:
        # Byte is not a length code: remaining bytes are the data value
        return len(payload) - offset, offset
    low = code & 0x0F
    if low != 0:
        return low, offset + 1
    # low nibble == 0: length in next byte
    if offset + 1 >= len(payload):
        return 0, offset + 2
    next_byte = payload[offset + 1]
    if next_byte == 0xC1:
        if offset + 2 >= len(payload):
            return 0, offset + 3
        return payload[offset + 2], offset + 3
    return next_byte, offset + 2


@dataclass
class _PendingWrite:
    can_id: int          # request channel
    session_ctr: int
    did: int
    data_length: int
    req_frame_type: str
    payload: bytes
    timestamp: float


@dataclass
class _PendingRead:
    can_id: int          # request channel
    session_ctr: int
    did: int
    req_frame_type: str
    timestamp: float


@dataclass
class _PendingSession:
    """Tracks the 0x21 half of a session frame pair."""
    request_id: int
    response_id: int
    session_ctr: int
    timestamp: float


class S77Decoder:
    """Decode Service 77 traffic for a set of (request_id, response_id) pairs."""

    def __init__(self, pairs: list[tuple[int, int]], timeout: float = 1.0) -> None:
        self._pairs = list(pairs)
        self._timeout = timeout

        # Maps: request_id → response_id and vice-versa
        self._req_to_rsp: dict[int, int] = {}
        self._rsp_to_req: dict[int, int] = {}
        for req, rsp in pairs:
            self._req_to_rsp[req] = rsp
            self._rsp_to_req[rsp] = req

        # ISO-TP reassemblers, one per channel
        self._reassemblers: dict[int, IsotpReassembler] = {}
        for req, rsp in pairs:
            self._reassemblers[req] = IsotpReassembler()
            self._reassemblers[rsp] = IsotpReassembler()

        # Pending writes awaiting confirmation: keyed by request_id
        self._pending_writes: dict[int, _PendingWrite] = {}
        # Pending reads awaiting response: keyed by request_id
        self._pending_reads: dict[int, _PendingRead] = {}
        # Pending session 0x21 frames awaiting 0x22: keyed by request_id
        self._pending_sessions: dict[int, _PendingSession] = {}

    @property
    def monitored_ids(self) -> set[int]:
        return set(self._req_to_rsp) | set(self._rsp_to_req)

    def ff_open(self, can_id: int) -> bool:
        """True when an ISO-TP FF is in progress on this channel."""
        r = self._reassemblers.get(can_id)
        return r is not None and r.in_progress

    def feed(self, can_id: int, data: bytes, timestamp: float) -> list[S77Event]:
        if can_id not in self._reassemblers:
            return []

        reassembler = self._reassemblers[can_id]
        frame_type_before = reassembler.frame_type if reassembler.in_progress else "SF"
        payload = reassembler.feed(data, timestamp)
        if payload is None:
            return []

        # Determine frame type: MF if a FF was open before this completed it
        frame_type = "MF" if frame_type_before == "MF" else "SF"

        if not payload or payload[0] != 0x77:
            return []

        events: list[S77Event] = []

        if can_id in self._req_to_rsp:
            # Frame on request channel — client→device
            events.extend(self._handle_request(can_id, payload, frame_type, timestamp))
        else:
            # Frame on response channel — device→client
            req_id = self._rsp_to_req[can_id]
            events.extend(self._handle_response(can_id, req_id, payload, frame_type, timestamp))

        return events

    def _handle_request(
        self, req_id: int, payload: bytes, frame_type: str, timestamp: float
    ) -> list[S77Event]:
        if len(payload) < 4:
            return []

        ctr = int.from_bytes(payload[1:3], "little")

        # 8-byte read request: 0x77 CTR_L CTR_H 0x41 0x01 0x82 DID_L DID_H
        if len(payload) == 8 and payload[3:6] == b"\x41\x01\x82":
            did = int.from_bytes(payload[6:8], "little")
            self._pending_reads[req_id] = _PendingRead(
                can_id=req_id,
                session_ctr=ctr,
                did=did,
                req_frame_type=frame_type,
                timestamp=timestamp,
            )
            return []

        # 4-byte session frame: 0x77 CTR_L CTR_H 0x21
        if len(payload) == 4 and payload[3] == 0x21:
            rsp_id = self._req_to_rsp[req_id]
            self._pending_sessions[req_id] = _PendingSession(
                request_id=req_id,
                response_id=rsp_id,
                session_ctr=ctr,
                timestamp=timestamp,
            )
            return []

        # Remaining path: full write request (at least 9 bytes)
        if len(payload) < 9:
            return []

        # Verify fixed client ID bytes3-5
        if payload[3:6] != b"\x43\x01\x82":
            return []

        did = int.from_bytes(payload[6:8], "little")
        data_length, data_start = _decode_length_code(payload, 8)
        data_payload = payload[data_start:]

        rsp_id = self._req_to_rsp[req_id]
        self._pending_writes[req_id] = _PendingWrite(
            can_id=req_id,
            session_ctr=ctr,
            did=did,
            data_length=data_length,
            req_frame_type=frame_type,
            payload=bytes(data_payload[:data_length]),
            timestamp=timestamp,
        )
        return []

    def _handle_response(
        self, rsp_id: int, req_id: int, payload: bytes, frame_type: str, timestamp: float
    ) -> list[S77Event]:
        if len(payload) < 3:
            return []

        ctr = int.from_bytes(payload[1:3], "little")

        # 4-byte response to session frame: 0x77 CTR_L CTR_H 0x22
        if len(payload) == 4 and payload[3] == 0x22:
            pending = self._pending_sessions.pop(req_id, None)
            if pending is not None:
                dt = (timestamp - pending.timestamp) * 1000
                return [S77Event(
                    timestamp=pending.timestamp,
                    request_id=req_id,
                    response_id=rsp_id,
                    kind="session",
                    session_ctr=ctr,
                    did=0,
                    data_length=0,
                    req_frame_type="SF",
                    rsp_frame_type="SF",
                    status="session",
                    duration_ms=dt,
                    req_byte=0x21,
                    rsp_byte=0x22,
                )]
            return []

        # Read response: 0x77 CTR_L CTR_H 0x42 0x01 0x82 DID_L DID_H len_code data...
        if len(payload) >= 9 and payload[3:6] == b"\x42\x01\x82":
            pending = self._pending_reads.pop(req_id, None)
            if pending is not None and pending.session_ctr == ctr:
                did = int.from_bytes(payload[6:8], "little")
                data_length, data_start = _decode_length_code(payload, 8)
                data_payload = payload[data_start:data_start + data_length]
                dt = (timestamp - pending.timestamp) * 1000
                return [S77Event(
                    timestamp=pending.timestamp,
                    request_id=req_id,
                    response_id=rsp_id,
                    kind="read",
                    session_ctr=ctr,
                    did=did,
                    data_length=data_length,
                    req_frame_type=pending.req_frame_type,
                    rsp_frame_type=frame_type,
                    status="ok",
                    duration_ms=dt,
                    payload=bytes(data_payload),
                )]
            return []

        # Positive confirmation: 0x77 CTR_L CTR_H 0x44
        if len(payload) == 4 and payload[3] == 0x44:
            pending = self._pending_writes.pop(req_id, None)
            if pending is not None and pending.session_ctr == ctr:
                dt = (timestamp - pending.timestamp) * 1000
                return [S77Event(
                    timestamp=pending.timestamp,
                    request_id=req_id,
                    response_id=rsp_id,
                    kind="write",
                    session_ctr=ctr,
                    did=pending.did,
                    data_length=pending.data_length,
                    req_frame_type=pending.req_frame_type,
                    rsp_frame_type=frame_type,
                    status="ok",
                    duration_ms=dt,
                    payload=pending.payload,
                )]
            return []

        # Device push / sync (CTR == 0x0000, full payload on response channel)
        if ctr == 0x0000 and len(payload) >= 9:
            if payload[3:6] != b"\x43\x01\x82":
                return []
            did = int.from_bytes(payload[6:8], "little")
            data_length, data_start = _decode_length_code(payload, 8)
            data_payload = payload[data_start:]
            return [S77Event(
                timestamp=timestamp,
                request_id=req_id,
                response_id=rsp_id,
                kind="push",
                session_ctr=0,
                did=did,
                data_length=data_length,
                req_frame_type="",
                rsp_frame_type=frame_type,
                status="push",
                duration_ms=None,
                payload=bytes(data_payload[:data_length]),
            )]

        return []

    def flush_timeouts(self, now: float) -> list[S77Event]:
        """Return timeout events for pending writes/reads that have exceeded the timeout."""
        events: list[S77Event] = []
        expired_writes = [
            req_id
            for req_id, pw in self._pending_writes.items()
            if now - pw.timestamp >= self._timeout
        ]
        for req_id in expired_writes:
            pw = self._pending_writes.pop(req_id)
            rsp_id = self._req_to_rsp[req_id]
            events.append(S77Event(
                timestamp=pw.timestamp,
                request_id=req_id,
                response_id=rsp_id,
                kind="write",
                session_ctr=pw.session_ctr,
                did=pw.did,
                data_length=pw.data_length,
                req_frame_type=pw.req_frame_type,
                rsp_frame_type="",
                status="timeout",
                duration_ms=None,
                payload=pw.payload,
            ))
        expired_reads = [
            req_id
            for req_id, pr in self._pending_reads.items()
            if now - pr.timestamp >= self._timeout
        ]
        for req_id in expired_reads:
            pr = self._pending_reads.pop(req_id)
            rsp_id = self._req_to_rsp[req_id]
            events.append(S77Event(
                timestamp=pr.timestamp,
                request_id=req_id,
                response_id=rsp_id,
                kind="read",
                session_ctr=pr.session_ctr,
                did=pr.did,
                data_length=0,
                req_frame_type=pr.req_frame_type,
                rsp_frame_type="",
                status="timeout",
                duration_ms=None,
                payload=b"",
            ))
        return events
