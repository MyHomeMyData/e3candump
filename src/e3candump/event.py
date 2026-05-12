"""Event data classes produced by the protocol decoders."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class CollectEvent:
    timestamp: float
    can_id: int
    did: int
    data_length: int
    frame_type: str        # "SF" or "MF"
    payload: bytes = field(default_factory=bytes)


@dataclass
class S77Event:
    timestamp: float
    request_id: int
    response_id: int
    kind: str              # "write" | "push" | "session"
    session_ctr: int
    did: int               # 0 for session frames
    data_length: int       # payload length; 0 for session frames
    req_frame_type: str    # "SF" or "MF"
    rsp_frame_type: str    # "SF" or "MF"; empty string for push/session
    status: str            # "ok" | "timeout" | "push" | "session"
    duration_ms: float | None
    payload: bytes = field(default_factory=bytes)
    # session frames only
    req_byte: int = 0      # 0x21
    rsp_byte: int = 0      # 0x22
