"""Text and JSON output formatters."""

from __future__ import annotations

import datetime
import json

from e3candump.event import CollectEvent, S77Event

_COL_TS = 15
_COL_KIND = 12
_COL_IDS = 18
_COL_DID = 22
_COL_LEN = 9
_COL_CTR = 13
_COL_DT = 10
_COL_FT = 6


def _ts(timestamp: float) -> str:
    dt = datetime.datetime.fromtimestamp(timestamp)
    return dt.strftime("%H:%M:%S.") + f"{dt.microsecond // 1000:03d}"


def _hex(n: int) -> str:
    return f"0x{n:04X}"


def _payload_hex(payload: bytes) -> str:
    return payload.hex(" ") if payload else ""


# ── Text formatters ──────────────────────────────────────────────────────────

def format_collect_text(event: CollectEvent, payload: bool = False) -> str:
    ts = _ts(event.timestamp)
    kind = "COLLECT"
    cid = f"{_hex(event.can_id)}"
    did = f"DID={_hex(event.did)} ({event.did})"
    length = f"len={event.data_length}"
    ft = event.frame_type

    line = f"{ts:<{_COL_TS}}{kind:<{_COL_KIND}}{cid:<{_COL_IDS}}{did:<{_COL_DID}}{length:<{_COL_LEN}}{ft}"
    if payload and event.payload:
        line += f"  data={_payload_hex(event.payload)}"
    return line


def format_s77_text(event: S77Event, payload: bool = False, verbose: bool = False) -> str | None:
    if event.kind == "session" and not verbose:
        return None

    ts = _ts(event.timestamp)
    ids = f"{_hex(event.request_id)}→{_hex(event.response_id)}"

    if event.kind == "write":
        kind = "S77"
        did = f"DID={_hex(event.did)} ({event.did})"
        ctr = f"CTR={_hex(event.session_ctr)}"
        length = f"len={event.data_length}"
        dt = f"dt={event.duration_ms:.1f}ms" if event.duration_ms is not None else ""
        ft_parts = [p for p in (event.req_frame_type, event.rsp_frame_type) if p]
        ft = "/".join(ft_parts)
        status = event.status

        parts = [
            f"{ts:<{_COL_TS}}",
            f"{kind:<{_COL_KIND}}",
            f"{ids:<{_COL_IDS}}",
            f"{did:<{_COL_DID}}",
            f"{ctr:<{_COL_CTR}}",
            f"{length:<{_COL_LEN}}",
            f"{dt:<{_COL_DT}}",
            f"{ft:<{_COL_FT}}",
            status,
        ]
        line = "".join(parts).rstrip()
        if payload and event.payload:
            line += f"  data={_payload_hex(event.payload)}"
        return line

    if event.kind == "push":
        kind = "S77-PUSH"
        did = f"DID={_hex(event.did)} ({event.did})"
        length = f"len={event.data_length}"
        ft = event.rsp_frame_type

        # CTR is always 0x0000 for pushes (that's how they are identified),
        # so it carries no information and is omitted to align with COLLECT.
        parts = [
            f"{ts:<{_COL_TS}}",
            f"{kind:<{_COL_KIND}}",
            f"{ids:<{_COL_IDS}}",
            f"{did:<{_COL_DID}}",
            f"{length:<{_COL_LEN}}",
            f"{ft:<{_COL_FT}}",
        ]
        line = "".join(parts).rstrip()
        if payload and event.payload:
            line += f"  data={_payload_hex(event.payload)}"
        return line

    if event.kind == "session":
        kind = "S77-SESSION"
        ctr = f"CTR={_hex(event.session_ctr)}"
        dt = f"dt={event.duration_ms:.1f}ms" if event.duration_ms is not None else ""
        detail = f"req=0x{event.req_byte:02X}  rsp=0x{event.rsp_byte:02X}"

        parts = [
            f"{ts:<{_COL_TS}}",
            f"{kind:<{_COL_KIND}}",
            f"{ids:<{_COL_IDS}}",
            f"{'':>{_COL_DID}}",
            f"{ctr:<{_COL_CTR}}",
            f"{'':>{_COL_LEN}}",
            f"{dt:<{_COL_DT}}",
            f"{'SF/SF':<{_COL_FT}}",
            detail,
        ]
        return "".join(parts).rstrip()

    return None


# ── JSON formatters ──────────────────────────────────────────────────────────

def format_collect_json(event: CollectEvent, payload: bool = False) -> str:
    obj: dict = {
        "timestamp": event.timestamp,
        "type": "collect",
        "can_id": event.can_id,
        "did": event.did,
        "data_length": event.data_length,
        "frame_type": event.frame_type,
    }
    if payload and event.payload:
        obj["data"] = event.payload.hex()
    return json.dumps(obj)


def format_s77_json(event: S77Event, payload: bool = False, verbose: bool = False) -> str | None:
    if event.kind == "session" and not verbose:
        return None

    obj: dict = {
        "timestamp": event.timestamp,
        "type": f"s77_{event.kind}",
        "request_id": event.request_id,
        "response_id": event.response_id,
        "session_ctr": event.session_ctr,
        "status": event.status,
    }

    if event.kind in ("write", "push"):
        obj["did"] = event.did
        obj["data_length"] = event.data_length
        if event.req_frame_type:
            obj["req_frame_type"] = event.req_frame_type
        if event.rsp_frame_type:
            obj["rsp_frame_type"] = event.rsp_frame_type
        if event.duration_ms is not None:
            obj["duration_ms"] = round(event.duration_ms, 3)
        if payload and event.payload:
            obj["data"] = event.payload.hex()

    if event.kind == "session":
        obj["req_byte"] = f"0x{event.req_byte:02X}"
        obj["rsp_byte"] = f"0x{event.rsp_byte:02X}"
        if event.duration_ms is not None:
            obj["duration_ms"] = round(event.duration_ms, 3)

    return json.dumps(obj)


# ── Dispatch helpers ─────────────────────────────────────────────────────────

def format_event(
    event: CollectEvent | S77Event,
    *,
    use_json: bool,
    payload: bool,
    verbose: bool,
) -> str | None:
    if isinstance(event, CollectEvent):
        if use_json:
            return format_collect_json(event, payload=payload)
        return format_collect_text(event, payload=payload)
    if isinstance(event, S77Event):
        if use_json:
            return format_s77_json(event, payload=payload, verbose=verbose)
        return format_s77_text(event, payload=payload, verbose=verbose)
    return None
