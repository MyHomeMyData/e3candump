"""Tests for the Service 77 decoder."""

import pytest
from e3candump.service77 import S77Decoder
from e3candump.event import S77Event

REQ = 0x682
RSP = 0x692

_CLIENT_ID = bytes([0x43, 0x01, 0x82])


def dec(timeout: float = 1.0) -> S77Decoder:
    return S77Decoder([(REQ, RSP)], timeout=timeout)


def _make_req_payload(ctr: int, did: int, data: bytes) -> bytes:
    """Build a reassembled S77 request payload."""
    n = len(data)
    if n <= 15:
        length_field = bytes([0xB0 + n])
    else:
        length_field = bytes([0xB0, n])
    return (
        bytes([0x77])
        + ctr.to_bytes(2, "little")
        + _CLIENT_ID
        + did.to_bytes(2, "little")
        + length_field
        + data
    )


def _sf(payload: bytes) -> bytes:
    """Wrap payload in an ISO-TP Single Frame."""
    assert len(payload) <= 7
    return bytes([len(payload)]) + payload + bytes(8 - 1 - len(payload))


def _ff(payload: bytes) -> tuple[bytes, list[bytes]]:
    """Split payload into ISO-TP FF + list of CFs."""
    total = len(payload)
    ff_data = payload[:6]
    ff = bytes([(total >> 8) | 0x10, total & 0xFF]) + ff_data + bytes(max(0, 6 - len(ff_data)))
    cfs = []
    sn = 1
    offset = 6
    while offset < total:
        chunk = payload[offset:offset + 7]
        cf = bytes([0x20 | sn]) + chunk + bytes(7 - len(chunk))
        cfs.append(cf)
        sn = (sn + 1) % 16
        offset += 7
    return ff, cfs


def _feed_isotp(decoder: S77Decoder, can_id: int, payload: bytes, ts: float) -> list[S77Event]:
    if len(payload) <= 7:
        frames = [_sf(payload)]
    else:
        ff, cfs = _ff(payload)
        frames = [ff] + cfs
    events = []
    for i, frame in enumerate(frames):
        events.extend(decoder.feed(can_id, frame, ts + i * 0.001))
    return events


# ── Client write → confirmed ──────────────────────────────────────────────────

def test_write_ok():
    """S77 write request is always MF (min payload 10 bytes); response is SF."""
    d = dec()
    req_payload = _make_req_payload(ctr=0x1234, did=0x044D, data=bytes([0x01, 0x02, 0x03]))
    events = _feed_isotp(d, REQ, req_payload, 1.0)
    assert events == []  # no event until response

    rsp_payload = bytes([0x77, 0x34, 0x12, 0x44])  # ctr=0x1234, confirmed
    events = _feed_isotp(d, RSP, rsp_payload, 1.005)
    assert len(events) == 1
    ev = events[0]
    assert isinstance(ev, S77Event)
    assert ev.kind == "write"
    assert ev.status == "ok"
    assert ev.session_ctr == 0x1234
    assert ev.did == 0x044D
    assert ev.data_length == 3
    assert ev.req_frame_type == "MF"
    assert ev.rsp_frame_type == "SF"
    assert ev.duration_ms is not None
    assert ev.duration_ms == pytest.approx(5.0, abs=1.0)


def test_write_mf_ok():
    d = dec()
    data = bytes(range(20))
    req_payload = _make_req_payload(ctr=0x0001, did=0x0100, data=data)
    events = _feed_isotp(d, REQ, req_payload, 1.0)
    assert events == []

    rsp_payload = bytes([0x77, 0x01, 0x00, 0x44])
    events = _feed_isotp(d, RSP, rsp_payload, 1.010)
    assert len(events) == 1
    ev = events[0]
    assert ev.status == "ok"
    assert ev.req_frame_type == "MF"
    assert ev.data_length == 20


# ── Timeout ───────────────────────────────────────────────────────────────────

def test_write_timeout():
    d = dec(timeout=0.5)
    req_payload = _make_req_payload(ctr=0x0002, did=0x0200, data=bytes([0xAA]))
    _feed_isotp(d, REQ, req_payload, 0.0)

    events = d.flush_timeouts(0.3)
    assert events == []

    events = d.flush_timeouts(0.6)
    assert len(events) == 1
    ev = events[0]
    assert ev.kind == "write"
    assert ev.status == "timeout"
    assert ev.did == 0x0200
    assert ev.duration_ms is None


# ── Device push (CTR=0x0000) ──────────────────────────────────────────────────

def test_device_push_b_length_code():
    """Push with 0xBx length code (e.g. 0xB3 = 3 bytes)."""
    d = dec()
    push_payload = (
        bytes([0x77, 0x00, 0x00])
        + _CLIENT_ID
        + bytes([0x4D, 0x04])  # DID=0x044D LE
        + bytes([0xB3, 0x01, 0x02, 0x03])
    )
    events = _feed_isotp(d, RSP, push_payload, 2.0)
    assert len(events) == 1
    ev = events[0]
    assert ev.kind == "push"
    assert ev.did == 0x044D
    assert ev.data_length == 3
    assert ev.payload == bytes([0x01, 0x02, 0x03])


def test_device_push_8x_length_code():
    """Push with 0x8x length code (e.g. 0x82 = 2 bytes, observed on real hardware)."""
    d = dec()
    # Mirrors real trace: DID=0x018C, length_code=0x82, data=B8 01
    push_payload = (
        bytes([0x77, 0x00, 0x00])
        + _CLIENT_ID
        + bytes([0x8C, 0x01])   # DID=0x018C LE
        + bytes([0x82, 0xB8, 0x01])  # length=2, data=B8 01
    )
    events = _feed_isotp(d, RSP, push_payload, 2.0)
    assert len(events) == 1
    ev = events[0]
    assert ev.kind == "push"
    assert ev.did == 0x018C
    assert ev.data_length == 2
    assert ev.payload == bytes([0xB8, 0x01])


# ── Session frames (0x21/0x22) ────────────────────────────────────────────────

def test_session_frames():
    d = dec()
    req_frame = bytes([0x03, 0x77, 0x41, 0x75, 0x21, 0x00, 0x00, 0x00])
    # SF: len=3, payload=0x77 0x41 0x75 0x21 (4 bytes, but SF length=3)
    # Actually for a session frame: payload is exactly [0x77, CTR_L, CTR_H, 0x21]
    # so SF wraps it as: byte0=0x04, bytes1-4=payload, bytes5-7=padding
    req_sf = bytes([0x04, 0x77, 0x40, 0x75, 0x21, 0x55, 0x55, 0x55])
    events = d.feed(REQ, req_sf, 3.0)
    assert events == []

    rsp_sf = bytes([0x04, 0x77, 0x40, 0x75, 0x22, 0x55, 0x55, 0x55])
    events = d.feed(RSP, rsp_sf, 3.001)
    assert len(events) == 1
    ev = events[0]
    assert ev.kind == "session"
    assert ev.status == "session"
    assert ev.req_byte == 0x21
    assert ev.rsp_byte == 0x22


# ── Multiple pairs ────────────────────────────────────────────────────────────

def test_multiple_pairs_independent():
    d = S77Decoder([(0x682, 0x692), (0x683, 0x693)], timeout=1.0)

    req1 = _make_req_payload(ctr=0x0001, did=0x0100, data=bytes([0x01]))
    _feed_isotp(d, 0x682, req1, 1.0)

    req2 = _make_req_payload(ctr=0x0002, did=0x0200, data=bytes([0x02]))
    _feed_isotp(d, 0x683, req2, 1.0)

    rsp2 = bytes([0x77, 0x02, 0x00, 0x44])
    events = _feed_isotp(d, 0x693, rsp2, 1.005)
    assert len(events) == 1
    assert events[0].request_id == 0x683
    assert events[0].did == 0x0200

    rsp1 = bytes([0x77, 0x01, 0x00, 0x44])
    events = _feed_isotp(d, 0x692, rsp1, 1.010)
    assert len(events) == 1
    assert events[0].request_id == 0x682
    assert events[0].did == 0x0100


# ── ff_open flag ──────────────────────────────────────────────────────────────

def test_ff_open_flag():
    d = dec()
    assert not d.ff_open(REQ)
    data = bytes(range(20))
    req_payload = _make_req_payload(ctr=0x0010, did=0x0300, data=data)
    ff, cfs = _ff(req_payload)
    d.feed(REQ, ff, 1.0)
    assert d.ff_open(REQ)
    for cf in cfs:
        d.feed(REQ, cf, 1.001)
    assert not d.ff_open(REQ)
