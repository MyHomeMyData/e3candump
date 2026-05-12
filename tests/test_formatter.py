"""Tests for the output formatter."""

import json
import pytest
from e3candump.event import CollectEvent, S77Event
from e3candump.formatter import format_event


def _collect(did=0x0140, length=9, ft="MF", payload=b""):
    return CollectEvent(
        timestamp=1746789865.131,
        can_id=0x693,
        did=did,
        data_length=length,
        frame_type=ft,
        payload=payload,
    )


def _s77_write(status="ok", dt=2.0, req_ft="SF", rsp_ft="SF", payload=b""):
    return S77Event(
        timestamp=1746789865.140,
        request_id=0x682,
        response_id=0x692,
        kind="write",
        session_ctr=0x7540,
        did=0x044D,
        data_length=3,
        req_frame_type=req_ft,
        rsp_frame_type=rsp_ft,
        status=status,
        duration_ms=dt,
        payload=payload,
    )


def _s77_push():
    return S77Event(
        timestamp=1746789865.143,
        request_id=0x682,
        response_id=0x692,
        kind="push",
        session_ctr=0,
        did=0x044D,
        data_length=3,
        req_frame_type="",
        rsp_frame_type="SF",
        status="push",
        duration_ms=None,
    )


def _s77_session():
    return S77Event(
        timestamp=1746789865.144,
        request_id=0x682,
        response_id=0x692,
        kind="session",
        session_ctr=0x7541,
        did=0,
        data_length=0,
        req_frame_type="SF",
        rsp_frame_type="SF",
        status="session",
        duration_ms=1.0,
        req_byte=0x21,
        rsp_byte=0x22,
    )


# ── Text format ───────────────────────────────────────────────────────────────

def test_collect_text_contains_fields():
    line = format_event(_collect(), use_json=False, payload=False, verbose=False)
    assert line is not None
    assert "COLLECT" in line
    assert "0x0693" in line
    assert "DID=0x0140" in line
    assert "320" in line       # decimal DID
    assert "len=9" in line
    assert "MF" in line


def test_collect_text_sf():
    line = format_event(_collect(ft="SF"), use_json=False, payload=False, verbose=False)
    assert "SF" in line


def test_collect_text_with_payload():
    ev = _collect(payload=bytes([0xDE, 0xAD, 0xBE]))
    line = format_event(ev, use_json=False, payload=True, verbose=False)
    assert "de ad be" in line


def test_s77_write_ok_text():
    line = format_event(_s77_write(), use_json=False, payload=False, verbose=False)
    assert line is not None
    assert "S77" in line
    assert "0x0682→0x0692" in line
    assert "DID=0x044D" in line
    assert "CTR=0x7540" in line
    assert "ok" in line
    assert "dt=" in line


def test_s77_write_timeout_text():
    ev = _s77_write(status="timeout", dt=None)
    line = format_event(ev, use_json=False, payload=False, verbose=False)
    assert "timeout" in line
    assert "dt=" not in line


def test_s77_push_text():
    line = format_event(_s77_push(), use_json=False, payload=False, verbose=False)
    assert "S77-PUSH" in line
    assert "CTR=" not in line   # CTR always 0x0000 for push — omitted for alignment


def test_s77_session_suppressed_without_verbose():
    line = format_event(_s77_session(), use_json=False, payload=False, verbose=False)
    assert line is None


def test_s77_session_shown_with_verbose():
    line = format_event(_s77_session(), use_json=False, payload=False, verbose=True)
    assert line is not None
    assert "S77-SESSION" in line
    assert "0x21" in line
    assert "0x22" in line


# ── JSON format ───────────────────────────────────────────────────────────────

def test_collect_json_valid():
    line = format_event(_collect(), use_json=True, payload=False, verbose=False)
    obj = json.loads(line)
    assert obj["type"] == "collect"
    assert obj["can_id"] == 0x693
    assert obj["did"] == 0x0140
    assert obj["data_length"] == 9
    assert obj["frame_type"] == "MF"


def test_collect_json_with_payload():
    ev = _collect(payload=bytes([0xAA, 0xBB]))
    line = format_event(ev, use_json=True, payload=True, verbose=False)
    obj = json.loads(line)
    assert obj["data"] == "aabb"


def test_s77_write_json():
    line = format_event(_s77_write(), use_json=True, payload=False, verbose=False)
    obj = json.loads(line)
    assert obj["type"] == "s77_write"
    assert obj["status"] == "ok"
    assert obj["did"] == 0x044D
    assert obj["session_ctr"] == 0x7540
    assert "duration_ms" in obj


def test_s77_push_json():
    line = format_event(_s77_push(), use_json=True, payload=False, verbose=False)
    obj = json.loads(line)
    assert obj["type"] == "s77_push"
    assert obj["session_ctr"] == 0


def test_s77_session_json_suppressed():
    line = format_event(_s77_session(), use_json=True, payload=False, verbose=False)
    assert line is None


def test_s77_session_json_verbose():
    line = format_event(_s77_session(), use_json=True, payload=False, verbose=True)
    obj = json.loads(line)
    assert obj["type"] == "s77_session"
    assert obj["req_byte"] == "0x21"
