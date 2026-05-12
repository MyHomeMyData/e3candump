"""Tests for the Collect protocol decoder."""

import pytest
from e3candump.collect import CollectDecoder
from e3candump.event import CollectEvent

CAN_ID = 0x693


def dec() -> CollectDecoder:
    return CollectDecoder({CAN_ID})


# ── Single-frame Collect (fits in one CAN frame) ─────────────────────────────

def test_sf_length_code_b1():
    """Length code 0xB1 → 1-byte payload."""
    d = dec()
    # byte0=0x21  DID=0x0140(LE)  length_code=0xB1  payload=0xAB
    frame = bytes([0x21, 0x40, 0x01, 0xB1, 0xAB, 0x55, 0x55, 0x55])
    ev = d.feed(CAN_ID, frame, 1.0)
    assert isinstance(ev, CollectEvent)
    assert ev.did == 0x0140
    assert ev.data_length == 1
    assert ev.frame_type == "SF"
    assert ev.payload == bytes([0xAB])


def test_sf_length_code_b4():
    """Length code 0xB4 → 4-byte payload (fits in FF)."""
    d = dec()
    frame = bytes([0x21, 0x40, 0x01, 0xB4, 0x01, 0x02, 0x03, 0x04])
    ev = d.feed(CAN_ID, frame, 1.0)
    assert isinstance(ev, CollectEvent)
    assert ev.data_length == 4
    assert ev.frame_type == "SF"
    assert ev.payload == bytes([0x01, 0x02, 0x03, 0x04])


def test_sf_length_code_bf():
    """Length code 0xBF → 15-byte payload requires continuation."""
    d = dec()
    # 0xBF → 15 bytes; 4 bytes start in FF, 11 need CF
    frame = bytes([0x21, 0x40, 0x01, 0xBF, 0x01, 0x02, 0x03, 0x04])
    ev = d.feed(CAN_ID, frame, 1.0)
    assert ev is None  # MF, waiting for CFs
    assert d.ff_open(CAN_ID)


def test_mf_two_frames():
    """Multi-frame: 0xBF (15 bytes), one CF."""
    d = dec()
    ff = bytes([0x21, 0x40, 0x01, 0xBF, 0xA1, 0xA2, 0xA3, 0xA4])
    assert d.feed(CAN_ID, ff, 1.0) is None
    cf = bytes([0x22, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB])
    assert d.feed(CAN_ID, cf, 1.1) is None
    cf2 = bytes([0x23, 0xAC, 0xAD, 0xAE, 0xAF, 0x55, 0x55, 0x55])
    ev = d.feed(CAN_ID, cf2, 1.2)
    assert isinstance(ev, CollectEvent)
    assert ev.data_length == 15
    assert ev.frame_type == "MF"
    assert ev.payload[:4] == bytes([0xA1, 0xA2, 0xA3, 0xA4])


# ── Length code 0xB0 variants ─────────────────────────────────────────────────

def test_length_b0_normal():
    """0xB0, next byte != 0xC1 → length = next byte."""
    d = dec()
    # 0xB0, 0x10 (16 bytes): FF has bytes4..7 = 3 bytes, need 13 more
    ff = bytes([0x21, 0x40, 0x01, 0xB0, 0x10, 0xA1, 0xA2, 0xA3])
    ev = d.feed(CAN_ID, ff, 1.0)
    assert ev is None
    assert d.ff_open(CAN_ID)


def test_length_b0_c1_escape():
    """0xB0, 0xC1 escape → length = byte after 0xC1."""
    d = dec()
    # 0xB0 0xC1 0xB5 (181 bytes, as noted in CLAUDE.md for DID 0x03BA)
    ff = bytes([0x21, 0xBA, 0x03, 0xB0, 0xC1, 0xB5, 0xD1, 0xD2])
    ev = d.feed(CAN_ID, ff, 1.0)
    assert ev is None
    assert d.ff_open(CAN_ID)


# ── Sequence number wrapping ─────────────────────────────────────────────────

def test_sn_wrap_0x2f_to_0x20():
    """SN wraps from 0x2F back to 0x20."""
    d = dec()
    # 0xB0 0x62 = 98 bytes: FF has 3 bytes, need 95 more in 14 CFs (7 each = 98, -3 = 95)
    ff = bytes([0x21, 0x40, 0x01, 0xB0, 0x62, 0xD1, 0xD2, 0xD3])
    d.feed(CAN_ID, ff, 1.0)
    # CFs: sn 0x22..0x2F (14 CFs), then 0x20
    for sn in range(2, 16):
        actual_sn = 0x20 | (sn & 0x0F)
        d.feed(CAN_ID, bytes([actual_sn] + [sn] * 7), float(sn))


# ── Unknown CAN-ID ───────────────────────────────────────────────────────────

def test_sf_length_code_8x():
    """Length code 0x82 (0x8x family) → 2-byte payload, same as 0xB2."""
    d = dec()
    frame = bytes([0x21, 0x8C, 0x01, 0x82, 0xB8, 0x01, 0x55, 0x55])
    ev = d.feed(CAN_ID, frame, 1.0)
    assert isinstance(ev, CollectEvent)
    assert ev.did == 0x018C
    assert ev.data_length == 2
    assert ev.frame_type == "SF"
    assert ev.payload == bytes([0xB8, 0x01])


def test_unknown_can_id_ignored():
    d = dec()
    ev = d.feed(0x999, bytes([0x21, 0x40, 0x01, 0xB1, 0xAB, 0, 0, 0]), 1.0)
    assert ev is None


# ── Timestamp is taken from FF ───────────────────────────────────────────────

def test_timestamp_from_ff():
    d = dec()
    ff = bytes([0x21, 0x40, 0x01, 0xBF, 0xA1, 0xA2, 0xA3, 0xA4])
    d.feed(CAN_ID, ff, 42.5)
    cf1 = bytes([0x22, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB])
    d.feed(CAN_ID, cf1, 42.6)
    cf2 = bytes([0x23, 0xAC, 0xAD, 0xAE, 0xAF, 0x55, 0x55, 0x55])
    ev = d.feed(CAN_ID, cf2, 42.7)
    assert ev is not None
    assert ev.timestamp == 42.5
