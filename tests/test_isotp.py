"""Tests for the ISO-TP reassembler."""

import pytest
from e3candump.isotp import IsotpReassembler


def r() -> IsotpReassembler:
    return IsotpReassembler()


# ── Single Frame ─────────────────────────────────────────────────────────────

def test_sf_basic():
    asm = r()
    result = asm.feed(bytes([0x03, 0xAA, 0xBB, 0xCC]), 0.0)
    assert result == bytes([0xAA, 0xBB, 0xCC])


def test_sf_with_padding():
    asm = r()
    result = asm.feed(bytes([0x03, 0xAA, 0xBB, 0xCC, 0x55, 0x55, 0x55, 0x55]), 0.0)
    assert result == bytes([0xAA, 0xBB, 0xCC])


def test_sf_length_1():
    asm = r()
    result = asm.feed(bytes([0x01, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]), 0.0)
    assert result == bytes([0xFF])


def test_sf_resets_mf_state():
    asm = r()
    asm.feed(bytes([0x10, 0x0A, 0x77, 0x01, 0x02, 0x03, 0x04, 0x05]), 0.0)
    assert asm.in_progress
    result = asm.feed(bytes([0x04, 0xAA, 0xBB, 0xCC, 0xDD]), 0.0)
    # SF clears MF state
    assert result == bytes([0xAA, 0xBB, 0xCC, 0xDD])
    assert not asm.in_progress


# ── Multi Frame ──────────────────────────────────────────────────────────────

def test_mf_two_frames():
    asm = r()
    # FF: length=10, 6 payload bytes
    ff = bytes([0x10, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    assert asm.feed(ff, 0.0) is None
    assert asm.in_progress
    # CF1: 4 more bytes (total 10)
    cf1 = bytes([0x21, 0x07, 0x08, 0x09, 0x0A, 0x55, 0x55, 0x55])
    result = asm.feed(cf1, 0.1)
    assert result == bytes(range(1, 11))


def test_mf_three_frames():
    asm = r()
    ff = bytes([0x10, 0x0E, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    assert asm.feed(ff, 0.0) is None
    cf1 = bytes([0x21, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D])
    assert asm.feed(cf1, 0.1) is None
    cf2 = bytes([0x22, 0x0E, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55])
    result = asm.feed(cf2, 0.2)
    assert result == bytes(range(1, 15))


def test_mf_sn_wrap():
    """Sequence number wraps from 0x2F (sn=15) back to 0x20 (sn=0)."""
    asm = r()
    # FF (6 bytes) + 15 CFs (sn 1..15) + 1 wrap CF (sn 0) = 6 + 16*7 = 118 bytes
    total = 6 + 16 * 7
    ff = bytes([0x10, total & 0xFF] + list(range(1, 7)))
    assert asm.feed(ff, 0.0) is None
    for sn in range(1, 16):  # sn 1..15 (0x21..0x2F)
        cf = bytes([0x20 | sn] + [sn] * 7)
        assert asm.feed(cf, float(sn)) is None
    # sn wraps to 0 (0x20)
    cf_wrap = bytes([0x20] + [0xAA] * 7)
    result = asm.feed(cf_wrap, 16.0)
    assert result is not None
    assert len(result) == total


def test_mf_wrong_sn_resets():
    asm = r()
    ff = bytes([0x10, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    asm.feed(ff, 0.0)
    # Wrong SN: send 0x22 instead of 0x21
    result = asm.feed(bytes([0x22, 0x07, 0x08, 0x09, 0x0A, 0x55, 0x55, 0x55]), 0.1)
    assert result is None
    assert not asm.in_progress


def test_frame_type_property():
    asm = r()
    assert asm.frame_type == "SF"
    ff = bytes([0x10, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06])
    asm.feed(ff, 0.0)
    assert asm.frame_type == "MF"


def test_reset():
    asm = r()
    asm.feed(bytes([0x10, 0x0A, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06]), 0.0)
    assert asm.in_progress
    asm.reset()
    assert not asm.in_progress
