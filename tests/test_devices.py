"""Tests for devices.json loading."""

import json
import pytest
from pathlib import Path
from e3candump.devices import load_devices


def test_load_devices(tmp_path):
    data = {
        "0x680": {"tx": "0x680", "prop": "HPMUMASTER"},
        "0x684": {"tx": "0x684", "prop": "HMI"},
    }
    f = tmp_path / "devices.json"
    f.write_text(json.dumps(data))

    names = load_devices(str(f))
    assert names[(0x682, 0x692)] == "HPMUMASTER"
    assert names[(0x686, 0x696)] == "HMI"


def test_load_devices_missing_file(tmp_path):
    names = load_devices(str(tmp_path / "nonexistent.json"))
    assert names == {}


def test_load_devices_lowercase_hex(tmp_path):
    data = {"0x68c": {"tx": "0x68c", "prop": "VCMU"}}
    f = tmp_path / "devices.json"
    f.write_text(json.dumps(data))

    names = load_devices(str(f))
    assert names[(0x68E, 0x69E)] == "VCMU"


def test_load_devices_missing_prop_uses_hex(tmp_path):
    data = {"0x680": {"tx": "0x680"}}
    f = tmp_path / "devices.json"
    f.write_text(json.dumps(data))

    names = load_devices(str(f))
    assert (0x682, 0x692) in names


def test_load_devices_invalid_json(tmp_path):
    f = tmp_path / "devices.json"
    f.write_text("not valid json")
    names = load_devices(str(f))
    assert names == {}
