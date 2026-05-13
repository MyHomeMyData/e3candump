# e3candump

A command-line tool for monitoring **Viessmann-specific E3 CAN-bus traffic** — one abstraction layer above `candump`.

While `candump` shows raw CAN frames, `e3candump` works at the protocol level: it reassembles multi-frame messages and outputs one decoded line per event for two Viessmann-specific protocols invisible to generic UDS tools:

- **Collect** — autonomous broadcast of data-point values (no request needed)
- **Service 77** — proprietary protocol for protected data points: client writes, device-initiated push notifications, and client reads

For standard UDS traffic on the same bus, see the sibling tool [udsdump](https://github.com/MyHomeMyData/udsdump).

The tool is entirely **passive** — it never writes to the CAN bus.

```
11:04:25.131  COLLECT      0x0693              DID=0x0140 (320)       len=9     MF
11:04:25.209  COLLECT      0x0693              DID=0x0141 (321)       len=2     SF
11:04:25.140  S77-WRITE    HPMUMASTER          DID=0x044D (1101)      CTR=0x7540   len=3     dt=2.0ms   SF/SF  ok
11:04:25.141  S77-WRITE    HPMUMASTER          DID=0x044D (1101)      CTR=0x7540   len=3     dt=1.8ms   SF/SF  ok
11:04:25.143  S77-PUSH     HPMUMASTER          DID=0x044D (1101)      len=3     SF
11:04:25.144  S77-PUSH     VCMU                DID=0x018C (396)       len=2     SF
11:04:25.150  S77-READ     VX3                 DID=0x0509 (1289)      CTR=0x3634   len=181   dt=3.2ms   MF/MF  ok
11:04:26.200  S77-WRITE    HPMUMASTER          DID=0x044D (1101)      CTR=0x7541   len=3     dt=5.0ms   SF/SF  timeout
```

## Features

- **One line per event** — Collect frames and Service 77 write/read/push/session events, each on a single line
- **Multi-frame reassembly** — handles Viessmann's Collect framing and standard ISO-TP (Service 77) transparently; `SF`/`MF` in the output shows the frame type
- **CAN-ID disambiguation** — shared IDs (e.g. `0x693` carries both Collect and S77 traffic) are resolved correctly using ISO-TP state. **Important:** configure `--s77-pair` for every CAN-ID that carries S77 traffic. Without it, S77-PUSH continuation frames (byte `0x21`) are structurally identical to Collect first frames and will be misidentified as Collect first frames, producing spurious Collect events.
- **Device names** — integrates with [open3e](https://github.com/open3e/open3e) `devices.json` to show device names instead of raw CAN-ID pairs
- **Configurable pairs** — S77 channel pairs can be loaded from `devices.json` and/or specified explicitly with `--s77-pair`
- **Output filters** — suppress Collect, S77-PUSH, S77-READ, or S77-WRITE events independently
- **Optional raw payload** — `--payload` appends the reassembled data bytes as hex
- **JSON output** — `--json` for machine-readable output, suitable for piping to `jq`

## Requirements

- Python 3.10+
- [python-can](https://python-can.readthedocs.io/) ≥ 4.3
- A CAN interface supported by python-can (SocketCAN, PEAK, Kvaser, virtual, …)

## Installation

Install directly from GitHub:

```bash
pip install git+https://github.com/MyHomeMyData/e3candump.git
```

For local development, clone the repository and install in editable mode:

```bash
git clone https://github.com/MyHomeMyData/e3candump.git
cd e3candump
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Quick Start

Monitor on `vcan0` with default settings (SocketCAN, Collect IDs `0x451` and `0x693`):

```bash
e3candump --channel vcan0
```

Monitor a real Vitocal 250 on `can0`, with open3e device names:

```bash
e3candump --channel can0 --devices
```

Explicit S77 pairs and Collect IDs:

```bash
e3candump --channel can0 --s77-pair 0x682:0x692 --s77-pair 0x683:0x693 --collect-id 0x451 --collect-id 0x693
```

JSON output, filtered with `jq`:

```bash
e3candump --channel can0 --devices --json | jq 'select(.type == "s77_write")'
```

Show only Service 77 write transactions:

```bash
e3candump --channel can0 --devices --no-collect --no-s77-push
```

## CLI Reference

```
e3candump [options]

CAN interface:
  --interface, -i INTERFACE   python-can interface name  (default: socketcan)
  --channel,   -c CHANNEL     CAN channel                (default: vcan0)

Collect configuration:
  --collect-id ID             CAN-ID for Collect broadcasts (hex).
                              May be repeated. Default: 0x451, 0x693

Service 77 configuration:
  --devices [FILE]            Load open3e devices.json to auto-configure S77
                              pairs and device names. Without a value, reads
                              'devices.json' in the current directory.
  --s77-pair REQ:RSP          S77 request:response CAN-ID pair (hex).
                              May be repeated. Additive to --devices.

Behaviour:
  --timeout, -t SECONDS       S77 write response timeout in seconds  (default: 1.0)

Output:
  --json                      One JSON object per line instead of text
  --payload                   Append raw payload bytes (hex) to each line
  --verbose, -v               Show S77 session frames (0x21/0x22 keepalives)
  --no-collect                Suppress Collect event output
  --no-s77-push               Suppress S77-PUSH event output
  --no-s77-read               Suppress S77-READ event output
  --no-s77-write              Suppress S77 write/confirm event output
```

## Output Format

### Text (default)

**Collect event:**
```
HH:MM:SS.mmm  COLLECT   CAN_ID              DID=0xNNNN (DDD)       len=N     FT
```

**Service 77 write/confirm:**
```
HH:MM:SS.mmm  S77-WRITE DEVICE_or_IDs       DID=0xNNNN (DDD)       CTR=0xNNNN   len=N     dt=N.Nms   FT  status
```

**Service 77 read/confirm:**
```
HH:MM:SS.mmm  S77-READ  DEVICE_or_IDs       DID=0xNNNN (DDD)       CTR=0xNNNN   len=N     dt=N.Nms   FT  status
```

**Service 77 device push (CTR is always 0x0000 — omitted):**
```
HH:MM:SS.mmm  S77-PUSH  DEVICE_or_IDs       DID=0xNNNN (DDD)       len=N     FT
```

| Field | Description |
|---|---|
| `HH:MM:SS.mmm` | Timestamp |
| `COLLECT` / `S77-WRITE` / `S77-READ` / `S77-PUSH` | Event type |
| `CAN_ID` / `DEVICE_or_IDs` | CAN-ID for Collect; device name or `REQ→RSP` hex pair for S77 |
| `DID=0x… (DDD)` | Data Identifier in hex and decimal |
| `CTR=0x…` | Session counter (S77 write and read) |
| `len=N` | Reassembled payload length in bytes |
| `dt=N.Nms` | Round-trip latency (S77 write and read); absent on timeout |
| `FT` | Frame type: `SF` (single) or `MF` (multi); `REQ/RSP` for S77 showing both directions |
| `status` | `ok` or `timeout` (S77 write and read) |

With `--payload`, the reassembled data bytes are appended as hex: `data=de ad be ef`.

With `--verbose`, S77 session keepalive frames are also shown as `S77-SESSION` lines.

### JSON

Each event is a JSON object on a single line. Only non-empty fields are included.

Collect:
```json
{"timestamp": 1746789865.131, "type": "collect", "can_id": 1683, "did": 320, "data_length": 9, "frame_type": "MF"}
```

S77 write:
```json
{"timestamp": 1746789865.140, "type": "s77_write", "request_id": 1666, "response_id": 1682, "session_ctr": 29952, "status": "ok", "device": "HPMUMASTER", "did": 1101, "data_length": 3, "req_frame_type": "SF", "rsp_frame_type": "SF", "duration_ms": 2.0}
```

S77 read:
```json
{"timestamp": 1746789865.150, "type": "s77_read", "request_id": 1089, "response_id": 1105, "session_ctr": 13876, "status": "ok", "did": 1289, "data_length": 181, "req_frame_type": "MF", "rsp_frame_type": "MF", "duration_ms": 3.2}
```

S77 push:
```json
{"timestamp": 1746789865.143, "type": "s77_push", "request_id": 1666, "response_id": 1682, "session_ctr": 0, "status": "push", "device": "HPMUMASTER", "did": 1101, "data_length": 3, "rsp_frame_type": "SF"}
```

## Integration with open3e

[open3e](https://github.com/open3e/open3e) and [ioBroker.e3oncan](https://github.com/MyHomeMyData/ioBroker.e3oncan) use a `devices.json` file that maps device names to their UDS addresses. `e3candump` can read this file to auto-configure S77 channel pairs and display human-readable device names:

```bash
e3candump --channel can0 --devices /path/to/devices.json
```

The S77 channel pair for each device is derived from the `tx` field:
- Request channel: `tx + 0x02`
- Response channel: `tx + 0x12`

The device name is taken from the `prop` field. Pairs configured via `--devices` and `--s77-pair` are combined — `--s77-pair` can add pairs not present in `devices.json`.

When `--devices` is used, a status line is printed to stderr on startup:
```
e3candump: devices: loaded 5 device(s) from devices.json
```

## Related Projects

- [udsdump](https://github.com/MyHomeMyData/udsdump) — sibling tool for standard UDS traffic on CAN
- [open3e](https://github.com/open3e/open3e) — Viessmann E3 data-point library
- [ioBroker.e3oncan](https://github.com/MyHomeMyData/ioBroker.e3oncan) — ioBroker adapter for Viessmann E3 heat pumps
- [E3onCANserver](https://github.com/MyHomeMyData/E3onCANserver) — Viessmann E3 simulator for offline testing

## Development

```bash
# Install with dev dependencies
pip install -e .
pip install pytest

# Run tests
pytest
```

54 tests cover the Collect decoder, the Service 77 decoder, the ISO-TP reassembler, the output formatter, and the device name loader — no CAN hardware required.

## Changelog

### 0.1.1 — 2026-05-13

- Service 77 read decoder: client read request (`41 01 82` marker) matched to device response (`42 01 82`), with timeout detection
- `--no-s77-read` output filter
- Fix: short S77 pushes where the data byte has high nibble < `0x8` no longer cause a crash or missing payload
- 54 tests

### 0.1.0 — 2026-05-12

- Initial release
- Collect decoder: SF and MF reassembly, Viessmann-specific length encoding including `0xC1` escape and `0x8x`/`0xBx` variants
- Service 77 decoder: client write with timeout detection, device-initiated push (CTR=0x0000), session keepalive frames (`--verbose`)
- CAN-ID disambiguation for shared IDs (e.g. `0x693` carries both Collect and S77)
- `--devices` to auto-configure S77 pairs and device names from open3e `devices.json`
- `--s77-pair` for explicit S77 channel pairs
- `--collect-id` for configurable Collect CAN-IDs
- `--no-collect`, `--no-s77-push`, `--no-s77-write` output filters
- JSON output (`--json`), raw payload option (`--payload`)
- 50 tests

## License

MIT License

Copyright (c) 2026 MyHomeMyData <juergen.bonfert@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
