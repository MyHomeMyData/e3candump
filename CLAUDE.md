# e3candump — Project Briefing for Claude Code

## What this project is

`e3candump` is a passive CAN-bus monitor for Viessmann E3-series heat pumps.
It decodes two Viessmann-specific protocols that are invisible to generic UDS
tools:

1. **Collect** — autonomous broadcast of data-point values (no request needed)
2. **Service 77** — proprietary write protocol for protected data points,
   including device-initiated push notifications

Output: one decoded line per event on stdout, similar to `candump` but one
layer higher. The tool never writes to the bus.

## Why it is a separate project

The companion tool `udsdump` (github.com/MyHomeMyData/udsdump) handles generic
UDS-on-CAN traffic. `e3candump` is intentionally separate because:

- Viessmann's protocols are not standard UDS — they need custom decoders
- The CAN-ID space is different (Collect/S77 channels, not UDS pairs)
- The intended audience overlaps with open3e / ioBroker.e3oncan users
- Keeping the tools separate avoids contaminating udsdump with proprietary logic

## Naming

`e3candump` — in the tradition of `candump` / `udsdump`. "e3" refers to the
Viessmann E3 series; "can" keeps the door open for a future DoIP extension.

## Related projects

- [udsdump](https://github.com/MyHomeMyData/udsdump) — sibling tool for UDS
- [E3onCANserver](https://github.com/MyHomeMyData/E3onCANserver) — E3 simulator
- [ioBroker.e3oncan](https://github.com/MyHomeMyData/ioBroker.e3oncan) — the
  ioBroker adapter that motivated this tooling

---

## Protocol reference

Full protocol documentation lives in `protocols.md` (to be copied into this
repo as `docs/protocols.md`). Key facts for implementation:

### Collect protocol

Viessmann E3 devices broadcast data-point values autonomously whenever a value
changes. No request is needed; no flow control is used.

**CAN-IDs (known):**

| Device | CAN-ID |
|---|---|
| Vitocharge VX3 | `0x451` |
| Vitocal 250 | `0x693` |

**Frame format** — every CAN frame is 8 bytes:

```
First Frame (FF):   byte 0 = 0x21 | bytes 1–2 = DID (LE) | byte 3 = length code | bytes 4+ = payload start
Continuation (CF):  byte 0 = 0x22, 0x23, … (wraps 0x2F → 0x20) | bytes 1–7 = payload
```

**Length code** (byte 3 of FF):

| Value | Meaning | Payload length | Payload start |
|---|---|---|---|
| `0xB1`–`0xBF` | Single or Multi Frame | `value − 0xB0` bytes | byte 4 |
| `0xB0`, next ≠ `0xC1` | Multi Frame | next byte (16–255) | byte 5 |
| `0xB0`, next = `0xC1` | Multi Frame | byte after `0xC1` | byte 6 |

The `0xC1` escape is used when the length byte would itself be `0xB5` or `0xC1`
(observed in the wild for DID `0x03BA`, 181-byte payload).

No flow control — device sends all frames back-to-back. Last frame is padded
to 8 bytes (pad byte `0x55`).

### Service 77 protocol

Viessmann-proprietary write protocol for data points protected against normal
UDS `WriteDataByIdentifier` (0x2E). Uses standard ISO-TP (ISO 15765-2) framing.

**CAN-ID mapping** (derived from device UDS tx address):

| | CAN-ID |
|---|---|
| S77 request channel  | `device_tx + 0x02` |
| S77 response channel | `device_tx + 0x12` |

Example for main device at `0x680`: request = `0x682`, response = `0x692`.

**Reassembled request payload:**

```
Byte 0:     0x77                     Service ID
Bytes 1–2:  [CTR_L] [CTR_H]         Session counter, 16-bit LE, monotonically
                                      increasing; wraps at 0xFFFF
Bytes 3–5:  0x43 0x01 0x82          Fixed client identifier (constant)
Bytes 6–7:  [DID_L] [DID_H]         Data identifier, little-endian
Byte 8:     0xB0 + n  or  0xB0 ...  Length code (same encoding as Collect FF)
Bytes 9+:   [DATA ...]               New value, little-endian
```

**Positive response (4 bytes):**

```
[0x77] [CTR_L] [CTR_H] [0x44]
```

The response echoes the **session counter** (not the DID). Confirmation byte
is always `0x44`.

**Device-initiated push (CTR = 0x0000):**

After a client write, the device can push Service 77 frames back to the client
(and to sibling devices) with `CTR = 0x0000`. Two patterns:

- **Pattern A (sync echo):** same DID + same data propagated to all client
  channels simultaneously (e.g. 0x692→0x682 and 0x693→0x683 with identical
  payload).
- **Pattern B (notification):** a set of related DIDs with updated values,
  pushed before the `0x44` confirmation is sent.

**4-byte session frames (meaning TBD):**

```
[0x77] [CTR_L] [CTR_H] [0x21]   client → device
[0x77] [CTR_L] [CTR_H] [0x22]   device → client  (1 ms later)
```

CTR = previous write CTR + 1. Appear between write batches on all active
channels. Possibly a session keepalive or commit signal. Byte 3 ≠ `0x44`.

### CAN-ID sharing and disambiguation

`0x451` and `0x693` carry **both** Collect and Service 77 traffic. A frame
with byte 0 = `0x21` is ambiguous without state:

- **Collect FF** — no ISO-TP FF is open for this CAN-ID
- **Service 77 CF1** — an ISO-TP FF (`0x1x`) was received from this CAN-ID
  and not yet consumed by a CF1

Implementation: maintain a boolean "FF open" flag per CAN-ID.

**Operational mode note:** In practice, the two protocols are functionally
exclusive by mode:
- Normal operation (passive): Collect dominates
- Active service session (writes): Service 77 device pushes dominate

---

## Architecture

### Design principle: closed for modification, open for extension

v1.0 handles only Viessmann-specific protocols. The architecture is
deliberately designed so that standard UDS can be added later as a drop-in
decoder — **without touching the existing decoders or the core pipeline**.

### Layers

```
┌──────────────────────────────────────────────────────┐
│  CLI / output formatter                               │  thin, replaceable
├──────────────────────────────────────────────────────┤
│  Protocol decoder registry                           │
│    v1.0:   CollectDecoder, Service77Decoder          │
│    later:  + UDSDecoder  (drop-in, no changes above) │
├──────────────────────────────────────────────────────┤
│  ISO-TP reassembler  (shared, per CAN-ID-pair)       │  reused by S77 and UDS
├──────────────────────────────────────────────────────┤
│  CAN capture                                         │  python-can, interface-agnostic
└──────────────────────────────────────────────────────┘
```

### Decoder interface

```python
class ProtocolDecoder(ABC):
    def can_handle(self, can_id: int) -> bool: ...
    def feed(self, can_id: int, data: bytes, timestamp: float) -> list[Event]: ...
```

`feed()` returns a (possibly empty) list of decoded events. The registry
iterates all registered decoders for each incoming frame; the first decoder
that claims the frame wins (first-match). Order matters: register Collect and
Service77 before UDS so they get priority on shared CAN-IDs.

### ISO-TP reassembler as a shared layer

Both Service 77 and UDS use ISO-TP framing. The ISO-TP reassembler should be
a **standalone, reusable component** — not embedded inside a specific decoder.
Decoders receive already-reassembled payloads and inspect only the service-
level bytes. This avoids duplicating ISO-TP logic when UDS is added later.

```python
class IsotpReassembler:
    """One instance per (request_id, response_id) pair."""
    def feed(self, can_id: int, data: bytes, timestamp: float
             ) -> bytes | None:  # returns complete payload or None
        ...
```

### Extension path for standard UDS (post-v1.0)

Adding UDS requires:
1. Register a `UDSDecoder` in the decoder registry — no other changes.
2. `UDSDecoder` reuses the existing `IsotpReassembler`.
3. UDS CAN-ID pairs are passed via a new `--uds-pair` CLI argument (same
   pattern as `--s77-pair`).
4. The output formatter already emits generic `Event` objects — UDS events
   just add a new subclass (`UDSTransaction`).

Alternative: depend on `udsdump` as a library and import its `UDSDecoder`
directly. This avoids duplicating UDS logic but couples the projects.
Decide when the time comes; the decoder interface makes either option viable.

## Data model

```python
@dataclass
class CollectFrame:
    timestamp:   float
    can_id:      int
    did:         int
    data_length: int
    # payload bytes deliberately not stored

@dataclass
class Service77Transaction:
    timestamp:    float
    request_id:   int
    response_id:  int
    direction:    str        # "client_write" | "device_push" | "device_sync"
    session_ctr:  int        # 0x0000 for device-initiated
    did:          int
    data_length:  int
    confirmed:    bool       # True when 0x44 response received
    duration_ms:  float | None
```

## CLI output format (proposed)

```
11:04:25.131  COLLECT  0x693  DID=0x0140 (320)   len=9   MF
11:04:25.140  S77-REQ  0x682→0x692  DID=0x044D (1101)  len=3   CTR=0x7540
11:04:25.142  S77-RSP  0x682→0x692  DID=0x044D (1101)  confirmed  dt=2ms
11:04:25.143  S77-SYN  0x692→0x682  DID=0x044D (1101)  len=3   CTR=0x0000
```

Optional `--json` flag for machine-readable output.

## Suggested v1.0 scope

- [ ] Collect decoder: SF and MF reassembly, all length-code variants incl.
      `0xC1` escape
- [ ] Service 77 decoder: client write, positive response (0x44 confirmation),
      device-initiated push (CTR=0), 4-byte session frames (log as unknown)
- [ ] CAN-ID sharing / disambiguation (ISO-TP state flag per CAN-ID)
- [ ] CLI with `--channel`, `--interface`, `--json`
- [ ] Configurable Collect CAN-IDs (`--collect-id`)
- [ ] Configurable S77 channel pairs (`--s77-pair`)
- [ ] Text output + JSON output
- [ ] pytest suite with replay from raw bytes (no hardware needed)

## Out of scope for v1.0

- Standard UDS services (0x22, 0x2E, 0x10, …) — architecture leaves room
  via decoder registry; see "Extension path" above
- Payload decoding (data-point values)
- DoIP transport
- Config file (CLI flags are sufficient)
- DID name lookup (keep it a low-level tool)

## Dependencies

- `python-can` ≥ 4.3
- Python ≥ 3.10

No dependency on udsdump, E3onCANserver, or ioBroker.

## Known CAN-IDs in a typical Viessmann E3 installation

From captured traces (Vitocal 250 + Vitocharge VX3):

| CAN-ID | Role |
|---|---|
| `0x451` | Collect broadcast (VX3) + S77 response for `0x441` |
| `0x693` | Collect broadcast (Vitocal) + S77 response for `0x683` |
| `0x692` | S77 response for `0x682` (main device) |
| `0x695` | S77 response for `0x685` |
| `0x696` | S77 response for `0x686` |
| `0x691` | S77 response for `0x681` |

S77 device pushes observed simultaneously on up to 4 channels (0x692 + 0x693
+ 0x695 + 0x696) with identical DID + data.
