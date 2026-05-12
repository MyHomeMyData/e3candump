"""Command-line interface for e3candump."""

from __future__ import annotations

import argparse
import sys

import can

from e3candump import __version__
from e3candump.devices import load_devices
from e3candump.formatter import format_event
from e3candump.monitor import DEFAULT_COLLECT_IDS, monitor


def _parse_hex(value: str) -> int:
    try:
        return int(value, 16)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid hex value: {value!r}")


def _parse_pair(value: str) -> tuple[int, int]:
    parts = value.split(":")
    if len(parts) != 2:
        raise argparse.ArgumentTypeError(
            f"invalid pair {value!r}: expected REQ:RSP in hex (e.g. 0x682:0x692)"
        )
    try:
        return int(parts[0], 16), int(parts[1], 16)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"invalid pair {value!r}: both values must be hex integers"
        )


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="e3candump",
        description=(
            "Viessmann E3 CAN-bus monitor — decodes Collect and Service 77 "
            "protocol traffic, one line per event."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  e3candump --channel can0
  e3candump --channel vcan0 --interface virtual
  e3candump --channel can0 --s77-pair 0x682:0x692 --s77-pair 0x683:0x693
  e3candump --channel can0 --collect-id 0x451 --collect-id 0x693
  e3candump --channel can0 --json | jq 'select(.type == "s77_write")'
""",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    iface = p.add_argument_group("CAN interface")
    iface.add_argument(
        "--interface", "-i",
        default="socketcan",
        metavar="INTERFACE",
        help="python-can interface name (default: socketcan)",
    )
    iface.add_argument(
        "--channel", "-c",
        default="vcan0",
        metavar="CHANNEL",
        help="CAN channel (default: vcan0)",
    )

    collect = p.add_argument_group("Collect configuration")
    collect.add_argument(
        "--collect-id",
        action="append",
        dest="collect_ids",
        type=_parse_hex,
        metavar="ID",
        help=(
            "CAN-ID for Collect broadcasts (hex). "
            f"May be repeated. Default: {', '.join(hex(i) for i in DEFAULT_COLLECT_IDS)}"
        ),
    )

    s77 = p.add_argument_group("Service 77 configuration")
    s77.add_argument(
        "--devices",
        default="devices.json",
        metavar="FILE",
        help=(
            "open3e devices.json to auto-configure S77 pairs and device names "
            "(default: devices.json in current directory; silently ignored if absent)"
        ),
    )
    s77.add_argument(
        "--s77-pair",
        action="append",
        dest="s77_pairs",
        type=_parse_pair,
        metavar="REQ:RSP",
        help=(
            "S77 request:response CAN-ID pair (hex). "
            "May be repeated (e.g. --s77-pair 0x682:0x692)."
        ),
    )

    behaviour = p.add_argument_group("Behaviour")
    behaviour.add_argument(
        "--timeout", "-t",
        type=float,
        default=1.0,
        metavar="SECONDS",
        help="S77 write response timeout in seconds (default: 1.0)",
    )

    output = p.add_argument_group("Output")
    output.add_argument(
        "--json",
        action="store_true",
        help="one JSON object per line instead of text",
    )
    output.add_argument(
        "--payload",
        action="store_true",
        help="append raw payload bytes (hex) to each line",
    )
    output.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="show S77 session frames (0x21/0x22 keepalives)",
    )
    output.add_argument(
        "--no-collect",
        action="store_true",
        dest="no_collect",
        help="suppress Collect event output",
    )
    output.add_argument(
        "--no-s77-push",
        action="store_true",
        dest="no_s77_push",
        help="suppress S77-PUSH event output",
    )
    output.add_argument(
        "--no-s77-write",
        action="store_true",
        dest="no_s77_write",
        help="suppress S77 write/confirm event output",
    )

    return p


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)

    collect_ids = tuple(args.collect_ids) if args.collect_ids else DEFAULT_COLLECT_IDS

    device_names = load_devices(args.devices)
    # Merge: device pairs first, then explicit --s77-pair (additive, no dedup needed)
    s77_pairs: list[tuple[int, int]] = list(device_names) + (args.s77_pairs or [])

    try:
        for event in monitor(
            interface=args.interface,
            channel=args.channel,
            collect_ids=collect_ids,
            s77_pairs=s77_pairs,
            timeout=args.timeout,
        ):
            line = format_event(
                event,
                use_json=args.json,
                payload=args.payload,
                verbose=args.verbose,
                no_collect=args.no_collect,
                no_s77_push=args.no_s77_push,
                no_s77_write=args.no_s77_write,
                device_names=device_names,
            )
            if line is not None:
                print(line, flush=True)
    except KeyboardInterrupt:
        pass
    except can.CanError as exc:
        print(f"e3candump: CAN error: {exc}", file=sys.stderr)
        sys.exit(1)
