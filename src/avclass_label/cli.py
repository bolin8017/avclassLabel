"""Command-line interface for avclass_label."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence

from avclass_label.config import Config
from avclass_label.labeler import Labeler


def build_parser() -> argparse.ArgumentParser:
    """Construct and return the argument parser."""
    parser = argparse.ArgumentParser(
        prog="avclass-label",
        description="Classify malware families from VirusTotal JSON reports using AVClass.",
    )
    parser.add_argument(
        "--input_folder",
        "-i",
        required=True,
        help="Directory containing VirusTotal JSON report files.",
    )
    parser.add_argument(
        "--max-workers",
        "-w",
        type=int,
        default=None,
        help="Maximum number of threads for parallel labeling (default: min(32, CPU count + 4)).",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Enable debug logging.",
    )
    return parser


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    return build_parser().parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    """Parse arguments, build config, and run the labeler."""
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    try:
        config = Config(
            input_dir=args.input_folder,
            max_workers=args.max_workers,
        )
    except ValueError as exc:
        logging.getLogger(__name__).error("%s", exc)
        sys.exit(1)

    labeler = Labeler(config)
    labeler.run()
