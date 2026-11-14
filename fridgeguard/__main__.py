"""Command-line entry point: ``python -m fridgeguard``."""

import argparse
import sys

from fridgeguard import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="fridgeguard",
        description="Smart-FridgeGuard security monitoring lab",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("check-env", help="verify that the development environment is ready")

    args = parser.parse_args(argv)
    if args.command == "check-env":
        from fridgeguard.envcheck import run_checks

        return run_checks()
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
