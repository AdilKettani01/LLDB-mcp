from __future__ import annotations

import argparse
import asyncio

from .server import run_stdio


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="LLDB MCP server")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    return parser.parse_args(argv)


def main() -> None:
    args = parse_args()
    asyncio.run(run_stdio(log_level=args.log_level))


if __name__ == "__main__":
    main()
