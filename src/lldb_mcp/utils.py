"""Utility functions for LLDB MCP server."""
from __future__ import annotations

import re


def parse_address(address: str) -> int:
    """Parse address string (hex or decimal) to integer.

    Accepts:
    - "0x1234" or "0X1234" - explicit hex
    - "1234abcd" (8+ hex chars) - assumed hex
    - "12345" - decimal

    Args:
        address: Address string to parse

    Returns:
        Integer address value

    Raises:
        ValueError: If address cannot be parsed
    """
    address = address.strip()
    if not address:
        raise ValueError("Empty address string")

    # Explicit hex prefix
    if address.startswith("0x") or address.startswith("0X"):
        return int(address, 16)

    # Looks like hex without prefix (8+ hex chars)
    if re.match(r"^[0-9a-fA-F]{8,}$", address):
        return int(address, 16)

    # Try decimal
    try:
        return int(address)
    except ValueError:
        pass

    # Try hex as fallback
    try:
        return int(address, 16)
    except ValueError:
        raise ValueError(f"Cannot parse address: {address}")


def format_address(addr: int) -> str:
    """Format integer address as hex string.

    Args:
        addr: Integer address

    Returns:
        Formatted address string like "0x0000000000001234"
    """
    return f"0x{addr:016x}"


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string.

    Args:
        data: Bytes to convert

    Returns:
        Hex string without prefix
    """
    return data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes.

    Args:
        hex_str: Hex string (with or without 0x prefix, spaces allowed)

    Returns:
        Bytes object

    Raises:
        ValueError: If hex string is invalid
    """
    # Remove common prefixes and separators
    hex_str = hex_str.replace(" ", "").replace("0x", "").replace("0X", "")
    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str
    return bytes.fromhex(hex_str)


def format_size(size: int) -> str:
    """Format byte size as human-readable string.

    Args:
        size: Size in bytes

    Returns:
        Human-readable size string
    """
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}" if size != int(size) else f"{int(size)} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
