"""Tests for utility functions."""
import pytest

from lldb_mcp.utils import (
    parse_address,
    format_address,
    bytes_to_hex,
    hex_to_bytes,
    format_size,
)


class TestParseAddress:
    """Tests for parse_address function."""

    def test_hex_with_prefix(self):
        assert parse_address("0x1234") == 0x1234
        assert parse_address("0X1234") == 0x1234
        assert parse_address("0xDEADBEEF") == 0xDEADBEEF

    def test_hex_without_prefix(self):
        # 8+ hex chars assumed to be hex
        assert parse_address("12345678") == 0x12345678
        assert parse_address("deadbeef") == 0xDEADBEEF
        assert parse_address("00007fff12345678") == 0x00007FFF12345678

    def test_decimal(self):
        assert parse_address("12345") == 12345
        assert parse_address("0") == 0
        assert parse_address("999") == 999

    def test_with_whitespace(self):
        assert parse_address("  0x1234  ") == 0x1234
        assert parse_address("\t12345\n") == 12345

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            parse_address("")
        with pytest.raises(ValueError):
            parse_address("   ")

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            parse_address("not_an_address")


class TestFormatAddress:
    """Tests for format_address function."""

    def test_format_basic(self):
        assert format_address(0) == "0x0000000000000000"
        assert format_address(0x1234) == "0x0000000000001234"
        assert format_address(0xDEADBEEF) == "0x00000000deadbeef"

    def test_format_large(self):
        assert format_address(0x7FFF12345678) == "0x00007fff12345678"
        assert format_address(0xFFFFFFFFFFFFFFFF) == "0xffffffffffffffff"


class TestBytesHex:
    """Tests for bytes/hex conversion functions."""

    def test_bytes_to_hex(self):
        assert bytes_to_hex(b"") == ""
        assert bytes_to_hex(b"\x00") == "00"
        assert bytes_to_hex(b"\xde\xad\xbe\xef") == "deadbeef"
        assert bytes_to_hex(b"hello") == "68656c6c6f"

    def test_hex_to_bytes(self):
        assert hex_to_bytes("") == b""
        assert hex_to_bytes("00") == b"\x00"
        assert hex_to_bytes("deadbeef") == b"\xde\xad\xbe\xef"
        assert hex_to_bytes("DEADBEEF") == b"\xde\xad\xbe\xef"

    def test_hex_to_bytes_with_prefix(self):
        assert hex_to_bytes("0xdeadbeef") == b"\xde\xad\xbe\xef"
        assert hex_to_bytes("0XDEADBEEF") == b"\xde\xad\xbe\xef"

    def test_hex_to_bytes_with_spaces(self):
        assert hex_to_bytes("de ad be ef") == b"\xde\xad\xbe\xef"

    def test_hex_to_bytes_odd_length(self):
        # Should pad with leading zero
        assert hex_to_bytes("f") == b"\x0f"
        assert hex_to_bytes("abc") == b"\x0a\xbc"

    def test_roundtrip(self):
        original = b"\x00\x01\x02\xfe\xff"
        assert hex_to_bytes(bytes_to_hex(original)) == original


class TestFormatSize:
    """Tests for format_size function."""

    def test_bytes(self):
        assert format_size(0) == "0 B"
        assert format_size(512) == "512 B"
        assert format_size(1023) == "1023 B"

    def test_kilobytes(self):
        assert format_size(1024) == "1 KB"
        assert format_size(2048) == "2 KB"

    def test_megabytes(self):
        assert format_size(1024 * 1024) == "1 MB"
        assert format_size(5 * 1024 * 1024) == "5 MB"

    def test_gigabytes(self):
        assert format_size(1024 * 1024 * 1024) == "1 GB"
