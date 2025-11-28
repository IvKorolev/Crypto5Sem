from __future__ import annotations
from typing import Iterable, List

def _get_bit(byte_seq: bytes, bit_index: int, lsb_first: bool) -> int:
    """Возвращает 0/1 для бита с глобальным индексом bit_index.
    Если lsb_first=True, то в каждом байте бит 0 — младший (LSB), 7 — старший.
    Если False — наоборот."""
    byte_i, bit_in_byte = divmod(bit_index, 8)
    b = byte_seq[byte_i]
    if lsb_first:
        mask = 1 << bit_in_byte
    else:
        mask = 1 << (7 - bit_in_byte)
    return 1 if (b & mask) else 0

def _set_bit(bits: bytearray, bit_index: int, value: int, lsb_first: bool) -> None:
    byte_i, bit_in_byte = divmod(bit_index, 8)
    if lsb_first:
        mask = 1 << bit_in_byte
    else:
        mask = 1 << (7 - bit_in_byte)
    if value:
        bits[byte_i] |= mask
    else:
        bits[byte_i] &= (~mask) & 0xFF

def permute_bits(data: bytes, pblock: Iterable[int], lsb_first: bool = False, start_index0: bool = True) -> bytes:
    total_bits = len(list(pblock))
    src_bits = len(data) * 8
    out = bytearray((total_bits + 7) // 8)
    for out_i, src_pos in enumerate(pblock):
        src_bit = src_pos - (0 if start_index0 else 1)
        if src_bit < 0 or src_bit >= src_bits:
            raise ValueError("pblock index out of range")
        val = _get_bit(data, src_bit, lsb_first)
        _set_bit(out, out_i, val, lsb_first)
    return bytes(out)