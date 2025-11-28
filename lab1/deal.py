from typing import List
from Interfaces import KeySchedule, SymmetricBlockCipher, RoundFunction
from des import DES
from Feistel_network import FeistelNetwork

FIXED_KEY = bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF])

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

class DEALKeySchedule(KeySchedule):
    def __init__(self, rounds: int):
        self.rounds = rounds

    def round_keys(self, master_key: bytes) -> List[bytes]:
        if len(master_key) not in (16, 24, 32):
            raise ValueError("Key must be 16, 24 or 32 bytes")

        key_blocks = [master_key[i:i + 8] for i in range(0, len(master_key), 8)]
        s = len(key_blocks)

        keygen_des = DES()
        keygen_des.configure(FIXED_KEY)
        round_keys: List[bytes] = []
        prev_rk = bytes(8)

        for i in range(self.rounds):
            k_part = key_blocks[i % s]

            inp = _xor_bytes(k_part, prev_rk)

            if i >= s:
                val = 1 << (i - s)
                h = val.to_bytes(8, 'big')
                inp = _xor_bytes(inp, h)

            rk = keygen_des.encrypt_block(inp)
            round_keys.append(rk)
            prev_rk = rk
        return round_keys

class DEALFRound(RoundFunction):
    def __init__(self):
        self._des_cache: dict[bytes, DES] = {}

    def _get_des(self, round_key: bytes) -> DES:
        d = self._des_cache.get(round_key)
        if d is None:
            d = DES()
            d.configure(round_key)
            self._des_cache[round_key] = d
        return d

    def F(self, right_half: bytes, round_key: bytes) -> bytes:
        if len(right_half) != 8:
            raise ValueError(f"DEAL round function expects 8 bytes, got {len(right_half)}")

        des = self._get_des(round_key)
        return des.encrypt_block(right_half)

class DEAL(SymmetricBlockCipher):
    def __init__(self, rounds: int = 6, block_size: int = 16):
        if block_size != 16:
            raise ValueError("DEAL block_size must be 16 (128 bits)")
        self.block_size = block_size
        half = block_size // 2
        self._ks = DEALKeySchedule(rounds)
        self._rf = DEALFRound()
        self._feistel = FeistelNetwork(half_size=half, rounds=rounds, ks=self._ks, rf=self._rf)

    def configure(self, key: bytes) -> None:
        if len(key) not in (16, 24, 32):
            raise ValueError(f"DEAL key must be 16, 24 or 32 bytes")
        self._feistel.configure(key)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError(f"DEAL block is {self.block_size} bytes")
        return self._feistel.encrypt_block(block)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError(f"DEAL block is {self.block_size} bytes")
        return self._feistel.decrypt_block(block)