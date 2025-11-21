from typing import List
from Interfaces import KeySchedule, SymmetricBlockCipher, RoundFunction
from des import DES
from Feistel_network import FeistelNetwork

class DEALKeySchedule(KeySchedule):
    def __init__(self, rounds: int):
        self.rounds = rounds

    def round_keys(self, master_key: bytes) -> List[bytes]:
        if len(master_key) == 0:
            raise ValueError("master key can't be empty")
        seed = int.from_bytes(master_key, 'big')
        if seed == 0:
            seed = 0x9E3779B97F4A7C15
        a = 6364136223846793005
        c = 1442695040888963407
        keys: List[bytes] = []
        for i in range(self.rounds):
            seed = (a * seed + c) & ((1 << 64) - 1)
            keys.append(seed.to_bytes(8, 'big'))
        return keys

class DEALFRound(RoundFunction):

    def __init__(self, half_size: int):
        self.half_size = half_size
        # кэш готовых объектов DES на ключ K, чтобы не дергать configure каждый раз
        self._des_cache: dict[bytes, DES] = {}

    def _get_des(self, round_key: bytes) -> DES:
        d = self._des_cache.get(round_key)
        if d is None:
            d = DES()
            d.configure(round_key)
            self._des_cache[round_key] = d
        return d

    def F(self, right_half: bytes, round_key: bytes) -> bytes:
        if len(right_half) != self.half_size:
            raise ValueError("DEAL right half must equal Feistel half_size")

        des = self._get_des(round_key)

        out_parts = []
        r = right_half
        for i in range(0, len(r), 8):
            chunk = r[i:i+8]
            if len(chunk) < 8:
                chunk = chunk + b"\x00" * (8 - len(chunk))
            c = des.encrypt_block(chunk)  # DES_K(Ri_pad)
            take = min(8, len(r) - i)
            out_parts.append(c[:take])

        return b"".join(out_parts)

class DEAL(SymmetricBlockCipher):
    """
    DEAL: блочный шифр на сети Фейстеля, где F(R, K) строится из DES_K над 8-байтовыми
    фрагментами R. Поддерживает block_size 16.
    Ключ: 16/24/32 (128/192/256 бит).
    """
    def __init__(self, rounds: int = 6, block_size: int = 16):
        if block_size != 16:
            raise ValueError("DEAL block_size must be 16 (128 bits)")
        self.block_size = block_size
        half = block_size // 2
        self._ks = DEALKeySchedule(rounds)
        self._rf = DEALFRound(half_size=half)
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
