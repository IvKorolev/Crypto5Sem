from typing import List
from Interfaces import SymmetricBlockCipher, KeySchedule, RoundFunction

class FeistelNetwork(SymmetricBlockCipher):
    """
    Общая сеть Фейстеля с заданными интерфейсами KeySchedule и RoundFunction.
    Блок: 2 * half_size (в байтах). Полублоки трактуются как bytes.
    """
    def __init__(self, *, half_size: int, rounds: int, ks: KeySchedule, rf: RoundFunction):
        self.half_size = half_size
        self.rounds = rounds
        self.ks = ks
        self.rf = rf
        self.block_size = half_size * 2
        self._rkeys: List[bytes] = []

    def configure(self, key: bytes) -> None:
        self._rkeys = self.ks.round_keys(key)
        if len(self._rkeys) != self.rounds:
            raise ValueError("key schedule produced unexpected number of round keys")

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("bad block size")
        L = block[: self.half_size]
        R = block[self.half_size :]
        for i in range(self.rounds):
            # L, R -> L', R'
            Fout = self.rf.F(R, self._rkeys[i])
            L, R = R, bytes(a ^ b for a, b in zip(L, Fout))
        return R + L

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("bad block size")
        L = block[: self.half_size]
        R = block[self.half_size :]
        for i in range(self.rounds - 1, -1, -1):
            Fout = self.rf.F(R, self._rkeys[i])
            L, R = R, bytes(a ^ b for a, b in zip(L, Fout))
        return R + L
