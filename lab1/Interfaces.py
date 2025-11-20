from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List

class KeySchedule(ABC):
    @abstractmethod
    def round_keys(self, master_key: bytes) -> List[bytes]:
        ...


class RoundFunction(ABC):
    @abstractmethod
    def F(self, right_half: bytes, round_key: bytes) -> bytes:
        ...


class SymmetricBlockCipher(ABC):

    block_size: int

    @abstractmethod
    def configure(self, key: bytes) -> None:
        ...

    @abstractmethod
    def encrypt_block(self, block: bytes) -> bytes:
        ...

    @abstractmethod
    def decrypt_block(self, block: bytes) -> bytes:
        ...