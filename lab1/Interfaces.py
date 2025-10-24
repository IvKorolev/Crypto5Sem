from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Protocol, runtime_checkable, List

@runtime_checkable
class KeySchedule(Protocol):
    def round_keys(self, master_key: bytes) -> List[bytes]:
        ...


@runtime_checkable
class RoundFunction(Protocol):
    def F(self, right_half: bytes, round_key: bytes) -> bytes:
        ...


class SymmetricBlockCipher(ABC):

    block_size: int  # байты

    @abstractmethod
    def configure(self, key: bytes) -> None:
        ...

    @abstractmethod
    def encrypt_block(self, block: bytes) -> bytes:
        ...

    @abstractmethod
    def decrypt_block(self, block: bytes) -> bytes:
        ...