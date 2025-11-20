from Interfaces import SymmetricBlockCipher
from typing import Iterable, List
import os
import enum
import math
import asyncio
from concurrent.futures import ThreadPoolExecutor

class PaddingMode(enum.Enum):
    ZEROS = 0
    ANSI_X923 = 1
    PKCS7 = 2
    ISO_10126 = 3

def pad(data: bytes, block_size: int, mode: PaddingMode) -> bytes:
    rem = len(data) % block_size
    pad_len = (block_size - rem) if rem != 0 else block_size
    if mode == PaddingMode.ZEROS:
        return data + b"\x00" * pad_len
    elif mode == PaddingMode.ANSI_X923:
        return data + (b"\x00" * (pad_len - 1)) + bytes([pad_len])
    elif mode == PaddingMode.PKCS7:
        return data + bytes([pad_len]) * pad_len
    elif mode == PaddingMode.ISO_10126:
        rnd = os.urandom(pad_len - 1)
        return data + rnd + bytes([pad_len])
    else:
        raise ValueError("Unknown padding")

def unpad(data: bytes, block_size: int, mode: PaddingMode) -> bytes:
    if mode == PaddingMode.ZEROS:
        return data.rstrip(b"\x00")
    last = data[-1]
    if last == 0 or last > block_size:
        raise ValueError("Bad padding")
    if mode == PaddingMode.ANSI_X923:
        if any(b != 0 for b in data[-last:-1]):
            raise ValueError("Bad ANSI X.923 padding")
        return data[:-last]
    if mode == PaddingMode.PKCS7:
        if any(b != last for b in data[-last:]):
            raise ValueError("Bad PKCS7 padding")
        return data[:-last]
    if mode == PaddingMode.ISO_10126:
        return data[:-last]
    raise ValueError("Unknown padding")

class CipherMode(enum.Enum):
    ECB = 0
    CBC = 1
    PCBC = 2
    CFB = 3
    OFB = 4
    CTR = 5
    RANDOM_DELTA = 6


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _inc_counter(counter: bytearray) -> None:
    for i in range(len(counter) - 1, -1, -1):
        counter[i] = (counter[i] + 1) & 0xFF
        if counter[i] != 0:
            break


class CryptoContext:
    """
    Контекст выполнения для блочного шифра с режимами и набивками.
    Асинхронные методы encrypt/decrypt возвращают bytes и умеют работать с файлами.
    Параллелизация там, где поддерживается
    """
    def __init__(
        self,
        cipher: SymmetricBlockCipher,
        key: bytes,
        mode: CipherMode,
        padding: PaddingMode,
        iv: bytes | None = None,
        **kwargs,
    ) -> None:
        self.cipher = cipher
        self.cipher.configure(key)
        self.mode = mode
        self.padding = padding
        self.iv = iv
        self.extra = kwargs
        if self.mode in (CipherMode.CBC, CipherMode.PCBC, CipherMode.CFB, CipherMode.OFB, CipherMode.CTR, CipherMode.RANDOM_DELTA):
            if iv is None:
                raise ValueError("This mode requires IV")
            if len(iv) != self.cipher.block_size:
                raise ValueError("IV must match block size")

    def _encrypt_ecb(self, blocks: List[bytes]) -> List[bytes]:
        with ThreadPoolExecutor() as ex:
            return list(ex.map(self.cipher.encrypt_block, blocks))

    def _encrypt_cbc(self, blocks: List[bytes]) -> List[bytes]:
        res = []
        prev = bytes(self.iv)
        for b in blocks:
            x = _xor(b, prev)
            c = self.cipher.encrypt_block(x)
            res.append(c)
            prev = c
        return res

    def _encrypt_pcbc(self, blocks: List[bytes]) -> List[bytes]:
        res = []
        prev_p = bytes(self.iv)
        prev_c = bytes(self.iv)

        for p in blocks:
            x = _xor(p, _xor(prev_p, prev_c))
            c = self.cipher.encrypt_block(x)
            res.append(c)
            prev_p = p
            prev_c = c
        return res

    def _encrypt_cfb(self, blocks: List[bytes]) -> List[bytes]:
        res = []
        prev = bytes(self.iv)
        for p in blocks:
            gamma = self.cipher.encrypt_block(prev)
            c = _xor(p, gamma)
            res.append(c)
            prev = c
        return res

    def _encrypt_ofb(self, blocks: List[bytes]) -> List[bytes]:
        res = []
        prev = bytes(self.iv)
        for p in blocks:
            gamma = self.cipher.encrypt_block(prev)
            c = _xor(p, gamma)
            res.append(c)
            prev = gamma
        return res

    def _encrypt_ctr(self, blocks: List[bytes]) -> List[bytes]:
        res = []
        counter = bytearray(self.iv)
        for p in blocks:
            gamma = self.cipher.encrypt_block(bytes(counter))
            _inc_counter(counter)
            c = _xor(p, gamma)
            res.append(c)
        return res

    def _encrypt_random_delta(self, blocks: List[bytes]) -> List[bytes]:
        res = []
        a = 1664525
        c = 1013904223
        mask = 0xFFFFFFFFFFFFFFFF

        seed = int.from_bytes(self.iv, 'big')

        for p in blocks:
            seed = (a * seed + c) & mask
            seed_bytes = seed.to_bytes(8, 'big')
            gamma = self.cipher.encrypt_block(seed_bytes)
            res.append(_xor(p, gamma))
        return res

    def _decrypt_ecb(self, blocks: List[bytes]) -> List[bytes]:
        with ThreadPoolExecutor() as ex:
            return list(ex.map(self.cipher.decrypt_block, blocks))

    def _decrypt_cbc(self, blocks: List[bytes]) -> List[bytes]:
        res = []
        prev = bytes(self.iv)
        for c in blocks:
            decrypted = self.cipher.decrypt_block(c)
            p = _xor(decrypted, prev)
            res.append(p)
            prev = c
        return res

    def _decrypt_pcbc(self, blocks: List[bytes]) -> List[bytes]:
        res = []
        prev_p = bytes(self.iv)
        prev_c = bytes(self.iv)

        for c in blocks:
            decrypted = self.cipher.decrypt_block(c)
            xor_mask = _xor(prev_p, prev_c)
            p = _xor(decrypted, xor_mask)

            res.append(p)
            prev_c = c
            prev_p = p
        return res

    def _decrypt_cfb(self, blocks: List[bytes]) -> List[bytes]:
        res = []
        prev = bytes(self.iv)
        for c in blocks:
            gamma = self.cipher.encrypt_block(prev)
            p = _xor(c, gamma)
            res.append(p)
            prev = c
        return res

    def _encrypt_blocks(self, blocks: List[bytes]) -> List[bytes]:
        if self.mode == CipherMode.ECB:
            return self._encrypt_ecb(blocks)
        elif self.mode == CipherMode.CBC:
            return self._encrypt_cbc(blocks)
        elif self.mode == CipherMode.PCBC:
            return self._encrypt_pcbc(blocks)
        elif self.mode == CipherMode.CFB:
            return self._encrypt_cfb(blocks)
        elif self.mode == CipherMode.OFB:
            return self._encrypt_ofb(blocks)
        elif self.mode == CipherMode.CTR:
            return self._encrypt_ctr(blocks)
        elif self.mode == CipherMode.RANDOM_DELTA:
            return self._encrypt_random_delta(blocks)
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")

    def _decrypt_blocks(self, blocks: List[bytes]) -> List[bytes]:
        if self.mode == CipherMode.ECB:
            return self._decrypt_ecb(blocks)
        elif self.mode == CipherMode.CBC:
            return self._decrypt_cbc(blocks)
        elif self.mode == CipherMode.PCBC:
            return self._decrypt_pcbc(blocks)
        elif self.mode == CipherMode.CFB:
            return self._decrypt_cfb(blocks)
        elif self.mode == CipherMode.OFB:
            return self._encrypt_ofb(blocks)
        elif self.mode == CipherMode.CTR:
            return self._encrypt_ctr(blocks)
        elif self.mode == CipherMode.RANDOM_DELTA:
            return self._encrypt_random_delta(blocks)
        else:
            raise ValueError(f"Unsupported mode: {self.mode}")

    async def encrypt(self, data: bytes) -> bytes:
        bs = self.cipher.block_size
        pdata = pad(data, bs, self.padding)
        blocks = [pdata[i : i + bs] for i in range(0, len(pdata), bs)]
        enc_blocks = await asyncio.to_thread(self._encrypt_blocks, blocks)
        return b"".join(enc_blocks)

    async def decrypt(self, ciph: bytes) -> bytes:
        bs = self.cipher.block_size
        if len(ciph) % bs != 0:
            raise ValueError("ciphertext length not multiple of block size")
        blocks = [ciph[i : i + bs] for i in range(0, len(ciph), bs)]
        dec_blocks = await asyncio.to_thread(self._decrypt_blocks, blocks)
        data = b"".join(dec_blocks)
        return unpad(data, bs, self.padding)

    async def encrypt_file(self, in_path: str, out_path: str, chunk_blocks: int = 1 << 14) -> None:
        bs = self.cipher.block_size
        chunk = bs * chunk_blocks
        size = os.path.getsize(in_path)
        with open(in_path, 'rb') as f_in, open(out_path, 'wb') as f_out:
            while True:
                buf = f_in.read(chunk)
                if not buf:
                    break
                # только последняя пачка получает padding
                if f_in.tell() == size:
                    buf = pad(buf, bs, self.padding)
                else:
                    if len(buf) % bs != 0:
                        # дочитаем чтобы кратно блоку
                        tail = f_in.read(bs - (len(buf) % bs))
                        buf += tail
                blocks = [buf[i : i + bs] for i in range(0, len(buf), bs)]
                enc_blocks = await asyncio.to_thread(self._encrypt_blocks, blocks)
                f_out.write(b"".join(enc_blocks))

    async def decrypt_file(self, in_path: str, out_path: str, chunk_blocks: int = 1 << 14) -> None:
        bs = self.cipher.block_size
        chunk = bs * chunk_blocks
        with open(in_path, 'rb') as f_in, open(out_path, 'wb') as f_out:
            buf_acc = b""
            while True:
                buf = f_in.read(chunk)
                if not buf:
                    break
                buf_acc += buf
                # обрабатываем блоками, паддинг снимем в конце
                while len(buf_acc) >= chunk:
                    part, buf_acc = buf_acc[:chunk], buf_acc[chunk:]
                    blocks = [part[i : i + bs] for i in range(0, len(part), bs)]
                    dec_blocks = await asyncio.to_thread(self._decrypt_blocks, blocks)
                    f_out.write(b"".join(dec_blocks))
            # последний кусок (включая паддинг)
            if buf_acc:
                if len(buf_acc) % bs != 0:
                    raise ValueError("ciphertext file not aligned")
                blocks = [buf_acc[i : i + bs] for i in range(0, len(buf_acc), bs)]
                dec_blocks = await asyncio.to_thread(self._decrypt_blocks, blocks)
                plaintext = b"".join(dec_blocks)
                plaintext = unpad(plaintext, bs, self.padding)
                f_out.write(plaintext)