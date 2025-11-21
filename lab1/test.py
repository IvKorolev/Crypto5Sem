import asyncio
import os
import glob
import time
from typing import List
from des import DES
from deal import DEAL
from packing import CryptoContext, CipherMode, PaddingMode

INPUT_DIR = os.path.join(os.path.dirname(__file__), "input")
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "output_py")

MODES_TO_TEST = [
    (CipherMode.ECB, "ECB"),
    (CipherMode.CBC, "CBC"),
    (CipherMode.PCBC, "PCBC"),
    (CipherMode.CFB, "CFB"),
    (CipherMode.OFB, "OFB"),
    (CipherMode.CTR, "CTR"),
    (CipherMode.RANDOM_DELTA, "RD"),
]

async def cleanup_old_files():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    files = glob.glob(f"{OUTPUT_DIR}/*.enc") + glob.glob(f"{OUTPUT_DIR}/*.jpg") + glob.glob(f"{OUTPUT_DIR}/*.txt")
    for f in files:
        try:
            os.remove(f)
        except OSError:
            pass

def get_test_files() -> List[str]:
    if not os.path.exists(INPUT_DIR):
        os.makedirs(INPUT_DIR)
        return []

    all_files = glob.glob(f"{INPUT_DIR}/*.*")

    files = [f for f in all_files if os.path.isfile(f)]

    print(f"Найдено файлов в {INPUT_DIR}: {len(files)}")
    for f in files:
        print(f"   - {os.path.basename(f)}")

    return files

async def run_single_test(
        cipher_obj,
        key: bytes,
        cipher_name: str,
        file_path: str,
        mode: CipherMode,
        mode_name: str,
        block_size: int
):

    basename = os.path.basename(file_path)
    enc_path = os.path.join(OUTPUT_DIR, f"encrypted_{cipher_name}_{mode_name}_{basename}.enc")
    dec_path = os.path.join(OUTPUT_DIR, f"decrypted_{cipher_name}_{mode_name}_{basename}")

    iv = None
    if mode != CipherMode.ECB:
        iv = os.urandom(block_size)

    try:
        ctx = CryptoContext(
            cipher=cipher_obj,
            key=key,
            mode=mode,
            padding=PaddingMode.PKCS7,
            iv=iv
        )

        print(f"⌛ {cipher_name} [{mode_name}] -> {basename}...", end="", flush=True)

        t1 = time.perf_counter()
        await ctx.encrypt_file(file_path, enc_path)
        t2 = time.perf_counter()

        await ctx.decrypt_file(enc_path, dec_path)
        t3 = time.perf_counter()

        with open(file_path, "rb") as f:
            original_data = f.read()

        with open(dec_path, "rb") as f:
            decrypted_data = f.read()

        if original_data == decrypted_data:
            print(f" OK ({len(original_data)} bytes)")
        else:
            print(f" FAIL (Hash mismatch)")

    except Exception as e:
        print(f" ERROR: {e}")
        import traceback
        traceback.print_exc()

async def main():
    print("=== Запуск тестов (Python порт) ===")
    await cleanup_old_files()

    files = get_test_files()
    if not files:
        print("Нет тестовых файлов! Создайте папку input/ и положите туда файл.")
        if not os.path.exists("input"): os.makedirs("input")
        with open("input/test_auto.txt", "wb") as f:
            f.write(b"Hello World! " * 1000)
        files = ["input/test_auto.txt"]

    # 1. Тест DES (Все режимы)
    print("\n--- Testing DES ---")
    des_key = os.urandom(8)
    des_cipher = DES()

    for f in files:
        for mode, name in MODES_TO_TEST:
            await run_single_test(des_cipher, des_key, "DES", f, mode, name, 8)

    # 2. Тест DEAL-128 (Все режимы)
    print("\n--- Testing DEAL-128 ---")
    deal128_key = os.urandom(16)
    deal128_cipher = DEAL()

    if deal128_cipher:
        for f in files:
            for mode, name in MODES_TO_TEST:
                await run_single_test(deal128_cipher, deal128_key, "DEAL-128", f, mode, name,
                                      16)

    # 3. Тест DEAL-192 (Все режимы)
    print("\n--- Testing DEAL-192 ---")
    deal192_key = os.urandom(24)
    deal192_cipher = DEAL()

    if deal192_cipher:
        for f in files:
            for mode, name in MODES_TO_TEST:
                await run_single_test(deal192_cipher, deal192_key, "DEAL-192", f, mode, name,
                                      16)

    # 4. Тест DEAL-256 (Все режимы)
    print("\n--- Testing DEAL-256 ---")
    deal256_key = os.urandom(32)
    deal256_cipher = DEAL(rounds=8)

    if deal256_cipher:
        for f in files:
            for mode, name in MODES_TO_TEST:
                await run_single_test(deal256_cipher, deal256_key, "DEAL-256", f, mode, name,
                                      16)


if __name__ == "__main__":
    asyncio.run(main())