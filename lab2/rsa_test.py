import unittest
import random
from rsa import RSAService, PrimalityTestType
from math_context import CryptoService
from simplicity_tests import FermatTest, SolovayStrassenTest, MillerRabinTest

class TestRSAService(unittest.TestCase):
    def setUp(self):
        self.crypto_service = CryptoService()
        self.primality_tests = {
            PrimalityTestType.FERMAT: FermatTest(self.crypto_service),
            PrimalityTestType.SOLOVAY_STRASSEN: SolovayStrassenTest(self.crypto_service),
            PrimalityTestType.MILLER_RABIN: MillerRabinTest(self.crypto_service)
        }

    def test_key_generation_and_encryption_for_all_types(self):
        test_types = [
            (PrimalityTestType.FERMAT, "Fermat"),
            (PrimalityTestType.SOLOVAY_STRASSEN, "SolovayStrassen"),
            (PrimalityTestType.MILLER_RABIN, "MillerRabin"),
        ]

        for test_type, name in test_types:
            with self.subTest(name=name):
                rsa_service = RSAService(
                    crypto_service=self.crypto_service,
                    primality_tests_dict=self.primality_tests,
                    test_type=test_type,
                    min_probability=0.99,
                    bit_length=512
                )

                try:
                    rsa_service.generate_keys()
                except Exception as e:
                    self.fail(f"Failed to generate keys: {e}")

                if rsa_service.public_key is None or rsa_service.private_key is None:
                    self.fail("Keys were not generated")

                message = 123456789

                try:
                    ciphertext = rsa_service.encrypt(message)
                except Exception as e:
                    self.fail(f"Encryption failed: {e}")

                try:
                    decrypted = rsa_service.decrypt(ciphertext)
                except Exception as e:
                    self.fail(f"Decryption failed: {e}")

                self.assertEqual(message, decrypted,
                                 f"Decrypted message does not match. Original: {message}, Decrypted: {decrypted}")

    def test_encryption_decryption_parametrized(self):
        test_types = [
            (PrimalityTestType.FERMAT, "Fermat"),
            (PrimalityTestType.SOLOVAY_STRASSEN, "SolovayStrassen"),
            (PrimalityTestType.MILLER_RABIN, "MillerRabin"),
        ]

        for test_type, name in test_types:
            with self.subTest(name=name):
                rsa_service = RSAService(
                    crypto_service=self.crypto_service,
                    primality_tests_dict=self.primality_tests,
                    test_type=test_type,
                    min_probability=0.99,
                    bit_length=512
                )
                rsa_service.generate_keys()
                n = rsa_service.public_key[1]

                # 1. Тесты со случайными сообщениями
                for _ in range(10):
                    max_msg = n - 1
                    message = random.randint(0, max_msg)

                    ciphertext = rsa_service.encrypt(message)
                    decrypted = rsa_service.decrypt(ciphertext)

                    self.assertEqual(message, decrypted,
                                     f"Random message test failed. Original: {message}, Decrypted: {decrypted}")

                # 2. Тесты с граничными значениями (0 и N-1)
                zero = 0
                encrypted_zero = rsa_service.encrypt(zero)
                decrypted_zero = rsa_service.decrypt(encrypted_zero)
                self.assertEqual(zero, decrypted_zero, "Encryption/Decryption failed for message = 0")

                max_message = n - 1
                encrypted_max = rsa_service.encrypt(max_message)
                decrypted_max = rsa_service.decrypt(encrypted_max)
                self.assertEqual(max_message, decrypted_max, "Encryption/Decryption failed for message = N-1")

    def test_encrypt_message_too_big(self):
        rsa_service = RSAService(
            crypto_service=self.crypto_service,
            primality_tests_dict=self.primality_tests,
            test_type=PrimalityTestType.MILLER_RABIN,
            min_probability=0.99,
            bit_length=256
        )
        rsa_service.generate_keys()

        n = rsa_service.public_key[1]
        too_big_message = n + 10

        with self.assertRaises(ValueError):
            rsa_service.encrypt(too_big_message)


if __name__ == '__main__':
    unittest.main()