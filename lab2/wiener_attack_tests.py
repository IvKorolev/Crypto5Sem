import unittest
from wiener_attack import WienerAttackService
from rsa import RSAService, PrimalityTestType
from math_context import CryptoService
from simplicity_tests import MillerRabinTest

class TestWienerAttack(unittest.TestCase):
    def setUp(self):
        self.crypto_service = CryptoService()
        self.attacker = WienerAttackService(self.crypto_service)

    def test_wiener_attack_successful(self):
        primality_tests = {
            PrimalityTestType.MILLER_RABIN: MillerRabinTest(self.crypto_service)
        }

        rsa_service = RSAService(
            crypto_service=self.crypto_service,
            primality_tests_dict=primality_tests,
            test_type=PrimalityTestType.MILLER_RABIN,
            min_probability=0.99,
            bit_length=512
        )

        rsa_service.generate_weak_keys()
        e, n = rsa_service.public_key
        original_d, _ = rsa_service.private_key
        result = self.attacker.attack(e, n)

        if not result.success:
            self.fail("Атака Винера на уязвимый ключ не удалась")

        self.assertEqual(result.d, original_d,
                         f"Найденный d не совпадает с оригинальным!\nНайдено: {result.d}\nОригинал: {original_d}")

    def test_wiener_attack_fails_on_secure_key(self):
        primality_tests = {
            PrimalityTestType.MILLER_RABIN: MillerRabinTest(self.crypto_service)
        }

        rsa_service = RSAService(
            crypto_service=self.crypto_service,
            primality_tests_dict=primality_tests,
            test_type=PrimalityTestType.MILLER_RABIN,
            min_probability=0.99,
            bit_length=1024
        )

        rsa_service.generate_keys()
        e, n = rsa_service.public_key
        result = self.attacker.attack(e, n)

        self.assertFalse(result.success,
                         "Атака Винера не должна была успешно взломать защищённый ключ!")

    def test_wiener_attack_with_example(self):
        n = 90581
        e = 17993
        expected_d = 5

        result = self.attacker.attack(e, n)
        if not result.success:
            self.fail("Атака на примере не удалась")

        self.assertEqual(result.d, expected_d,
                         f"Найденный d не совпадает с ожидаемым!\nОжидалось: {expected_d}\nНайдено: {result.d}")


if __name__ == '__main__':
    unittest.main()