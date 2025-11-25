from enum import Enum
import random
from typing import Tuple, Optional

class PrimalityTestType(Enum):
    FERMAT = "fermat"
    SOLOVAY_STRASSEN = "solovay_strassen"
    MILLER_RABIN = "miller_rabin"

class RSAService:
    PrimalityTestType = PrimalityTestType

    def __init__(
            self,
            crypto_service,
            primality_tests_dict,
            test_type: PrimalityTestType = PrimalityTestType.MILLER_RABIN,
            min_probability: float = 0.99,
            bit_length: int = 512
    ):
        """
        :param crypto_service: экземпляр CryptoService
        :param primality_tests_dict: словарь с тестами простоты
        :param test_type: тип теста простоты
        :param min_probability: минимальная вероятность простоты
        :param bit_length: битовая длина генерируемых простых чисел
        """
        self.crypto = crypto_service

        self.key_generator = self.RSAKeyGenerator(
            crypto_service=crypto_service,
            primality_tests_dict=primality_tests_dict,
            test_type=test_type,
            min_probability=min_probability,
            bit_length=bit_length
        )

        self.public_key: Optional[Tuple[int, int]] = None
        self.private_key: Optional[Tuple[int, int]] = None

    def generate_keys(self):
        self.public_key, self.private_key = self.key_generator.generate_key_pair()
        return self.public_key, self.private_key

    def encrypt(self, message: int) -> int:
        if self.public_key is None:
            raise ValueError("Ключи не сгенерированы. Вызовите generate_keys()")

        e, n = self.public_key

        if message >= n:
            raise ValueError(f"Сообщение должно быть меньше модуля n={n}")

        return self.crypto.mod_pow(message, e, n)

    def decrypt(self, ciphertext: int) -> int:
        if self.private_key is None:
            raise ValueError("Ключи не сгенерированы. Вызовите generate_keys()")

        d, n = self.private_key

        return self.crypto.mod_pow(ciphertext, d, n)

    def generate_weak_keys(self):

        while True:
            p = self.key_generator._generate_prime()
            q = self.key_generator._generate_prime()

            if p == q:
                continue

            n = p * q
            phi_n = (p - 1) * (q - 1)

            n_sqrt = int(n ** 0.5)
            n_root4 = int(n_sqrt ** 0.5)
            limit = n_root4 // 3

            if limit <= 3:
                continue

            d = None
            for _ in range(500):
                d_candidate = random.randint(3, limit)

                if self.crypto.gcd(d_candidate, phi_n) == 1:
                    d = d_candidate
                    break

            if d is None:
                continue

            gcd_val, x, y = self.crypto.extended_gcd(d, phi_n)
            if gcd_val != 1:
                continue

            e = x % phi_n
            if e < 1:
                e += phi_n

            self.public_key = (e, n)
            self.private_key = (d, n)
            return

    class RSAKeyGenerator:
        def __init__(
                self,
                crypto_service,
                primality_tests_dict,
                test_type: PrimalityTestType,
                min_probability: float,
                bit_length: int
        ):
            self.crypto = crypto_service
            self.primality_test = primality_tests_dict[test_type]
            self.min_probability = min_probability
            self.bit_length = bit_length

        def generate_key_pair(self) -> Tuple[Tuple[int, int], Tuple[int, int]]:
            p, q = self._generate_primes_with_fermat_protection()

            n = p * q
            phi_n = (p - 1) * (q - 1)

            e = self._choose_public_exponent(phi_n)

            d = self._compute_private_exponent_with_wiener_protection(e, phi_n, n)

            return (e, n), (d, n)

        def _generate_prime(self) -> int:
            while True:
                candidate = random.getrandbits(self.bit_length)

                candidate |= (1 << (self.bit_length - 1))
                candidate |= 1

                if self.primality_test.is_prime(candidate, self.min_probability):
                    return candidate

        def _generate_primes_with_fermat_protection(self) -> Tuple[int, int]:
            while True:
                p = self._generate_prime()
                q = self._generate_prime()

                if p == q:
                    continue

                min_difference = 2 ** (self.bit_length // 2 - 100)
                if abs(p - q) > min_difference:
                    return (p, q) if p > q else (q, p)

        def _choose_public_exponent(self, phi_n: int) -> int:
            """
            Стандартно e = 65537
            Должно выполняться: 1 < e < phi(n) и gcd(e, phi(n)) = 1
            """
            e = 65537

            if e < phi_n and self.crypto.gcd(e, phi_n) == 1:
                return e

            e = 3
            while e < phi_n:
                if self.crypto.gcd(e, phi_n) == 1:
                    return e
                e += 2

            raise ValueError("Не удалось найти подходящую открытую экспоненту")

        def _compute_private_exponent_with_wiener_protection(self, e: int, phi_n: int, n: int) -> int:
            """
            Вычисление закрытой экспоненты d с защитой от атаки Винера. (d > n^(1/3)).
            """
            gcd, x, y = self.crypto.extended_gcd(e, phi_n)

            if gcd != 1:
                raise ValueError("e и phi(n) не взаимно просты")
            d = x % phi_n

            bit_length = n.bit_length()
            min_d = 1 << (bit_length // 3)

            if d < min_d:
                while d < min_d:
                    d += phi_n

            return d