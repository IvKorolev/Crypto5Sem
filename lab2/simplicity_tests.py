from abc import ABC, abstractmethod
import random
from math_context import CryptoService

class IPrimalityTest(ABC):
    @abstractmethod
    def is_prime(self, n: int, min_probability: float) -> bool:
        ...

class BasePrimalityTest(IPrimalityTest):
    def __init__(self, crypto_service):
        self.crypto = crypto_service

    def is_prime(self, n: int, min_probability: float = 0.99) -> bool:
        if not (0.5 <= min_probability < 1.0):
            raise ValueError("Вероятность должна быть в диапазоне [0.5, 1)")

        if n < 2:
            return False
        if n == 2 or n == 3:
            return True
        if n % 2 == 0:
            return False

        num_iterations = self._calculate_iterations(min_probability)

        for _ in range(num_iterations):
            if not self._single_test_iteration(n):
                return False

        return True

    def _calculate_iterations(self, min_probability: float) -> int:
        error_probability = 1 - min_probability
        k = 1
        while (0.5 ** k) > error_probability:
            k += 1
        return k

    @abstractmethod
    def _single_test_iteration(self, n: int) -> bool:
        ...

class FermatTest(BasePrimalityTest):
    def _single_test_iteration(self, n: int) -> bool:
        a = random.randint(2, n - 1)
        result = self.crypto.mod_pow(a, n - 1, n)
        return result == 1

class SolovayStrassenTest(BasePrimalityTest):
    def _single_test_iteration(self, n: int) -> bool:
        a = random.randint(2, n - 1)

        if self.crypto.gcd(a, n) != 1:
            return False

        jacobi = self.crypto.jacobi_symbol(a, n)
        jacobi_mod = jacobi % n

        euler = self.crypto.mod_pow(a, (n - 1) // 2, n)
        return euler == jacobi_mod

class MillerRabinTest(BasePrimalityTest):
    def _single_test_iteration(self, n: int) -> bool:

        s, d = 0, n - 1
        while d % 2 == 0:
            s += 1
            d //= 2

        a = random.randint(2, n - 2)

        x = self.crypto.mod_pow(a, d, n)
        if x == 1 or x == n - 1:
            return True

        for _ in range(s - 1):
            x = self.crypto.mod_pow(x, 2, n)
            if x == n - 1:
                return True

        return False
