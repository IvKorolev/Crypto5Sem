from typing import List, Tuple, Optional
from dataclasses import dataclass
from math_context import CryptoService
from math import isqrt

@dataclass
class WienerAttackResult:
    d: Optional[int]
    phi_n: Optional[int]
    convergents: List[Tuple[int, int]]
    success: bool


class WienerAttackService:
    def __init__(self, crypto_service):
        self.crypto = crypto_service

    def attack(self, e: int, n: int) -> WienerAttackResult:
        convergents = self._compute_convergents(e, n)

        for k, d in convergents:
            if k == 0:
                continue

            phi_n_candidate = (e * d - 1) // k

            if self._verify_phi(n, phi_n_candidate):
                return WienerAttackResult(
                    d=d,
                    phi_n=phi_n_candidate,
                    convergents=convergents,
                    success=True
                )

        return WienerAttackResult(
            d=None,
            phi_n=None,
            convergents=convergents,
            success=False
        )

    def _compute_convergents(self, e: int, n: int) -> List[Tuple[int, int]]:
        """
        Вычисляет подходящие дроби для разложения e/n в цепную дробь
        :return: список подходящих дробей [(k0, d0), (k1, d1), ...]
        """
        continued_fraction = self._continued_fraction_expansion(e, n)
        convergents = []

        h_prev2, k_prev2 = 1, 0
        h_prev1, k_prev1 = continued_fraction[0], 1

        convergents.append((h_prev1, k_prev1))

        for i in range(1, len(continued_fraction)):
            a_i = continued_fraction[i]
            h_current = a_i * h_prev1 + h_prev2
            k_current = a_i * k_prev1 + k_prev2

            convergents.append((h_current, k_current))

            h_prev2, k_prev2 = h_prev1, k_prev1
            h_prev1, k_prev1 = h_current, k_current

        return convergents

    def _continued_fraction_expansion(self, numerator: int, denominator: int) -> List[int]:
        """
        Цепная дробь имеет вид: a_0 + 1/(a_1 + 1/(a_2 + 1/(a_3 + ...)))
        :return: список коэффициентов [a_0, a_1, a_2, ...]
        """
        coefficients = []

        while denominator != 0:
            quotient = numerator // denominator
            coefficients.append(quotient)

            numerator, denominator = denominator, numerator - quotient * denominator

        return coefficients

    def _verify_phi(self, n: int, phi_n_candidate: int) -> bool:
        """
        Для корректного φ(n) должно выполняться:
        1. φ(n) < n
        2. φ(n) > 0
        3. p и q (корни уравнения x² - (n - φ(n) + 1)x + n = 0) должны быть целыми
        4. p * q = n
        """
        if phi_n_candidate <= 0 or phi_n_candidate >= n:
            return False

        sum_pq = n - phi_n_candidate + 1
        discriminant = sum_pq * sum_pq - 4 * n

        if discriminant < 0:
            return False

        sqrt_discriminant = isqrt(discriminant)
        if sqrt_discriminant * sqrt_discriminant != discriminant:
            return False

        p = (sum_pq + sqrt_discriminant) // 2
        q = (sum_pq - sqrt_discriminant) // 2

        if p * q != n:
            return False

        if p <= 1 or q <= 1:
            return False

        return True