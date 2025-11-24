class CryptoService:
    @staticmethod
    def legendre_symbol(a, p):
        """
        Вычисляет символ Лежандра (a/p)
        a - целое число
        p - простое число
        Возвращает: 1, -1 или 0
        Проверяем, является ли число квадратным вычетом по модулю p
        """
        if p < 2:
            raise ValueError("p должно быть простым числом >= 2")

        a = a % p
        if a == 0:
            return 0

        result = CryptoService.mod_pow(a, (p - 1) // 2, p)
        return -1 if result == p - 1 else result

    @staticmethod
    def jacobi_symbol(a, n):
        """
        Вычисляет символ Якоби (a/n)
        a - целое число
        n - нечетное положительное число
        Возвращает: 1, -1 или 0
        Проверяем, является ли число квадратным вычетом по модулю n
        """
        if n <= 2 or n % 2 == 0:
            raise ValueError("n должно быть нечетным положительным числом")

        result = 1
        if a < 0:
            a = -a
            if n % 4 == 3:
                result = -result

        a = a % n
        while a != 0:
            while a % 2 == 0:
                a = a // 2
                if n % 8 in [3, 5]:
                    result = -result
            a, n = n, a
            if a % 4 == 3 and n % 4 == 3:
                result = -result
            a = a % n

        return result if n == 1 else 0

    @staticmethod
    def gcd(a, b):
        if a == 0 or b == 0:
            raise ValueError("One of the arguments is 0")

        a, b = abs(a), abs(b)
        while b != 0:
            r = a % b
            a = b
            b = r
        return a

    @staticmethod
    def extended_gcd(a, b):
        if a == 0:
            return abs(b), 0, 1 if b >= 0 else -1
        if b == 0:
            return abs(a), 1 if a >= 0 else -1, 0

        sign_a = 1 if a >= 0 else -1
        sign_b = 1 if b >= 0 else -1
        a, b = abs(a), abs(b)

        old_r, r = a, b
        old_x, x = 1, 0
        old_y, y = 0, 1

        while r != 0:
            quotient = old_r // r
            old_r, r = r, old_r - quotient * r
            old_x, x = x, old_x - quotient * x
            old_y, y = y, old_y - quotient * y

        return old_r, old_x * sign_a, old_y * sign_b

    @staticmethod
    def mod_pow(base, exponent, modulus):
        """
        Быстрое возведение в степень по модулю
        Вычисляет (base^exponent) mod modulus

        Использует метод бинарного возведения в степень
        """
        if modulus == 1:
            return 0

        if exponent < 0:
            raise ValueError("Отрицательная степень не поддерживается")

        result = 1
        base = base % modulus
        while exponent > 0:
            if exponent % 2 == 1:
                result = (result * base) % modulus
            exponent = exponent >> 1
            base = (base * base) % modulus
        return result