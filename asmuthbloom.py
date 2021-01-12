"""
Schemat dzielenia sekretu Asmutha-Blooma

Głowne założenia schematu:
    - Wybierz n parami różnych względnie pierwszych liczb całkowitych m1, ..., mn
    - Wybierz m0 takie, że gcd (m0, mi) = 1 (NWD(m0, mi) = 1) dla i = 1, ..., n
    - Wymagady warunek:
        iloczyn najmniejszych k liczb pierwszych > m0 * iloczyn największych (k-1) liczb pierwszych

Niech sekret S = x
Niech M = iloczyn najmniejszych k liczb pierwszych
Wybierz losowe A takie, że 0 <= x + A * m0 <= M
n kluczy = x + A * m0 (mod mi) dla i = 1, 2, ... , n
>= k kluczy może wyznaczyć x za pomocą modulacji chińskiego twierdzenia o resztach (CRT) iloczynu podanych mi. Następnie sekret = unikalne rozwiązanie CRT mod m0
<k kluczy nie może zapewnić unikalnego rozwiązania za pośrednictwem CRT

Konwencje:
    Rozwiązaniem chińskiego twierdzenia o resztach jest sekret / klucz S
    Podzieliliśmy 256-bitowy klucz AES na 32 fragmenty po 8 bitów / 1 bajt, a następnie kodujemy każdy z nich
    Dzieje się tak, ponieważ naprawdę trudno jest znaleźć zestaw par liczb całkowitych względnie pierwszych, które spełniają wymagane warunki.
    Na razie,
    1) Maksymalne dopuszczalne n wynosi 10, tj. Co najwyżej podzielone na 10 udziałów
    2) Wybór mi to najmniejsze n liczb pierwszych z listy od 91 do 100.
    3) m0 jest ustalone na 2 ^ 8 = 256

"""

import sys
import math
from sss import *
from Crypto.Random import random  # Jest to kryptograficznie mocniejsza wersja modułu random


class AsmuthBloomSSS(SSS):

    def __init__(self):
        """
        Pierwsze 91 liczb pierwszych ze 100 zostają użyte jako zbior par liczb
        całkowitch względnie pierwszych
        """

        super().__init__()
        self.primes = [467, 479, 487, 491, 499, 503, 509, 521, 523, 541]
        self.m0 = 256

    def split_key(self, key, n, k):
        """
        Klucz AES dzielony jest na 32 kawałki potem każdy
        kawałek jest zakodowany używając najmniejszych n liczb pierwszych
        y = x + A * m0
        Key i = [mi, y for kawałek 1, ... , y for kawałek 32]
        """

        # Nasz szyfr działa dla klucza podzielonego na max 10 części
        assert (n <= 10)

        # Podziel 256 bitowy klucz AES na 32 kawałki 8bitowe
        chunks = [c for c in key]

        # Bierzemy najmeniejsze liczby pierwsze z naszego zbioru
        m = self.primes[:n]

        # Funkcja pomocnicza z sss.py, wszystkie elementy listy zostaną pomnozone
        M = prod(m[:k])

        # Sprawdzamy czy warunki są spełnione
        assert (self.m0 * prod(m[-k + 1:]) < prod(m[:k]))

        keys = [[mi] for mi in m]
        for c in chunks:
            # Generujemy losowe A takie że 0 <= c + A * m0 < M
            A = random.randrange(0, math.floor((M - c) / self.m0))
            y = c + A * self.m0
            assert (y < M)

            # Generowanie części dla każdej 8-bitowy kawałek
            shares = [y % mi for mi in m]
            for i in range(n):
                keys[i].append(shares[i])

        # Zwracamy klucz
        return keys

    def combine_keys(self, keys):
        """
        Wyodrębniamy kawałki mi i y , następnie używamy CRT do każdego kawałka osobno
        Łączymy wszystkie 32 kawalki w 256 bitowy klucz AES
        Key = Połączone rozwiązania z chińskiego twierdzenia o resztach wszystkich 32 fragmentów
        """

        # keys[i][0] = mi
        # keys[i][1..32] = y mod mi (32 różne kawałki)
        k = len(keys)

        # m = [m1, m2, ... , mk]
        # chunks = [[y1, y2, ... , yk], ... , [y1, y2, ... , yk]]
        # Kazdy element [y1, y2, ... , yk] reprezentuje 8-bitowy kawałek originalnego 256-bitowego klucza AES
        m = [keys[i][0] for i in range(k)]
        chunks = [[keys[i][j] for i in range(k)] for j in range(1, 33)]

        # Obliczmy M, mi
        # M = produkt wszystkich mi
        # zi = M / mi
        # bi * (M / mi) = 1 (mod mi), i.e. bi = mulinv(zi, mi)
        # S = (y1 * z1 * b1 + y2 * z2 * b2 + ... + yk * zk * bk) % M % m0
        M = prod([mi for mi in m])
        z = [prod([m[i] for i in range(k) if i != j]) for j in range(k)]
        b = [mulinv(z[i], m[i]) for i in range(k)]
        S_chunks = [int(sum(y[i] * z[i] * b[i] % M for i in range(k)) % M % self.m0) for y in chunks]

        # Sekret S = klucz AES = Połączone rozwiązania z chińskiego twierdzenia o resztach wszystkich 32 fragmentów
        S = sum(S_chunks[i] * (256 ** i) for i in range(32))
        key = S.to_bytes(32, byteorder=sys.byteorder)

        # Zwracamy klucz
        return key
