"""
Schemat dzielenia sekretu Blakleya

Głowne założenia schematu:
    - Sekret przechowywany jest w k-vector X
    - n kluczy = n równań hiperpłaszczyznowych
    - Odtworzyć sekret możemy gdy mamy >=k hiperpłaszczyzn
    - Wskazują one punkt X
    - Jeżeli liczba hiperpłaszcyzn < k to wtedy nie można uzyskać X
    - Pierwsza współrzędna jest naszym sekretem
"""

import sys
import scipy.linalg
import numpy as np
from sss import *
from Crypto.Random import random # Lepsza wersja biblioteki random


class BlakleySSS(SSS):

    def __init__(self):
        super().__init__()

    def split_key(self, key, n, k):
        """
        Generujemy k-vector X i odpowiadającą mu macierz Pascala A
        Potem obliczamy y wektora ze wzoru Ax = y
        Key i = [i-ty wiersz Macierzy Paskala, y[i]]
        """

        # Wygeneruj wektor x
        x = [int.from_bytes(key, byteorder=sys.byteorder)]
        for i in range(k - 1):
            x.append(random.randint(0, 2 ** 256))
        x = np.array(x)

        # Generujemy macierz Pascala
        A = np.ones((n, k)).astype(int)
        for r in range(1, n):
            for c in range(1, k):
                A[r, c] = A[r, c - 1] + A[r - 1, c]

        # Generujemy wektor y gdzie Ax = y
        y = np.dot(A, x)

        # Podział klucza
        keys = [A[i].tolist() + [y[i]] for i in range(n)]

        # Zwracamy klucz
        return keys

    def combine_keys(self, keys):
        """
        Generowanie kwadratowej macierzy Pascala B z pierwszych k kluczy
        Wyciągamy pierwsze wartości k y
        Rozwiązujemy dla x w Bx = y
        Klucz = x[0]
        """

        k = len(keys[0]) - 1
        if k > len(keys):
            raise Exception(
                "Nieodpowiednie klucze deszyfrowania.Proszę upewnić się najpierw aby {} klucze były poprawne.".format(k))

        # Generowanie macierzy i y wektora z kluczy, bierzemy pierwsze k kluczy
        B = np.matrix([keys[i][:-1] for i in range(k)])[:k]
        y = np.array([keys[i][-1] for i in range(k)])[:k]

        if np.linalg.matrix_rank(B) != k:
            raise Exception(
                "Podane klucze nie są liniowo niezależne. Proszę się upewnić że {} pierwszych kluczy są poprawne.".format(k))


        # Rozwiązujemy równanie: Bx = y
        # Używamy scipy ponieważ numpy nie ma wbudowanej funkcji inwersji

        invB = scipy.linalg.inv(B)
        detB = round(scipy.linalg.det(B))

        # Musimy użyć // zamiast / aby zachować dokładność numeryczną
        S = sum(int(round(detB * invB[0][i])) * y[i] for i in range(k)) // round(detB)
        key = S.to_bytes(32, byteorder=sys.byteorder)

        # Zwracamy klucz
        return key