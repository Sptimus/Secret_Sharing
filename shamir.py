"""
Schemat dzielenia sekretu Shamira

Głowne założenia schematu:
    - Wybierz losowy wielomian stopnia (k-1):
        - q(x) = a_0 + a_1 * x + a2 * x^2 + ... + a_(k-1) * x^(k-1)
    - Sekret przechowywany jest w q(0) = a_0 = S
    - Sekret dzielony jest na n cześci  n>=k
    - Potrzebujemy co najmniej k czesci zeby odzyskac sekret q(x)
    - Jezeli mamy mniej części niż k to nie jesteśmy w stanie zrekonstruować sekretu q(x)
    - Rekonstrukcja sekretu odbywa się poprzez interpolacje wielomianu metodą Lagrange
"""

import sys
from sss import *
from Crypto.Random import random  # Jest to lepsza wersja pythonowego modulu Radnom


#Definicja klasy Shamir ktora odpowiada za podzial sekretu schematem Shamira
class ShamirSSS(SSS):


    #Klasa dziedziczy z modułu SSS
    def __init__(self):
        super().__init__()

    # Funkcja podziału klucza
    def split_key(self, key, n, k):

        # Generowanie wektora a
        a = [int.from_bytes(key, byteorder=sys.byteorder)]
        for i in range(k - 1):
            a.append(random.randint(0, 2 ** 256))

        # Wielomian q(x) = a_0 + a_1 * x + a2 * x^2 + ... + a_(k-1) * x^(k-1) (mod p)
        # Wygeneruj q(1), q(2), ... , q(n) (mod p)
        keys = []
        for i in range(1, n + 1):
            x = [i ** j for j in range(k)]
            keys.append([i, sum(a[j] * x[j] % self.p for j in range(k)) % self.p])

        # Zwróc klucz
        return keys

    # Funkcja łącząca klucze
    def combine_keys(self, keys):
        """
        Z klucza wyciągamy x i y = q(x)
        Wykorzystujemy interoplacje wieolomianów Lagrange aby obliczyć q(0) = S
        Key = q(0)
        """

        # Wartość x zdefiniowana jest w następujący sposób:
        # keys[i][0] = x value

        # Wartość y zdefiniowana jest w następujący sposób:
        # keys[i][1] = q(x) value

        k = len(keys)
        x = [keys[i][0] for i in range(k)]
        y = [keys[i][1] for i in range(k)]

        # Znajdujemy q(0) bezpośrednio poprzez zastosowanie interpolacji wielomianu Lagrange
        # Secret S = AES key = q(0)

        # Przyjmuje za wartość modulo (2 ** 256) ponieważ nieodpowiedni klucz może doprowadzić
        # do sytuacji gdy S > 256 bity
        # Jeżeli S > 256 bity, wtedy wyrzuci błąd przy konwersji na 32 bity
        S = int(sum(y[j] * basis(x, k, j, self.p) % self.p for j in range(k)) % self.p) % (2 ** 256)
        key = S.to_bytes(32, byteorder=sys.byteorder)

        #Zwracamy klucz
        return key