import sys
from functools import reduce
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random  # Kryptograficznie silniejsza wersja od modulu python Random

#######################################################################################################################
# Najpierw zdefiniujemy funkcje pomocnicze

    ######################
    # Funkcje pomocnicze #
    ######################


def prod(lst):
    """
    Funkcja przyjmuje liste i mnoży wszystkie elementy
    """
    return reduce(lambda x, y: x * y, lst)


def xgcd(b, n):
    """
    Rozszerzony algorytm euklidesa
    """
    x0, x1, y0, y1 = 1, 0, 0, 1
    while n != 0:
        q, b, n = b // n, n, b % n
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return b, x0, y0



def mulinv(b, n):
    """
    Zwraca odwrotność modulo b w mod n
    i.e. x = mulinv(b) mod n, (x * b) % n == 1
    """
    g, x, _ = xgcd(b, n)
    if g == 1:
        return x % n


def basis(x, k, j, p):
    # Obliczanie podstawy dla metody Lagrange

    terms = [(0 - x[m]) * mulinv(x[j] - x[m], p) for m in range(k) if m != j]
    return prod(terms) % p

#######################################################################################################################


class SSS:
    """
    Jest to klasa bazowa dla wszustkich schematow dzielenia sekretu

    Szyfrowanie: polega na użyciu AES-256 zaszyfrowaniu pliku wyjściowego i zapisaniu go
    Następnie klucz dzielony jest na n częśći


    Deszyfrowanie: Połącz k kluczy w klucz AES i odszyfruj plik

    Inne klasy rozszerzają klasę SSS i implementuja swoje własne metody podziału i łaczenia klucza
    """

    def __init__(self):
        """
        Musimy wygernerować bardzo duzą liczbę pierwszą p pamietając o warunkach:
            - S < p
            - S jest 32 bitowe więc p > 256 bitów
        """

        # Liczba pierwsza p zapisana statycznie
        self.p = 2 ** 257 - 93

    def split_key(self, key, n, k):
        """
        Podział klucza AES na wiele cześci
        Implementacja jest zależna od schematu
        """
        pass

    def combine_keys(self, keys):
        """
        Funkcja ma laczyc podzielony klucz
        Udaje sie tylko pod warunkiem jezeli zostala podana odpowiednia liczba kluczy
        Implementacja zależna od wykorzystanego schematu
        """
        pass

    def encrypt(self, infile, outfile, keysfile, n, k):
        """
        Schemat szyfrowania:
        1) Wczytuje plik
        2) Tworzy encodera AES-256 i bierze 32 losowe bity jako klucz
        3) Szyfrujemy Plik
        4) Szyfrogram przechowywany zostaje w osobnym pliku
        5) Podział klucza za pomocą funkcji split_key
        6) Zapisz podzielone klucze do pliku
        Encrypts infile to outfile via AES-256 and stores "broken up" key in keysfile
        """

        # Wczytanie pliku z tekstem jawnym
        with open(infile, 'rb') as f:
            plain = f.read()

        # Stwórz enkoder AES z 32 losowymi bitami jako klucz
        key = Random.new().read(32)
        encoder = AES.new(key, AES.MODE_CTR, counter=Counter.new(128))

        # Szyfrowanie tekstu jawnego
        cipher = encoder.encrypt(plain)

        # Zapis szyfrogramu w osobnym pliku
        with open(outfile, 'wb') as f:
            f.write(cipher)

        # Podział klucza na n części
        keys = self.split_key(key, n, k)

        # Zapis klucza w osobnym pliku
        with open(keysfile, 'w') as f:
            for key in keys:
                f.write("{}\n".format(key))

    # Funkcja otwiera plik z kluczami i tworzy z niego liste
    def decrypt(self, infile, outfile, keysfile):

        # Otwarcie pliku z kluczami
        with open(keysfile, 'r') as f:
            keys = f.read().splitlines()
        keys = [[int(num) for num in key[1:-1].replace(' ', '').split(',')] for key in keys]
        self.decrypt_with_keys(infile, outfile, keys)

    def decrypt_with_keys(self, infile, outfile, keys):
        """
        Schemat deszyfrowania:
        1) Odczytaj szyfroagram z pliku
        2) Połącz klucze aby otrzymacz klucz AES-256
        3) Stwórz decoder AES z połączonym kluczem
        4) Deszyfruj szyfrogram
        5) Zapisz szyfrogram do nowego pliku
        """

        # Wczytanie szyfrogramu
        with open(infile, 'rb') as f:
            cipher = f.read()

        try:
            # Łaczenie kluczy. W razie gdy liczba podanych kluczy jest zbyt mała (<k) wyrzuci wyjątek
            key = self.combine_keys(keys)

            # Utworzenie decodera AES-256
            decoder = AES.new(key, AES.MODE_CTR, counter=Counter.new(128))

            # Odszyfrowanie szyfrogramu
            plain = decoder.decrypt(cipher)
        except Exception as e:
            plain = str.encode(e.args[0])
        finally:
            # Zapis odszyfrowanej wiadomości do nowego pliku
            with open(outfile, 'wb') as f:
                f.write(plain)
