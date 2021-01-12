"""
Temat: Schematy dzielenia sekretu
Do przedstawienia problemu zaimplementowane zostały 3 schematy:
    - Schemat Shamira
    - Schmat Blakleya
    - Schemat Asmutha-Blooma

Wszystkie 3 powyższe schematy do szyfrowania i deszyfrowania używają AES-256

Szyfrowanie:

    - Wczytaj plik wejściowy (Tekst jawny)
    - Zaszyfruj go za pomocą AES-256 z losowo wygenerowanym kluczem 256-bit
    - Zapisz zaszyfrowany plik (Szyfrogram)
    - Podziel klucz na n części który może zostać zrekonstrowany przez k części
    - Zapisz klucze do osobnego pliku

Deszyfrowanie:

    - Odczytaj zaszyfrowany plik (szyfrogram)
    - Odczytaj podane klucze
    - Spróbuj połączyć klucze aby otrzymać oryginalny 256-bitowy klucz
    - Zdeszyfruj szyfrogram używająć AES-256
    - Zapisz tekst jawny do pliku


Przykładowe działanie programu
Szyfrowanie:
>>> python3 main.py -scheme [SCHEMAT] -encrypt -infile [NAZWA SZYFROWANEGO PLIKU] -outfile [NAZWA ZASZYFROWANEGO PLIKU] -keysfile [NAZWA PLIKU Z KLUCZAMI] -n [LICZBA CZĘŚCI] -k [ILE POTRZEBA ABY ODSZYFROWAĆ]
>>> python3 main.py -scheme Blakley -encrypt -infile corgi.jpg -outfile cipher.jpg -keysfile keys.txt -n 7 -k 5


Deszyfrowanie:
>>> python3 main.py -scheme [SCHEMAT] -decrypt -infile [NAZWA ZASZYFROWANEGO PLIKU] -outfile [NAZWA ODSZYFROWANEGO PLIKU] -keysfile [NAZWA PLIKU Z KLUCZAMI]
>>> python3 main.py -scheme Blakley -decrypt -infile cipher.jpg -outfile corgi_restored.jpg -keysfile keys.txt

Program powstał jako projekt na zajecia z przedmiotu kryptografia na III semestrze
"""

# Importowanie potrzebnych bibliotek i wcześniej utworzonych modułów
# Do wyboru poszczególncych trybów używamy pythonowego modułu argparse
import argparse
from blakley import *
from shamir import *
from asmuthbloom import *



                #########################
                # PARSOWANIE ARGUMENTÓW #
                #########################

parser = argparse.ArgumentParser()
parser.add_argument("-scheme", help="Wybierz schemat dzielenia sekretu: 'Blakley', 'Shamir' or 'AsmuthBloom'")
parser.add_argument("-encrypt", help="Włącz tryb szyfrowania", action="store_true")
parser.add_argument("-decrypt", help="Włącz tryb deszyfrowania", action="store_true")
parser.add_argument("-infile", help="Nazwa pliku wejściowego.")
parser.add_argument("-outfile", help="Nazwa pliku który zostanie utworzyony po szyfrowaniu.")
parser.add_argument("-keysfile", help="Nazwa pliku do którego zostaną zapisane klucze")
parser.add_argument("-n", help="Na tyle części podzielony zostanie klucz", type = int)
parser.add_argument("-k", help="Liczba części potrzebnych do odtworzenia sekretu", type = int)
args = parser.parse_args()
print("Arguments: {}".format(args))

                ########################
                # URUCHOMIENIE FUNKCJI #
                ########################

# Wybór odpowiedniego schematu dzielenia sekretu
if args.scheme == 'Blakley' or args.scheme == 'Shamir' or args.scheme == 'AsmuthBloom':
    if args.scheme == 'Blakley':
        sss = BlakleySSS()
    elif args.scheme == 'Shamir':
        sss = ShamirSSS()
    elif args.scheme == 'AsmuthBloom':
        sss = AsmuthBloomSSS()

    # Wybór szyforwania lub deszyfrowania
    if args.encrypt and args.decrypt:
        print("Niepoprawny tryb: Nie można szyfrować i deszyfrować jednocześnie")
    elif not args.encrypt and not args.decrypt:
        print("Niepoprawny tryb: Proszę wybrać jeden z trybów.'encrypt' lub 'decrypt'")
    elif args.encrypt:
        #Za pomocą AES-256 zaszyfruj tekst jawny i zapisz wynik do pliku następnie podziel klucz na n części
        print("Szyfrowanie...")
        sss.encrypt(args.infile, args.outfile, args.keysfile, args.n, args.k)
        print("Wykonano!")
    else:
        print("Deszyfrowanie...")
        # Połącz k częsci klucza a następnie odszyfruj szyfrogram
        sss.decrypt(args.infile, args.outfile, args.keysfile)
        print("Done!")
else:
    print("Proszę wybrać odpowiedni TRYB: 'Blakley', 'Shamir' or 'AsmuthBloom'")

