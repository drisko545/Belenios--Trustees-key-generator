"""
LOKALNE GENEROVANIE ED25519 KLUCOV PRE BELENIOS TRUSTEES BEZ THRESHOLDU
Daniel Riško
KPI
2026
"""

import argparse
import hashlib
import json#na zapis do JSON formatu (pre public kluc)
import os
from pathlib import Path
from typing import Dict, Optional, Tuple


#PARAMETRE ELIPTICKEJ KRIVKY ED25519
P = (1 << 255) - 19 # Modul prvocislo pouzivani v Ed25519
L = (1 << 252) + 27742317777372353535851937790883648493#Rad grupy, priblizne 2^252
A = -1 % P
D = (-(121665 * pow(121666, P - 2, P))) % P
K = (2 * D) % P

# Pevne dane body krivky, pomocou ktorych sa pocita verejny kluc (base point) podla Ocaml kodu
GX = 15112221349535400772501151409588531511454012693041857206046113283949847762202
GY = 46316835694926478169428394003475163141307993866256225615783033603165251855960


#GENEROVANIE NAHODNEHO CISLA
#pokial sa nevrati hodnota mensia ako modulus
#modulus je priblizne 2^252, definovana hodnota vyssie
def random_modulo(modulus: int) -> int:
    bits = modulus.bit_length()#Zistenie kolko bitov ma modulus
    size = ((bits - 1) // 8) + 1 #prepocet bitov na bajty
    mask = (1 << bits) - 1
    while True:
        r = int.from_bytes(os.urandom(size), "little") & mask
        if r < modulus: #ak je cislo mensie ako modulus, vrati sa, ak nie pokracujeme dalej
            return r


#KONVERZIA BODOV
def of_coordinates(x: int, y: int) -> Tuple[int, int, int, int]:
    x %= P
    y %= P
    return (x, y, 1, (x * y) % P)


ONE = of_coordinates(0, 1)
G = of_coordinates(GX, GY)


# SCITANIE BODOV NA ELIPTICKEJ KRIVKE
# Funkcia zoberie dva body P a Q na eliptickej krivke a vrati ich sucet R = P + Q,
# kde R je novy bod, ktory tiez lezi na tej istej krivke.
# Vypocet sa realizuje v tzv. extended (rozsirenych) suradniciach (x, y, z, t),
# aby sa eliminovalo delenie, ktore je pri modulo aritmetike nad velkymi cislami neefektivne
# P reprezentuje MODULO
def point_add(
    p1: Tuple[int, int, int, int], p2: Tuple[int, int, int, int]
) -> Tuple[int, int, int, int]:

    # Rozbalenie vstupnych bodov P a Q
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2

    # Kombinacie suradnic oboch bodov (optimalizovane vyrazy pre vypocet)
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P

    # Zahrnutie parametra krivky (konstanta K vychadza z parametra D krivky Ed25519)
    c = (t1 * K * t2) % P

    # Praca so Z-suradnicami (skalovanie v projektivnych/extended suradniciach)
    d = (z1 * (2 * z2 % P)) % P

    # Pomocne medzivypocty pre zjednodusenie finalnych rovnic
    e = (b - a) % P
    f = (d - c) % P
    g = (d + c) % P
    h = (b + a) % P

    # Vypocet vysledneho bodu R = (x3, y3, z3, t3)
    x3 = (e * f) % P  # nova x-ova suradnica
    y3 = (g * h) % P  # nova y-ova suradnica
    t3 = (e * h) % P  # pomocna hodnota (x * y)
    z3 = (f * g) % P  # nova z-ova suradnica

    return (x3, y3, z3, t3) #vracia sa novy bod


# NASOBENIE BODU SKALAROM
# Vypocita sa verejny kluc ako nasobok generatoroveho bodu G a sukromneho kluca.
# Priame opakovane scitanie bodu (G + G + ... + G) by bolo pri velkych cislach pomale,
# preto sa pouziva efektivny algoritmus zalozeny na binarnom rozklade cisla (double-and-add).
# def point_pow(base: Tuple[int, int, int, int], n: int) -> Tuple[int, int, int, int]:
#     result = ONE #neutralny bod (0)
#     addend = base # aktualny bod (na zaciatku G)
#     k = n % L # sukromny kluc (skalar)
#     while k > 0:
#         if k & 1:
#             result = point_add(result, addend)
#
#         #zdvojenie bodu (2G, 4G, 8G,....)
#         addend = point_add(addend, addend)
#         # posun bitov doprava (spracovanie dalsieho bitu)
#         k >>= 1
#     return result



def point_pow(base: Tuple[int, int, int, int], n: int) -> Tuple[int, int, int, int]:
    """
    Skalarne nasobenie bodu pomocou Montgomery ladder algoritmu.
    Na rozdiel od double-and-add, tento algoritmus vykonava rovnaky
    pocet operacii bez ohladu na hodnotu kluca, cim eliminuje
    zranitelnost voci utokom postrannym kanalmi (side-channel attacks).
    """
    k = n % L
    R0 = ONE      # neutralny bod
    R1 = base     # aktualny bod
    bits = k.bit_length()
    for i in range(bits - 1, -1, -1):
        if (k >> i) & 1:
            R0 = point_add(R0, R1)
            R1 = point_add(R1, R1)
        else:
            R1 = point_add(R0, R1)
            R0 = point_add(R0, R0)
    return R0

#PREVEDIE BOD Z (x, y, z, t) na klasicke (x, y)
def to_coordinates(p: Tuple[int, int, int, int]) -> Tuple[int, int]:
    x, y, z, _ = p
    invz = pow(z, P - 2, P)
    return (x * invz) % P, (y * invz) % P


#PREVEDIE BOD Z (x, y, z, t) na klasicke (x, y)
def point_to_string(p: Tuple[int, int, int, int]) -> str:
    x, y = to_coordinates(p)
    # Ulozi sa cela hodnota y a iba 1 bit z x (parita x - ci je parne/neparne).
    # Hodnota x sa totiz da spatne vypocitat zo y, pricom existuju len 2 moznosti,
    # a tento 1 bit urcuje, ktoru z nich vybrat
    compressed = y ^ ((x & 1) << 255)
    return format(compressed, "064x")#Vrati sa 64 bitovy retazec, ktory sa nasledne ulozi do JSONU pod public_key


#HASH DO Zq
def hash_to_zq_hex_string(s: str) -> int:
    digest = hashlib.sha256(s.encode("utf-8")).hexdigest()
    return int(digest, 16) % L


#OVERENIE ZK DOKAZU
#Overenie, ci challenge a response naozaj sedia k verejnemu klucu
def verify_trustee_pok(public_key_str: str, challenge: int, response: int) -> bool:
    y = point_from_string(public_key_str)
    commitment = point_add(point_pow(G, response), point_pow(y, challenge))
    zkp_prefix = f"pok|Ed25519|{public_key_str}|"
    expected = hash_to_zq_hex_string(zkp_prefix + point_to_string(commitment))
    return expected == challenge


#DEKODOVANIE BODU
def point_from_string(s: str) -> Tuple[int, int, int, int]:
    if len(s) != 64:
        raise ValueError("invalid Ed25519 point encoding length")
    raw = int(s, 16)
    y = raw & ((1 << 255) - 1)
    x_sign = raw >> 255

    y2 = (y * y) % P
    x2 = ((y2 - 1) * pow((D * y2 + 1) % P, P - 2, P)) % P

    x = mod_sqrt_ed25519(x2)
    if x is None:
        raise ValueError("invalid Ed25519 point encoding")
    if (x & 1) != x_sign:
        x = (-x) % P
    return of_coordinates(x, y)


#ODMOCNINA MODULO P
def mod_sqrt_ed25519(a: int) -> Optional[int]:
    exp = (P - 5) // 8
    v = pow((2 * a) % P, exp, P)
    i = (2 * a * v * v) % P
    x = (a * v * (i - 1)) % P
    if (x * x) % P == a % P:
        return x
    return None


#GENEROVANIE KLUCOV TRUSTEE
def make_trustee_keypair(
    private_key: Optional[int] = None,
) -> Tuple[int, Dict[str, object], str]:
    x = private_key if private_key is not None else random_modulo(L)# Ak bol cez argumenty zadany sukromny kluc, pouzije sa ten, inak generujeme novy
    if not (0 <= x < L):# cislo musi patrit do grupy, teda modulo
        raise ValueError("private key must satisfy 0 <= x < L")

    #G-generatorovy bod
    # x - sukromny kluc (skalar)
    y = point_pow(G, x) # vypocitanie verejneho bodu Y = xG
    y_str = point_to_string(y) # prevedie bod z (x, y, z, t) na textovy (string format)

    w = random_modulo(L)# vytvori sa nova nahodna pomocna hodnota w v intervale 0 <= w < L
    commitment = point_pow(G, w)# spravi sa bod na krivke
    commitment_str = point_to_string(commitment)

    zkp_prefix = f"pok|Ed25519|{y_str}|"#aby bol dokaz viazany na konkretny kluc
    challenge = hash_to_zq_hex_string(zkp_prefix + commitment_str)# challenge sa urci ako hash verejneho kluca a commitmentu, prevedeny na cislo modulo L
    response = (w - (x * challenge)) % L

    if not verify_trustee_pok(y_str, challenge, response):
        raise RuntimeError("generated PoK failed internal verification")

    pub = {
        "pok": {"challenge": str(challenge), "response": str(response)},
        "public_key": y_str,
        "signature": None,
        "name": None,
    }

    fingerprint = hashlib.sha256(y_str.encode("utf-8")).hexdigest()[:8].upper()
    return x, pub, fingerprint


#ZAPIS SUBOROV
def write_outputs(
    out_dir: Path, fingerprint: str, private_key: int, public_key: Dict[str, object]
) -> Tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)

    priv_path = out_dir / f"{fingerprint}.privkey"
    pub_path = out_dir / f"{fingerprint}.pubkey"

    # Write private key as JSON string (with quotes, NO trailing newline)
    # Format required by Belenios web UI: "<integer>"
    priv_path.write_text(json.dumps(str(private_key)), encoding="utf-8")
    pub_path.write_text(json.dumps(public_key, separators=(",", ":")) + "\n", encoding="utf-8")

    os.chmod(priv_path, 0o400)
    os.chmod(pub_path, 0o444)
    return priv_path, pub_path


# SPRACOVANIE ARGUMENTOV
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate Belenios-compatible Ed25519 trustee keypair (.privkey/.pubkey)."
    )
    parser.add_argument(
        "--out-dir",
        default=".",
        help="Output directory for generated files (default: current directory)",
    )
    parser.add_argument(
        "--private-key",
        type=int,
        default=None,
        help="Optional fixed private key value in [0, L). If omitted, generated randomly.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()#nacita argumenty z prikazoveho riadky
    private_key, public_key, fingerprint = make_trustee_keypair(args.private_key)#generacia klucov

    #ulozenie do suborov
    priv_path, pub_path = write_outputs(Path(args.out_dir), fingerprint, private_key, public_key)

    print(f"I: keypair {fingerprint} has been generated")
    print(f"I: private key saved to {priv_path}")
    print(f"I: public key saved to {pub_path}")


if __name__ == "__main__":
    main()