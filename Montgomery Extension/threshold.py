#!/usr/bin/env python3
"""
LOKALNE GENEROVANIE ED25519 KLUCOV PRE BELENIOS TRUSTEES s THRESHOLDOM
Daniel Riško
KPI
2026
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Pridanie aktualneho priecinka do sys.path, aby Python nasiel lokalne moduly (napr. ed25519.py)
CONTRIB_DIR = Path(__file__).resolve().parent
if str(CONTRIB_DIR) not in sys.path:
    sys.path.insert(0, str(CONTRIB_DIR))


#Impotruje Ed22519 z povodneho suboru
#G- generator eliptickej krivky
# L- rad skupiny (vele prvocislo, vsetky kluce su mensie ako L)
# point_pow- vypočíta G^n (skalarne nasobenie bodu na krivke)
# point_to_string- zakoduje bod na krivke do 64-znakoveho hex retazca
# random_modulo- vygeneruje kryptograficky bezpecne nahodne cislo < L
from ed25519 import (
    G,
    L,
    make_trustee_keypair,
    point_pow,
    point_to_string,
    random_modulo,
)


GROUP_DESCRIPTION = "Ed25519"#zapisuje sa do certifikatu, nazov kryptografickej skupiny
#Podla common_types.ml v Beleniosu
B58_DIGITS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


# Vypocita SHA-256 hash zadaneho textu a vrati ho ako hex retazec
def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# Serializuje Python objekt do kompaktneho JSON retazca (bez medzier)
def compact_json(obj: Any) -> str:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


# Vygeneruje jeden nahodny znak Base58 abecedy
# Pouziva os.urandom pre kryptograficku bezpecnost
# Maska 63 (0b00111111) zaistuje rovnomerne rozlozenie
def generate_b58_digit() -> str:
    while True:
        x = os.urandom(1)[0] & 63  # nahodny bajt obmedzeny na 0-63

        if x < 58:# odmieta hodnoty >= 58  (kvoli rovnomernemu rozlozeniu)
            return B58_DIGITS[x]


# Vygeneruje nahodny Base58 retazec zadanej dlzky (predvolene 22 znakov)
# Tento retazec sa pouziva ako seed (tajny kluc trusteea)
def generate_b58_token(length: int = 22) -> str:
    return "".join(generate_b58_digit() for _ in range(length))

#Odvodí podpisovy sukromny kluc (sk) zo seedu
def derive_sk(seed: str) -> int:
    return int(sha256_hex("sk|" + seed), 16) % L


def derive_dk(seed: str) -> int:
    return int(sha256_hex("dk|" + seed), 16) % L


# Vytvara Schnorrov podpis spravy pomocou sukromneho kluca sk
# Postup:
#   1. Vygeneruje nahodne w a vypocita commitment = G^w
#   2. Vypocita challenge ako hash prefixu + commitment
#   3. Vypocita response = w - sk * challenge (mod L)
# Vrati slovnik so spravou a podpisom {challenge, response}
def sign(sk: int, message: str) -> Dict[str, Any]:
    w = random_modulo(L)
    commitment = point_pow(G, w)
    prefix = f"sigmsg|{message}|"
    challenge = int(sha256_hex(prefix + point_to_string(commitment)), 16) % L
    response = (w - (sk * challenge)) % L
    return {"message": message, "signature": {"challenge": str(challenge), "response": str(response)}}


# Vytvara certifikat trusteea zo seedu a kontextu
# Certifikat obsahuje:
#   - context: metadata (skupina, index, threshold, pocet trustees)
#   - verification: verejny podpisovy kluc (G^sk)
#   - encryption: verejny sifrovaci kluc (G^dk)
#   - podpis celého obsahu certifikatu pomocou sk
# Vrati dvojicu: (JSON retazec obsahu certifikatu, podpisany certifikat)
def make_cert(seed: str, context: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    sk = derive_sk(seed)# podpisovy sukromny kluc odvodeny zo seedu
    dk = derive_dk(seed)# sifrovaci sukromny kluc odvodeny zo seedu

    #obsah certifikatu
    cert_keys = {
        "context": context,
        "verification": point_to_string(point_pow(G, sk)),
        "encryption": point_to_string(point_pow(G, dk)),
    }
    cert_message = compact_json(cert_keys)
    cert = sign(sk, cert_message)
    return cert_message, cert


 #Datova trieda uchovavajuca vsetky udaje jedneho trustee
@dataclass
class TrusteeMaterial:
    index: int
    seed: str
    cert: Dict[str, Any]


# vytvori prvu cast verejneho kluca
def generate_trustee(index: int, threshold: int, size: int) -> TrusteeMaterial:
    context = {"group": GROUP_DESCRIPTION, "index": index, "threshold": threshold, "size": size}
    seed = generate_b58_token(22)
    _, cert = make_cert(seed, context)# vytvori certifikat zo seedu a kontextu
    return TrusteeMaterial(index=index, seed=seed, cert=cert)


# Vygeneruje zoznam materialov pre vsetkych trustees
# Parametre:
#   count - celkovy pocet trustees
#   threshold - minimalny pocet trustees potrebnych na desifrovanie
def generate_trustees(count: int, threshold: int) -> List[TrusteeMaterial]:
    return [generate_trustee(i + 1, threshold, count) for i in range(count)]
