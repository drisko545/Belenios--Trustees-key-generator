#!/usr/bin/env python3

"""
LOKALNE GENEROVANIE ED25519 KLUCOV PRE BELENIOS THRESHOLD TRUSTEES
Daniel Riško
KPI
2026
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

# Pridanie aktualneho priecinka do sys.path, aby Python nasiel lokalne moduly (napr. threshold.py)
CONTRIB_DIR = Path(__file__).resolve().parent
if str(CONTRIB_DIR) not in sys.path:
    sys.path.insert(0, str(CONTRIB_DIR))


# Importuje z threshold.py:
# compact_json - serializuje objekt do kompaktneho JSON retazca
# generate_trustees - vygeneruje zoznam materialov (seed + cert) pre vsetkych trustees
from threshold import compact_json, generate_trustees


# Zapise textovy obsah do suboru na zadanej ceste
# Ak priecinok neexistuje, automaticky ho vytvori
def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


# Definuje a vrati parser pre argumenty prikazoveho riadku
# Pouzivatel musi zadat:
#   --work-dir   - priecinok kde sa ulozia kluce
#   --trustees   - celkovy pocet trustees
#   --threshold  - minimalny pocet trustees potrebnych na desifrovanie
#   --clean      - (volitelne) zmaze work-dir pred generovanim
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Generate Belenios threshold trustee keys."
    )
    parser.add_argument("--work-dir", required=True, help="Directory where the keys will be written.")
    parser.add_argument("--trustees", type=int, required=True, help="Number of threshold trustees.")
    parser.add_argument("--threshold", type=int, required=True, help="Threshold required to decrypt.")
    parser.add_argument("--clean", action="store_true", help="Remove work-dir before generating.")
    return parser


def main() -> None:
    #Vytvori parder pre argumenty prikazoveho riadku
    parser = build_parser()

    #Nacitanie udajov ktore pouzivatel zadal pri spusteni skripty (pocet trustees, threshold)
    args = parser.parse_args()

    #Zakladne vstupne podmienky, ktore overuju, ze sa jedna aspon o 2 trustees, inak threshold nebude fungovat
    if args.trustees < 2:
        parser.error("--trustees must be at least 2 for Belenios threshold setup")
    if not (1 <= args.threshold < args.trustees):
        parser.error("--threshold must satisfy 1 <= threshold < trustees")

    # Pripravenie pracovneho priecinka
    work_dir = Path(args.work_dir).resolve()
    if work_dir.exists() and args.clean:
        shutil.rmtree(work_dir)
    work_dir.mkdir(parents=True, exist_ok=True)

    #Vygenerovanie klucov pre vsetkych trustees, ktorych pocet sa zadal pri spusteni skriptu
    trustees = generate_trustees(args.trustees, args.threshold)


    #Vytvorenie dvojice suborov pre kazdeho trustee
    for trustee in trustees:
        prefix = work_dir / f"trustee-{trustee.index:02d}"
        #zapise seed (privkey) do trustee-01.privkey
        write_text(prefix.with_suffix(".privkey"), trustee.seed)
        #zapise certifikat (pubkey) do trustee-01.pubkey
        write_text(prefix.with_suffix(".pubkey"), compact_json(trustee.cert) + "\n")

    print(f"I: wrote trustee keys to {work_dir}")
    for path in sorted(work_dir.glob("trustee-*.*key")):
        print(f"I: {path.relative_to(work_dir)}")


if __name__ == "__main__":
    main()
