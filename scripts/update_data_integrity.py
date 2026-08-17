#!/usr/bin/env python3
"""
scripts/update_data_integrity.py

AUTOMATISATION — Procédure de mise à jour des données statiques critiques
(data/*.json + gschema + .desktop) + leurs manifests d'intégrité.

Deux modes :
  1) python update_data_integrity.py update
     - Régénère data/checksums.sha256
     - Met à jour EXPECTED_SHA256 dans src/.../vuln_scanner.py
     - Met à jour EXPECTED_HASH    dans src/.../pqc_validator.py

  2) python update_data_integrity.py check
     - Vérifie que data/checksums.sha256 + constantes Python concordent
       avec les fichiers actuels. Échoue rc=1 si non (pour CI gate).

UTILISATION TYPIQUE (après modification de vuln_database.json ou
pqc_nist_reference.json ou gschema / .desktop) :

    $ python3 scripts/update_data_integrity.py update
    $ git diff data/checksums.sha256 src/netsentinel/core/audit/{vuln_scanner,pqc_validator}.py
    $ git commit …
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Literal

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"

# Fichiers listés explicitement : ordre DETERMINISTE (crucial pour
# checksums.sha256 diff idempotents).
DATA_FILES_REL = [
    "vuln_database.json",
    "pqc_nist_reference.json",
    "org.netsentinel.NetSentinel.gschema.xml",
    "netsentinel.desktop",
]

# Mapping simple: clé -> (fichier python, regex à matcher, nom affiché)
EXPECTED_CONSTANTS = [
    {
        "key": "vuln_database.json",
        "py_file": ROOT / "src/netsentinel/core/audit/vuln_scanner.py",
        "pattern": re.compile(r'(EXPECTED_SHA256\s*=\s*")([0-9a-f]{64})(")'),
        "label": "vuln_scanner.EXPECTED_SHA256",
    },
    {
        "key": "pqc_nist_reference.json",
        "py_file": ROOT / "src/netsentinel/core/audit/pqc_validator.py",
        "pattern": re.compile(r'(EXPECTED_HASH\s*=\s*")([0-9a-f]{64})(")'),
        "label": "pqc_validator.EXPECTED_HASH",
    },
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def compute_hashes() -> dict[str, str]:
    """Calcule sha256 de chaque fichier listé dans DATA_FILES_REL."""
    result: dict[str, str] = {}
    for rel in DATA_FILES_REL:
        p = DATA_DIR / rel
        if not p.exists():
            raise FileNotFoundError(f"missing: data/{rel}")
        result[rel] = sha256_file(p)
    return result


def write_checksums_manifest(hashes: dict[str, str]) -> str:
    """
    Écrit data/checksums.sha256 au format `sha256sum` (compatible
    `sha256sum -c data/checksums.sha256` depuis la racine projet).
    """
    lines = [
        "# Manifest SHA-256 — GÉNÉRÉ AUTOMATIQUEMENT par scripts/update_data_integrity.py",
        "# Ne PAS éditer à la main. Utiliser `python3 scripts/update_data_integrity.py update`.",
        "# Format: sha256-hex  <relative path (data/...)>",
        "# ================================================================",
        "",
    ]
    for rel in DATA_FILES_REL:
        lines.append(f'{hashes[rel]}  data/{rel}')
    lines.append("")
    manifest_path = DATA_DIR / "checksums.sha256"
    manifest_path.write_text("\n".join(lines), encoding="utf-8")
    return str(manifest_path)


def patch_expected_constant(spec: dict, new_sha: str, *, dry_run: bool) -> bool:
    py = spec["py_file"]
    if not py.exists():
        raise FileNotFoundError(f"Python source manquant: {py}")
    text = py.read_text(encoding="utf-8")
    match = spec["pattern"].search(text)
    if not match:
        raise ValueError(f"pattern non trouvé dans {py} : {spec['pattern'].pattern}")
    old_sha = match.group(2)
    if old_sha == new_sha:
        return False  # rien à faire
    prefix, suffix = text[: match.start(2)], text[match.end(2):]
    new_text = prefix + new_sha + suffix
    if not dry_run:
        py.write_text(new_text, encoding="utf-8")
    return True


def mode_update(*, dry_run: bool) -> int:
    print("[1/3] Calcul SHA-256 des fichiers data/ ...")
    hashes = compute_hashes()
    for rel in DATA_FILES_REL:
        print(f"  - data/{rel:<40}  {hashes[rel]}")

    print("[2/3] Écriture data/checksums.sha256 ...")
    manifest_path = write_checksums_manifest(hashes)
    if dry_run:
        print(f"    [dry-run] écrirait {manifest_path}")
    else:
        print(f"    OK  {manifest_path}")

    print("[3/3] Mise à jour constantes Python EXPECTED_* ...")
    any_patched = False
    for spec in EXPECTED_CONSTANTS:
        sha = hashes[spec["key"]]
        changed = patch_expected_constant(spec, sha, dry_run=dry_run)
        label = spec["label"]
        if changed:
            any_patched = True
            status = "[dry-run] modifierait" if dry_run else "PATCHÉ"
            print(f"    {status}  {label} = {sha}")
        else:
            print(f"    inchangé   {label} = {sha}")

    print()
    if dry_run:
        print("DRY-RUN : aucun fichier modifié. Ré-exécutez SANS --dry-run pour appliquer.")
    else:
        print("✅ Terminé. Vérifiez l'écart avec :  git diff")
        if any_patched:
            print("   ⚠  Des constantes Python ont changé : relancez `pytest tests/unit/core/test_vuln_scanner.py tests/unit/core/test_pqc_validator.py`")
    return 0


def mode_check() -> int:
    """
    Mode CI / pre-commit : échoue rc=1 si data/checksums.sha256 ou constantes
    EXPECTED_* sont en désaccord avec les fichiers sur disque.
    """
    hashes = compute_hashes()

    # 1. Vérif manifest checksums.sha256 existe et correspond
    manifest_path = DATA_DIR / "checksums.sha256"
    if not manifest_path.exists():
        print(f"❌ manifest absent: {manifest_path}", file=sys.stderr)
        return 1
    r = subprocess.run(
        ["sha256sum", "-c", str(manifest_path)],
        cwd=ROOT, capture_output=True, text=True,
    )
    if r.returncode != 0:
        print("❌ Échec `sha256sum -c data/checksums.sha256` :", file=sys.stderr)
        print(r.stdout, file=sys.stderr)
        print(r.stderr, file=sys.stderr)
        return 1
    print("✅ checksums.sha256 vérifié (sha256sum -c)")

    # 2. Vérif constantes Python
    ok_all = True
    for spec in EXPECTED_CONSTANTS:
        expected = hashes[spec["key"]]
        py = spec["py_file"]
        m = spec["pattern"].search(py.read_text(encoding="utf-8"))
        if not m:
            print(f"❌ pattern introuvable dans {py}", file=sys.stderr)
            ok_all = False
            continue
        actual = m.group(2)
        if actual != expected:
            print(
                f"❌ {spec['label']} mismatch: code={actual} attendu={expected}",
                file=sys.stderr,
            )
            ok_all = False
        else:
            print(f"✅ {spec['label']:<36} {expected}")
    return 0 if ok_all else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Met à jour ou vérifie l'intégrité des données statiques.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "mode",
        nargs="?",
        choices=("update", "check"),
        default="update",
        help="update = régénère + patch; check = mode CI gate (défaut: update)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="(mode update seulement) Affiche les changements sans rien écrire",
    )
    args = p.parse_args(argv)

    if args.mode == "check":
        return mode_check()
    return mode_update(dry_run=args.dry_run)


if __name__ == "__main__":
    raise SystemExit(main())
