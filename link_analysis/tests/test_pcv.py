#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json
import requests
import os
import time
import csv
import sys
from collections import Counter
from pathlib import Path

os.system('')  # Active les couleurs ANSI sous Windows

COLORS = {
    "phishing": "\033[91m",
    "suspect": "\033[93m",
    "legitimate": "\033[92m",
    "error": "\033[95m",
    "reset": "\033[0m"
}

REQUEST_DELAY   = 0.03
REQUEST_TIMEOUT = 12
API_URL         = "http://127.0.0.1:8001/check_url"

def csv_path_default():
    return (Path(__file__).resolve().parent.parent / "database" / "pcv_phishing.csv").resolve()

CSV_PATH = csv_path_default()

def load_urls_from_csv(path: Path):
    if not path.exists():
        print(COLORS["error"] + f"[ERREUR] Fichier introuvable : {path}" + COLORS["reset"])
        return []
    urls, seen = [], set()
    with path.open(newline='', encoding='utf-8', errors='ignore') as f:
        for row in csv.reader(f):
            if not row:
                continue
            u = str(row[0]).strip().strip('"').strip("'")
            if u and u not in seen:
                seen.add(u)
                urls.append(u)
    return urls

def safe_float(x):
    try:
        return float(x)
    except Exception:
        return None

def extract_ml_info(result: dict):
    proba = result.get("proba", None)
    pred  = result.get("sources", {}).get("ml", {}).get("prediction", None)
    if proba is None:
        proba = result.get("sources", {}).get("ml", {}).get("proba", None)
    return (pred, safe_float(proba))

def normalized_db_hits(result: dict):
    hits = result.get("db_hits", None)
    if hits is None:
        src = (result.get("source") or "").lower()
        hits = []
        if "urlhaus" in src:
            hits.append("URLhaus")
        if any(k in src for k in ("ofcs", "phishdb", "nemesis")):
            hits.append("OFCS")
        if any(k in src for k in ("google", "safebrowsing", "gsb")):
            hits.append("GSB")

    norm, seen = [], set()
    for h in hits or []:
        if not h:
            continue
        h_up = h.strip().upper()
        if "URLHAUS" in h_up:
            name = "URLhaus"
        elif "OFCS" in h_up or "PHISHDB" in h_up:
            name = "OFCS"
        elif "GSB" in h_up or "SAFE" in h_up or "GOOGLE" in h_up:
            name = "GSB"
        else:
            name = h.strip()
        if name not in seen:
            seen.add(name)
            norm.append(name)
    return norm

class Acc:
    def __init__(self):
        self.db_by_source = Counter()
        self.db_combo_counts = Counter()
        self.ml_high = 0
        self.ml_medium = 0
        self.ml_low = 0
        self.db_and_ml_high   = 0
        self.db_and_ml_medium = 0
        self.db_and_ml_low    = 0
        self.db_urls_list = []
        self.errors = 0

def bucket_ml(proba: float | None) -> str:
    if proba is None:
        return "low"
    if proba >= 0.80:
        return "high"
    if proba >= 0.60:
        return "medium"
    return "low"

def classify_and_count(url: str, result: dict, acc: Acc):
    db_hits = normalized_db_hits(result)
    _, ml_proba = extract_ml_info(result)

    if db_hits:
        for h in db_hits:
            if h in ("URLhaus", "OFCS", "GSB"):
                acc.db_by_source[h] += 1
        if len(db_hits) >= 2:
            acc.db_combo_counts[tuple(sorted(db_hits))] += 1

        b = bucket_ml(ml_proba)
        if b == "high":
            acc.db_and_ml_high += 1
        elif b == "medium":
            acc.db_and_ml_medium += 1
        else:
            acc.db_and_ml_low += 1

        acc.db_urls_list.append((url, ",".join(db_hits), ml_proba))
        return

    b = bucket_ml(ml_proba)
    if b == "high":
        acc.ml_high += 1
    elif b == "medium":
        acc.ml_medium += 1
    else:
        acc.ml_low += 1

def run_all_tests():
    print("\n=== Lancement des tests de détection de phishing (CSV) ===\n")
    urls = load_urls_from_csv(CSV_PATH)
    total = len(urls)
    if total == 0:
        print(COLORS["error"] + "[ERREUR] Aucun URL chargé." + COLORS["reset"])
        return
    print(f"[INFO] {total} URL(s) chargée(s) depuis '{CSV_PATH}'.\n")

    acc = Acc()

    for i, test_url in enumerate(urls, 1):
        # --- Progression en direct ---
        sys.stdout.write(f"\r[{i}/{total}] Envoi…")
        sys.stdout.flush()

        try:
            resp = requests.post(API_URL, json={"url": test_url}, timeout=REQUEST_TIMEOUT)
            if resp.status_code != 200:
                acc.errors += 1
            else:
                result = resp.json()
                classify_and_count(test_url, result, acc)
        except Exception:
            acc.errors += 1

        time.sleep(REQUEST_DELAY)

    # Fin de la ligne de progression
    print()

    # ---------- RÉSUMÉ GLOBAL ----------
    print("\n" + "=" * 70)
    print("[RÉSUMÉ GLOBAL]\n")

    db_total = acc.db_by_source.get("URLhaus", 0) + acc.db_by_source.get("OFCS", 0) + acc.db_by_source.get("GSB", 0)
    print(f"DB Phishing {db_total}")
    print(f"  - URLhaus {acc.db_by_source.get('URLhaus', 0)}")
    print(f"  - OFCS {acc.db_by_source.get('OFCS', 0)}")
    print(f"  - GSB {acc.db_by_source.get('GSB', 0)}\n")

    ml_total = acc.ml_high + acc.ml_medium + acc.ml_low
    print(f"Machine learning {ml_total}")
    print(f"  - Risque élevé {acc.ml_high}")
    print(f"  - Risque modéré {acc.ml_medium}")
    print(f"  - Risque faible {acc.ml_low}\n")

    if acc.errors:
        print(COLORS["error"] + f"Erreurs / timeouts : {acc.errors}" + COLORS["reset"])
        print()

    print("-" * 70)
    print("Accord DB ↔ ML (sur les URLs détectées par au moins une DB) :\n")
    print(f"- ML 'élevé'   : {acc.db_and_ml_high}")
    print(f"- ML 'modéré'  : {acc.db_and_ml_medium}")
    print(f"- ML 'faible'  : {acc.db_and_ml_low}\n")

    if acc.db_combo_counts:
        print("-" * 70)
        print("Combinaisons de DB (URLs trouvées par plusieurs bases) :\n")
        for combo, cnt in acc.db_combo_counts.most_common():
            print(f"- {', '.join(combo):<30} : {cnt}")
        print()

    if acc.db_urls_list:
        print("-" * 70)
        print("URLs classées Phishing (DB) :\n")
        for url, srcs, proba in acc.db_urls_list:
            p_str = f"{proba:.2f}" if (proba is not None) else "N/A"
            print(f"- {url}\n    sources: {srcs:<20} | score ML: {p_str}")
        print("-" * 70)

    print("\n" + "=" * 70 + "\n")

if __name__ == "__main__":
    run_all_tests()
