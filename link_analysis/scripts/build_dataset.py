import os
import sys
import pandas as pd
import re

sys.path.append(os.path.abspath("."))

from link_analysis.analysis.ml.feature_extraction import extract_features

# Fichiers d’entrée
LEGIT_CH_FILE = "link_analysis/database/legit_ch_url.csv"
LEGIT_GLOBAL_FILE = "link_analysis/database/legit_global_url.csv"
PHISH_FILE = "link_analysis/database/phish_ofcs_url.txt"
OUTPUT_DATASET = "link_analysis/database/dataset_final.csv"

# Supprime totalement les données précédentes
if os.path.exists(OUTPUT_DATASET):
    os.remove(OUTPUT_DATASET)

def is_valid_url(url: str) -> bool:
    return bool(re.match(r"^https://[^\s\[\]]+$", url.strip()))

def normalize_url(url: str) -> str:
    return url.strip().lower()

all_urls = set()
rows = []

# --- LEGIT_CH : domaines suisses ---
df_ch = pd.read_csv(LEGIT_CH_FILE)
for domain in df_ch["domainname"].dropna().astype(str):
    url = f"https://{domain.strip()}"
    norm = normalize_url(url)
    if norm in all_urls or not is_valid_url(url):
        continue
    try:
        features = extract_features(url)
        features["url"] = url
        features["status"] = "legitimate"
        rows.append(features)
        all_urls.add(norm)
    except Exception as e:
        print(f"[CH] Erreur {url} : {e}")

# --- LEGIT_GLOBAL : domaines globaux ---
df_global = pd.read_csv(LEGIT_GLOBAL_FILE)
for raw in df_global["url"].dropna().astype(str):
    url = f"https://{raw.strip()}"
    norm = normalize_url(url)
    if norm in all_urls or not is_valid_url(url):
        continue
    try:
        features = extract_features(url)
        features["url"] = url
        features["status"] = "legitimate"
        rows.append(features)
        all_urls.add(norm)
    except Exception as e:
        print(f"[GLOBAL] Erreur {url} : {e}")

# --- PHISHING URLs : déjà complètes ---
with open(PHISH_FILE, "r", encoding="utf-8") as f:
    for line in f:
        url = line.strip()
        if not url or url.startswith("#"):
            continue
        norm = normalize_url(url)
        if norm in all_urls or not re.match(r"^https?://", url):
            continue
        try:
            features = extract_features(url)
            features["url"] = url
            features["status"] = "phishing"
            rows.append(features)
            all_urls.add(norm)
        except Exception as e:
            print(f"[PHISH] Erreur {url} : {e}")

# --- Sauvegarde finale ---
df_final = pd.DataFrame(rows)
df_final.to_csv(OUTPUT_DATASET, index=False)

print(f"[DONE] Total lignes ajoutées : {len(df_final)}")
print("\n[STATS] Répartition du dataset :")
print(df_final["status"].value_counts())
