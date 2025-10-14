import os
import sys
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

# Permet d'exécuter le script directement sans erreur d'import
sys.path.append(os.path.abspath("."))

from link_analysis.analysis.ml.feature_extraction import extract_features

# Chemins vers les fichiers du modèle
ML_DIR = os.path.join(os.path.dirname(__file__), "ml")
MODEL_PATH = os.path.join(ML_DIR, "model.joblib")
FEATURE_ORDER_PATH = os.path.join(ML_DIR, "model_features.txt")

def train_model(csv_path: str, output_model_path: str = MODEL_PATH) -> None:
    """
    Entraîne un modèle Random Forest avec tous les phishing, tous les legit_ch,
    et un échantillon de legit_global équilibré.
    """
    df = pd.read_csv(csv_path, low_memory=False)

    if "status" not in df.columns:
        raise ValueError("Le dataset doit contenir une colonne 'status'.")

    # --- Séparation des classes ---
    df_phishing = df[df["status"] == "phishing"]
    df_legit = df[df["status"] == "legitimate"]

    # Identification des CH (par leur domaine .ch ou autre ?)
    df_legit_ch = df_legit[df_legit["url"].str.contains(r"\.ch", case=False, na=False)]

    # Retirer les CH du dataset global pour éviter les doublons
    urls_ch = set(df_legit_ch["url"].str.lower().unique())
    df_legit_global = df_legit[~df_legit["url"].str.lower().isin(urls_ch)]

    # --- Sample aléatoire de global légitimes ---
    remaining = len(df_phishing) - len(df_legit_ch)
    if remaining <= 0:
        raise ValueError("Trop de CH légitimes pour équilibrer. Réduis leur nombre ou ajoute plus de phishing.")

    df_legit_sampled = df_legit_global.sample(n=remaining, random_state=42)

    # --- Concat et shuffle ---
    df_balanced = pd.concat([df_phishing, df_legit_ch, df_legit_sampled]).sample(frac=1, random_state=42).reset_index(drop=True)

    print(f"[INFO] Échantillon équilibré : {len(df_phishing)} phishing + {len(df_legit_ch)} legit_ch + {len(df_legit_sampled)} legit_global")
    print(f"[INFO] Total entraînement : {len(df_balanced)} exemples")

    # --- Préparation des features ---
    y = df_balanced["status"].map(lambda a: 1 if a == "phishing" else 0)
    x = df_balanced.drop(columns=["url", "status"])

    # Encodage
    if "scheme" in x.columns:
        x["scheme"] = x["scheme"].map({"http": 0, "https": 1}).fillna(-1)

    if "tld" in x.columns:
        top_tlds = x["tld"].value_counts().nlargest(20).index
        x["tld"] = x["tld"].where(x["tld"].isin(top_tlds), "__other__")
        x = pd.get_dummies(x, columns=["tld"])

    if "path_ext" in x.columns:
        top_exts = x["path_ext"].value_counts().nlargest(15).index
        x["path_ext"] = x["path_ext"].where(x["path_ext"].isin(top_exts), "__other__")
        x = pd.get_dummies(x, columns=["path_ext"])

    # Garde uniquement les colonnes numériques
    x = x.select_dtypes(include=["number"])

    # Sauvegarde des features
    os.makedirs(ML_DIR, exist_ok=True)
    with open(FEATURE_ORDER_PATH, "w", encoding="utf-8") as f:
        for col in x.columns:
            f.write(f"{col}\n")

    # --- Entraînement ---
    clf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight="balanced")
    clf.fit(x, y)
    joblib.dump(clf, output_model_path)

    print(f"[SUCCÈS] Modèle entraîné et sauvegardé dans {output_model_path}")

def load_model(model_path: str = MODEL_PATH) -> tuple[RandomForestClassifier | None, list[str]]:
    """
    Charge un modèle ML et l’ordre attendu des features.
    """
    try:
        clf = joblib.load(model_path)
        with open(FEATURE_ORDER_PATH, "r") as f:
            feature_order = [line.strip() for line in f]
        return clf, feature_order
    except Exception as e:
        print(f"[ERREUR] Échec du chargement du modèle : {e}")
        return None, []

def predict_url(url: str, clf, feature_order: list[str]) -> tuple[str, float]:
    """
    Prédit la classification d’une URL à l’aide du modèle entraîné.

    Retourne :
        - le verdict ("phishing", "suspect", "legitimate")
        - la probabilité associée
    """
    features = extract_features(url)
    df = pd.DataFrame([features])

    # Encodage identique à l'entraînement
    if "scheme" in df.columns:
        df["scheme"] = df["scheme"].map({"http": 0, "https": 1}).fillna(-1)

    if "tld" in df.columns and any(col.startswith("tld_") for col in feature_order):
        top_tlds = [col[4:] for col in feature_order if col.startswith("tld_")]
        df["tld"] = df["tld"].where(df["tld"].isin(top_tlds), "__other__")
        df = pd.get_dummies(df, columns=["tld"])

    if "path_ext" in df.columns and any(col.startswith("path_ext_") for col in feature_order):
        top_exts = [col[9:] for col in feature_order if col.startswith("path_ext_")]
        df["path_ext"] = df["path_ext"].where(df["path_ext"].isin(top_exts), "__other__")
        df = pd.get_dummies(df, columns=["path_ext"])

    # Garder uniquement les colonnes numériques
    df = df.select_dtypes(include=["number"])

    # Réalignement avec l’ordre attendu
    for col in feature_order:
        if col not in df:
            df[col] = 0
    df = df[feature_order]

    # Prédiction
    proba = clf.predict_proba(df)[0][1]
    if proba >= 0.8:
        return "phishing", proba
    elif proba >= 0.6:
        return "suspect", proba
    else:
        return "legitimate", proba

if __name__ == "__main__":
    train_model("link_analysis/database/dataset_final.csv")
