from fastapi import FastAPI
from pydantic import BaseModel

from link_analysis.analysis.google_api import check_google_api
from link_analysis.analysis.urlhaus_api import check_urlhaus_api
from link_analysis.analysis.ofcs_api import check_ofcs_api
from link_analysis.analysis.ml_model import load_model, predict_url

# Initialisation de l'application FastAPI
app = FastAPI()

# Chargement du modèle de machine learning et des features à l'initialisation
clf, feature_order = load_model()


class URLInput(BaseModel):
    """
    Modèle d'entrée pour l'analyse d'une URL.
    """
    url: str


@app.post("/check_url")
def verifier_url(input: URLInput):
    """
    Analyse une URL à l'aide de plusieurs techniques (base de données OFCS, Google Safe Browsing, URLhaus, modèle ML).

    Paramètres :
        input (URLInput) : modèle contenant l'URL à vérifier.

    Retour :
        dict : verdict et détails de la classification.
    """
    url = input.url.strip()

    # 1. Vérification avec l'API OFCS
    print(f"[ANALYSE] Vérification OFCS : {url}")
    is_phishing, details = check_ofcs_api(url)
    if is_phishing:
        print(f"[RÉSULTAT] Verdict : PHISHING (source : OFCS)")
        return {
            "verdict": "phishing",
            "source": "OFCS API",
            "details": details
        }

    # 2. Vérification via Google Safe Browsing
    print(f"[ANALYSE] Vérification Google Safe Browsing : {url}")
    is_malicious, matches = check_google_api(url)
    if is_malicious:
        print(f"[RÉSULTAT] Verdict : PHISHING (source : Google Safe Browsing)")
        return {
            "verdict": "phishing",
            "source": "Google Safe Browsing",
            "details": matches
        }

    # 3. Vérification via URLhaus
    print(f"[ANALYSE] Vérification URLhaus : {url}")
    is_urlhaus, status, full_data = check_urlhaus_api(url)
    if is_urlhaus:
        print(f"[RÉSULTAT] Verdict : PHISHING (source : URLhaus)")
        return {
            "verdict": "phishing",
            "source": "URLhaus",
            "details": {
                "status": status,
                "info": full_data
            }
        }

    # 4. Prédiction avec le modèle de machine learning
    print(f"[ANALYSE] Prédiction via modèle ML : {url}")
    if clf:
        prediction, proba = predict_url(url, clf, feature_order)
        print(f"[RÉSULTAT] {prediction.upper()} (source : ML) - Score : {round(proba, 2)}")
        return {
            "verdict": prediction,
            "source": "ML",
            "proba": proba
        }

    # Cas par défaut : aucune menace détectée
    print(f"[RÉSULTAT] Aucun danger détecté pour : {url}")
    return {
        "verdict": "clean",
        "details": "Aucune menace détectée par les méthodes utilisées."
    }
