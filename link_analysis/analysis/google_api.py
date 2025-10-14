import os
import requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

# Récupération de la clé API Google Safe Browsing
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")


def check_google_api(url: str) -> tuple[bool, dict | None]:
    """
    Vérifie si une URL est signalée comme dangereuse par l'API Google Safe Browsing.

    Paramètres :
        url (str) : L'URL à analyser.

    Retour :
        tuple[bool, dict | None] :
            - True + détails si une menace est détectée.
            - False + None si aucune menace ou en cas d'erreur.
    """
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"

    payload = {
        "client": {
            "clientId": "phishing-checker",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(endpoint, json=payload)
        response.raise_for_status()

        result = response.json()
        if "matches" in result:
            return True, result["matches"]
        return False, None

    except requests.RequestException as e:
        print(f"[ERREUR] Erreur lors de la requête : {e}")
        return False, None
