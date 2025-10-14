import os
import requests
from urllib.parse import urlparse
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

OFCS_API_KEY = os.getenv("OFCS_API_KEY")
OFCS_API_URL = "https://nemesis.govcert.ch/phishdb/api.php"

def check_ofcs_api(url: str) -> tuple[bool, dict]:
    """
    Interroge l'API de PhishDB (OFCS) pour savoir si une URL est référencée comme étant du phishing.

    Paramètres :
        url (str) : L'URL à analyser

    Retour :
        tuple : (est_phishing (booléen), détails (dict))
    """
    if not OFCS_API_KEY:
        print("[OFCS API] Clé API manquante.")
        return False, {"erreur": "OFCS_API_KEY non définie"}

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or url

        params = {
            "apikey": OFCS_API_KEY,
            "api": "query",
            "search": hostname,
            "format": "json",
            "type": "host",
            "mode": "exact"
        }

        response = requests.get(OFCS_API_URL, params=params, timeout=5)
        response.raise_for_status()

        data = response.json()

        if data.get("matches"):
            return True, data["matches"]
        else:
            return False, {}

    except Exception as e:
        print(f"[OFCS API] Erreur lors de la requête : {e}")
        return False, {"erreur": str(e)}
