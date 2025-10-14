import os
import requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parents[1] / ".env")

# Récupérer la clé API pour URLhaus
URLHAUS_API_KEY = os.getenv("URLHAUS_API_KEY")


def check_urlhaus_api(url: str) -> tuple[bool, str | None, dict | None]:
    """
    Vérifie si une URL est référencée comme malveillante dans la base de données URLhaus.

    Paramètres :
        url (str) : L'URL à vérifier.

    Retour :
        tuple :
            - bool : True si l'URL est connue comme malveillante.
            - str | None : Statut de l'URL selon URLhaus (ex : 'online', 'offline'), ou None si inconnu.
            - dict | None : Réponse JSON complète de URLhaus si disponible.
    """
    endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Auth-Key": URLHAUS_API_KEY
    }
    data = {"url": url}

    try:
        response = requests.post(endpoint, headers=headers, data=data)
        result = response.json()

        if result.get("query_status") == "ok":
            return True, result.get("url_status"), result
        else:
            return False, None, result

    except Exception as e:
        print("[ERREUR URLhaus] Erreur lors de la requête : {e}")
        return False, None, None
