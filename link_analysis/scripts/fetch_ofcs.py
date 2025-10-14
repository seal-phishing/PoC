import os
import requests
from dotenv import load_dotenv

# Charger la clé depuis le fichier .env
load_dotenv()
OFCS_API_KEY = os.getenv("OFCS_API_KEY")

OFCS_API_URL = "https://nemesis.govcert.ch/phishdb/api.php"

def fetch_domainbl():
    if not OFCS_API_KEY:
        raise ValueError("Clé OFCS_API_KEY manquante dans le .env")

    params = {
        "apikey": OFCS_API_KEY,
        "api": "text",
        "limit": 0, # 0 pour récupérer tous les domaines, sinon spécifier un nombre
        "online": 0 # 0 pour récupérer tous les domaines, 1 pour les domaines en ligne
    }

    try:
        print("[OFCS API] Requête domainbl en cours...")
        response = requests.get(OFCS_API_URL, params=params, timeout=10)
        response.raise_for_status()
        domains = response.text.splitlines()
        print(f"[OFCS API] {len(domains)} domaines en ligne récupérés.")
        return domains
    except Exception as e:
        print(f"[OFCS API] Erreur lors de la récupération : {e}")
        return []

if __name__ == "__main__":
    domains = fetch_domainbl()
    if domains:
        with open("database/phish_ofcs_url.txt", "w") as f:
            f.write("\n".join(domains))
        print("✅ Liste enregistrée dans phish_domainbl.txt")
