# link_analysis/__init__.py
from pathlib import Path
from dotenv import load_dotenv, find_dotenv

# Cherche un .env en partant de ce package (link_analysis) vers la racine
_pkg_dir = Path(__file__).resolve().parent
# Priorité au .env placé dans le package lui-même
_env_in_pkg = _pkg_dir / ".env"
if _env_in_pkg.exists():
    load_dotenv(_env_in_pkg)
else:
    # Sinon, essaie de le retrouver dans les parents (ne lève pas d’erreur s’il n’existe pas)
    load_dotenv(find_dotenv(usecwd=True))
