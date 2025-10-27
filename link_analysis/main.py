from fastapi import FastAPI
from pydantic import BaseModel

from link_analysis.analysis.google_api import check_google_api
from link_analysis.analysis.urlhaus_api import check_urlhaus_api
from link_analysis.analysis.ofcs_api import check_ofcs_api
from link_analysis.analysis.ml_model import load_model, predict_url

app = FastAPI(title="Link Analysis API", version="1.0.0")

clf, feature_order = load_model()

class URLInput(BaseModel):
    url: str

def decide_final_verdict(db_hits: list[str], ml_pred: str | None) -> str:
    if db_hits:
        return "phishing"
    if ml_pred:
        return ml_pred
    return "clean"

@app.post("/check_url")
def verifier_url(input: URLInput):
    url = (input.url or "").strip()

    # ---------- OFCS ----------
    print(f"[ANALYSE] OFCS : {url}")
    try:
        ofcs_hit, ofcs_details = check_ofcs_api(url)
    except Exception as e:
        print(f"[OFCS] Exception non gérée: {e}")
        ofcs_hit, ofcs_details = False, None
    ofcs_obj = {"hit": bool(ofcs_hit), "details": ofcs_details or None}

    # ---------- Google Safe Browsing ----------
    print(f"[ANALYSE] Google Safe Browsing : {url}")
    try:
        gsb_hit, gsb_matches = check_google_api(url)
    except Exception as e:
        print(f"[GSB] Exception non gérée: {e}")
        gsb_hit, gsb_matches = False, None
    gsb_obj = {"hit": bool(gsb_hit), "details": gsb_matches or None}

    # ---------- URLhaus ----------
    print(f"[ANALYSE] URLhaus : {url}")
    try:
        uh_hit, uh_status, uh_full = check_urlhaus_api(url)
    except Exception as e:
        print(f"[URLhaus] Exception non gérée: {e}")
        uh_hit, uh_status, uh_full = False, None, None
    uh_obj = {"hit": bool(uh_hit), "status": uh_status, "details": uh_full or None}

    # ---------- ML ----------
    print(f"[ANALYSE] Modèle ML : {url}")
    ml_pred, ml_proba = None, None
    if clf:
        try:
            ml_pred, ml_proba = predict_url(url, clf, feature_order)
            print(f"[RÉSULTAT ML] {ml_pred.upper()} - score: {round(ml_proba or 0.0, 3)}")
        except Exception as e:
            print(f"[ERREUR ML] {e}")

    # ---------- Agrégation ----------
    db_hits = []
    if ofcs_obj["hit"]:
        db_hits.append("OFCS")
    if gsb_obj["hit"]:
        db_hits.append("GSB")
    if uh_obj["hit"]:
        db_hits.append("URLhaus")

    final_verdict = decide_final_verdict(db_hits, ml_pred)
    final_source = "DB" if db_hits else ("ML" if ml_pred else "None")

    result = {
        "verdict": final_verdict,
        "source": final_source,
        "db_hits": db_hits,      # <- si 2 ou 3 DB matchent, elles seront toutes listées
        "proba": ml_proba,
        "sources": {
            "ofcs": ofcs_obj,
            "gsb": gsb_obj,
            "urlhaus": uh_obj,
            "ml": {"prediction": ml_pred, "proba": ml_proba},
        },
    }

    if db_hits:
        print(f"[RÉSULTAT] PHISHING via DB : {', '.join(db_hits)}")
    else:
        print(f"[RÉSULTAT] ML → {final_verdict} (score={round(ml_proba, 3) if ml_proba is not None else 'N/A'})")

    return result
