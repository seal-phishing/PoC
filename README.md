# [SEAL] PoC – Détection de liens de phishing

Projet de démonstration complet de détection de liens malveillants, combinant :

- un **service Python d’analyse de sécurité** (`link_analysis`)
- une **application Android** basée sur le projet open-source **URLCheck** (intégré dans `app_urlcheck/`), enrichie d’un module de communication avec notre service d’analyse

> Remarque : l’ancien PoC Flutter (`poc_link_preview`) est conservé à titre d’archive dans le dossier `archive/`.  
> L’application de référence utilisée dans la démonstration est désormais **`app_urlcheck/`**.

---

## Objectif du projet

Permettre à l’utilisateur d’évaluer la **fiabilité d’un lien reçu** (par e-mail, SMS, ou messagerie).  
Le service analyse le lien et renvoie un **niveau de risque** accompagné de la **source du verdict** :  
si le lien est connu d’une base de données (ex. PhishDB, Google SB, URLhaus), il est signalé comme *phishing* ;  
sinon, le modèle de machine learning estime le risque comme *élevé*, *modéré* ou *faible*.

---

## Composants

### 1) `link_analysis/` – Service Python d’analyse des liens

- Fournit un endpoint **`POST /check_url`**
- Combine plusieurs techniques :
  - Vérification via **Google Safe Browsing**
  - Vérification via **PhishDB / OFCS**
  - Vérification via **URLhaus**
  - Analyse via un **modèle de machine learning (Random Forest)**
- Retourne un verdict clair : *phishing*, *suspect* ou *legitimate*
- Fournit un **script de test automatisé** pour valider le service

Voir [`link_analysis/README.md`](link_analysis/README.md) pour les instructions détaillées.

**À noter :**
- Si certaines clés API (comme OFCS) sont absentes, le service fonctionne quand même : ces vérifications sont simplement ignorées
- La clé OFCS est difficile à obtenir et réservée à certains partenaires. Son absence est normale pour les tests.

---

### 2) `app_urlcheck/` – Application Android

Application basée sur le projet open-source **URLCheck** de **TrianguloY**, adapté pour intégrer un module personnalisé appelé **“LinkRisk”**.  
Ce module envoie les URLs saisies ou interceptées par l’application vers le service Python (`link_analysis`) et affiche le résultat à l’utilisateur.

**Fonctionnalités principales :**
- Interface simple et modulaire (basée sur URLCheck)
- Communication HTTP avec le backend (`link_analysis`)
- Affichage du verdict :  
  - *Phishing détecté (source : OFCS / Google / URLhaus)*  
  - *Risque élevé / modéré / faible (source : ML)*

**Crédits et licence :**
- Projet original : [TrianguloY / URLCheck](https://github.com/TrianguloY/URLCheck)
- Licence : se référer au fichier de licence du projet d’origine
- Module “LinkRisk” ajouté dans le cadre du PoC pour intégrer la détection côté serveur (aucune clé API n’est intégrée à l’application)

---

## Prérequis

- **Python 3.10+**
- **Android Studio** avec SDK et build-tools installés
- (Optionnel) Flutter/Dart uniquement si vous souhaitez consulter l’ancien PoC dans `archive/poc_link_preview`

---

## Démarrage rapide

### 1. Lancer le service d’analyse (`link_analysis`)

1. Copier le fichier d’exemple :
```bash
  cp .env.example .env
```

2. Compléter les clés API selon votre configuration :

   * `GOOGLE_API_KEY` : clé Google Safe Browsing
   * `OFCS_API_KEY` : clé privée PhishDB (facultative)
   * `URLHAUS_API_KEY` : clé publique ou vide
3. Installer les dépendances Python :

```bash
  pip install -r link_analysis/requirements.txt
```

4. Construire le dataset :

```bash
  python link_analysis/scripts/build_dataset.py
```

5. Entraîner le modèle :

```bash
  python link_analysis/analysis/ml_model.py
```

6. Démarrer le service :

```bash
  uvicorn link_analysis.main:app --host 127.0.0.1 --port 8001 --reload
```

L’API sera accessible sur [http://127.0.0.1:8001](http://127.0.0.1:8001)

Interface interactive : [http://127.0.0.1:8001/docs](http://127.0.0.1:8001/docs)

---

### 2. Lancer l’application Android (`app_urlcheck`)

1. Ouvrir **Android Studio**
2. `File > Open…` → sélectionner le dossier `app_urlcheck/`
3. Construire et exécuter l’application :

   * Sur **émulateur Android** : l’API du backend est accessible via `http://10.0.2.2:8001/check_url`
   * Sur **appareil réel** : remplacer l’URL par `http://<IP_locale_de_votre_machine>:8001/check_url`
4. Vérifier que l’accès HTTP clair est autorisé dans la configuration réseau Android

> Astuce : la commande `adb reverse tcp:8001 tcp:8001` permet à l’émulateur d’utiliser `http://127.0.0.1:8001` comme adresse locale.

---

## Contenu du dossier `media/`

Le dossier `media/` contient :

* Des captures d’écran de l’application (PoC Flutter, Sortie de console, URLCheck)
* Des extraits vidéo de la démonstration complète
* Les illustrations utilisées dans la documentation

---

## Dossier `archive/`

Le dossier `archive/` contient l’ancien PoC Flutter (`poc_link_preview/`).
Ce prototype a servi à valider les premiers échanges entre une app mobile et le service d’analyse, mais a été remplacé par une intégration plus stable et complète avec **URLCheck**.

---

## Technologies principales

* **Python / FastAPI / scikit-learn**
* **Android (Java)** via le projet URLCheck
* **APIs externes** : Google Safe Browsing, PhishDB (OFCS), URLhaus
* **Communication JSON** entre le service et l’application Android
* **Modèle ML Random Forest** entraîné localement sur un dataset d’URLs réelles

---

## Points clés

* Aucune clé API n’est embarquée dans l’application Android : tout le traitement s’effectue côté serveur.
* Les tests automatisés peuvent être exécutés directement depuis le dossier `link_analysis/tests`.
* L’architecture modulaire permet de remplacer ou d’ajouter des modules de vérification.

---

## Résumé

| Dossier            | Rôle                | Description                                                                  |
| ------------------ | ------------------- | ---------------------------------------------------------------------------- |
| **link_analysis/** | Service Python      | Analyse et classification des liens (FastAPI + ML + APIs externes)           |
| **app_urlcheck/**  | Application Android | Interface utilisateur, affichage du verdict et communication avec le backend |
| **media/**         | Ressources          | Captures d’écran et vidéos de démonstration                                  |
| **archive/**       | Historique          | Ancien PoC Flutter, conservé pour référence                                  |
