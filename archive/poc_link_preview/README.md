# PoC - Prévisualisation des liens

Cette application Flutter intercepte les liens cliqués dans l'environnement Android, les envoie à une API backend (`poc_link_analysis`) pour analyse, et affiche à l'utilisateur un retour sur la sécurité du lien (légitime, suspect ou phishing). Elle sert de couche de prévention pour éviter l'ouverture automatique de liens malveillants.

---

## Prérequis

1. **Flutter installé** (canal stable recommandé)
2. **Dispositif Android ou émulateur configuré**

---

## Installation & commandes utiles

### Mettre à jour les dépendances

Ajouter les dépendances dans le fichier `poc_link_preview/pubspec.yaml` et mettre à jour avec :
```bash
  flutter pub get
```

### Lister les emulateurs disponibles

```bash
  flutter emulators
```

### Lancer un émulateur spécifique

```bash
  flutter emulators --launch <ID_de_l'émulateur>
```

### Lancer sur un appareil connecté

```bash
  flutter run
```
---

## Structure du projet

* `lib/` : code source principal (Dart)
* `android/` : code natif Android (manifest, config)

---

## Communication avec l’API

L’application interagit avec un serveur Python (`poc_link_analysis`) via une requête POST à :

```
http://<adresse_ip_locale>:8001/check_url
```

Le backend retourne un verdict (`legitimate`, `suspect`, `phishing`) et une probabilité dans le cas de l’IA.

---

## Exemple de fonctionnement

1. L’utilisateur clique sur un lien.
2. L’application intercepte et l’envoie à l’API.
3. L’utilisateur voit un retour comme :
    - Lien sûr
    - Lien suspect
    - Phishing détecté

---

## Exemple de test simple

1. Définir l'application **Link Preview** comme navigateur par défaut sur l’appareil Android (réel ou émulé).
2. Envoyer un **SMS contenant des liens** vers l'appareil (par exemple via l'application Messages).
3. Ouvrir le lien directement depuis le SMS : l’application sera déclenchée, analysera le lien, et affichera le verdict.

---

## Limitations

* Ne couvre que les liens ouverts via l'application (pas tous les navigateurs).
* L’analyse repose sur un serveur distant actif (`poc_link_analysis`).
* Le projet nécessite une configuration réseau locale fonctionnelle.

---

## Dépendances principales

* `http` : communication avec le backend
* `uni_links` : interception des liens
