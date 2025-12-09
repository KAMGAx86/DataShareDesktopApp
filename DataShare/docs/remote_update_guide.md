# Système de Mise à Jour à Distance DataShare

Ce document décrit l'architecture et l'implémentation du système de mise à jour automatique pour DataShare.

## Architecture

Le système repose sur une architecture Client-Serveur simple :
1.  **Client (DataShare Desktop)** : Interroge régulièrement le serveur.
2.  **Serveur (FastAPI)** : Héberge un fichier JSON de manifeste et les exécutables.

### Flux de Mise à Jour

1.  **Check** : L'application envoie une requête `GET` à l'URL de mise à jour.
2.  **Compare** : Le serveur renvoie la version la plus récente. L'app compare avec sa version locale.
3.  **Download** : Si une nouvelle version existe, l'app télécharge le nouvel exécutable.
4.  **Apply** : L'app lance le nouvel exécutable et se ferme.

## Spécification API (Backend)

Votre backend FastAPI doit exposer une route (ex: `/api/updates/latest`) retournant ce JSON :

```json
{
    "version": "1.2.0",
    "release_date": "2025-12-10",
    "download_url": "https://votre-domaine.com/downloads/DataShare_v1.2.0.exe",
    "changelog": [
        "Correction de bugs mineurs",
        "Amélioration de la vitesse de transfert"
    ]
}
```

### Exemple de code FastAPI

```python
from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI()

class UpdateInfo(BaseModel):
    version: str
    release_date: str
    download_url: str
    changelog: list[str]

@app.get("/api/updates/latest", response_model=UpdateInfo)
def get_latest_update():
    return {
        "version": "1.2.0",
        "release_date": "2025-12-10",
        "download_url": "http://localhost:8000/static/DataShare_v1.2.0.exe",
        "changelog": ["Nouveau design", "Support Drag & Drop"]
    }
```

## Intégration Client (updater.py)

Le module `updater.py` (déjà créé) gère la logique côté client.

### Utilisation dans l'App

```python
from updater import DataShareUpdater

# Initialisation
updater = DataShareUpdater(current_version="1.0.0", update_url="http://localhost:8000/api/updates/latest")

# Vérification
update_info = updater.check_for_updates()

if update_info:
    # Télécharger et appliquer
    updater.download_update(update_info['download_url'], "update.exe")
    updater.apply_update("update.exe")
```

## Sécurité

Pour sécuriser les mises à jour :
1.  **HTTPS** : Utilisez toujours HTTPS pour empêcher l'interception.
2.  **Signature (Avancé)** : Signez vos exécutables numériquement et vérifiez la signature avant l'installation.
3.  **Hash** : Ajoutez un champ `sha256` dans le manifeste JSON et vérifiez le hash du fichier téléchargé.
