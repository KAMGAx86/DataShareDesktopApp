# Système de Mise à Jour à Distance - Guide Technique Détaillé

Ce document explique comment mettre en place l'infrastructure nécessaire pour que votre application DataShare Pro puisse se mettre à jour automatiquement.

## 1. Architecture

Le système fonctionne selon un modèle Client-Serveur simple :
1.  **L'Application (Client)** vérifie périodiquement un fichier JSON hébergé sur un serveur web.
2.  **Le Serveur Web** héberge deux fichiers :
    *   `update.json`: Contient le numéro de la dernière version et le lien de téléchargement.
    *   `DataShare_Setup.exe`: Le nouvel installateur de l'application.

## 2. Préparer le Serveur

Vous pouvez utiliser n'importe quel hébergement web (Apache, Nginx, IIS, ou même GitHub Pages pour le JSON).

### Structure des fichiers sur le serveur
Créez un dossier (ex: `datashare-updates`) accessible via une URL publique.

### Le fichier `update.json`
Créez ce fichier avec le contenu suivant :

```json
{
    "version": "6.1.0",
    "release_date": "2023-12-10",
    "download_url": "http://votre-site.com/datashare-updates/DataShare_Setup_v6.1.0.exe",
    "release_notes": "Correction de bugs mineurs et amélioration du Wi-Fi Direct."
}
```

*   **version**: Doit être supérieur à la version actuelle de l'app (actuellement 6.0.0). Format sémantique `Majeur.Mineur.Patch`.
*   **download_url**: Lien direct vers le nouvel exécutable.

## 3. Configurer l'Application

Dans le code source (`main_gui.py`), la ligne suivante définit où l'application va chercher les mises à jour :

```python
self.updater = DataShareUpdater("6.0.0", "http://votre-site.com/datashare-updates/update.json")
```

**Pour la production :**
1.  Remplacez l'URL par la vraie adresse de votre fichier JSON.
2.  Lorsque vous compilez une nouvelle version, n'oubliez pas d'incrémenter le numéro de version dans le premier argument (`"6.0.0"` -> `"6.1.0"`).

## 4. Workflow de Mise à Jour (Pas à Pas)

Voici ce que vous devez faire pour déployer une mise à jour :

1.  **Développer** : Faites vos modifications dans le code Python.
2.  **Tester** : Vérifiez que tout fonctionne.
3.  **Incrémenter la version** :
    *   Dans `main_gui.py`, changez `DataShareUpdater("6.0.0", ...)` par `DataShareUpdater("6.1.0", ...)`.
4.  **Compiler** : Créez le nouvel exécutable (`DataShare_Setup_v6.1.0.exe`) avec PyInstaller.
5.  **Uploader** :
    *   Mettez le fichier `.exe` sur votre serveur web.
    *   Mettez à jour le fichier `update.json` sur le serveur avec la nouvelle version `6.1.0` et le nouveau lien.
6.  **C'est tout !** : Les utilisateurs recevront une notification ou pourront cliquer sur "Rechercher des mises à jour" pour télécharger et installer la nouvelle version automatiquement.
