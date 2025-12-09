# Guide de création d'exécutable pour DataShare

Ce guide vous explique comment transformer votre application Python DataShare en un fichier exécutable (.exe) autonome pour Windows.

## Prérequis

Assurez-vous d'avoir installé `pyinstaller` :

```powershell
pip install pyinstaller
```

## Étapes de création

1.  **Ouvrir un terminal** dans le dossier de votre projet :
    ```powershell
    cd "c:/Users/CL INFO/Desktop/DataShare_Projet/DataShareDesktopApp/DataShare"
    ```

2.  **Lancer la commande de build** :
    Utilisez la commande suivante pour créer un exécutable unique (`--onefile`) et sans console (`--noconsole`, optionnel si vous voulez voir les logs) :

    ```powershell
    pyinstaller --name DataShare --onefile --noconsole --add-data "assets;assets" --hidden-import=flet --hidden-import=plyer --hidden-import=win10toast main_gui.py
    ```

    *Note : Si vous avez des fichiers de ressources (images, sons) dans un dossier `assets`, l'option `--add-data "assets;assets"` est importante. Ajustez selon votre structure réelle.*

3.  **Récupérer l'exécutable** :
    Une fois la commande terminée, votre fichier `DataShare.exe` se trouvera dans le dossier `dist`.

## Notes importantes

-   **Droits Administrateur** : Pour que la fonctionnalité de Hotspot fonctionne, l'application doit souvent être lancée en tant qu'administrateur.
-   **Pare-feu** : Lors du premier lancement, Windows demandera l'autorisation pour le pare-feu. Il est crucial d'accepter pour que le transfert de fichiers fonctionne.
-   **Dépendances** : Si vous rencontrez des erreurs de modules manquants au lancement de l'exe, ajoutez-les avec `--hidden-import=nom_du_module`.

## Test de l'exécutable

1.  Allez dans le dossier `dist`.
2.  Lancez `DataShare.exe`.
3.  Vérifiez que l'interface s'ouvre et que les fonctionnalités (scan, paramètres) répondent.
