# DataShare Pro

DataShare Pro est une application de transfert de fichiers ultra-rapide et sécurisée en réseau local (LAN), développée avec Python et Flet.

## Fonctionnalités Clés

*   **Transfert Haute Vitesse**: Mode Turbo détectant automatiquement le réseau local (jusqu'à 1Gbps+).
*   **Découverte Automatique**: Détection des autres appareils DataShare sur le réseau via UDP Broadcast.
*   **Sécurité**:
    *   Chiffrement ChaCha20-Poly1305.
    *   Authentification par Code PIN (Optionnel).
    *   Validation explicite des réceptions.
    *   Protection contre le Path Traversal.
*   **Interface Moderne**: GUI fluide et responsive basée sur Flet.
*   **Fonctionnalités Avancées**:
    *   Drag & Drop de fichiers.
    *   Historique de transfert.
    *   Mises à jour à distance (Client-Serveur).

## Installation

1.  Assurez-vous d'avoir Python 3.10+ installé.
2.  Installez les dépendances :
    ```bash
    pip install -r requirements.txt
    ```

## Démarrage

Pour lancer l'application :

```bash
cd DataShare
python main_gui.py
```

## Compilation (Executable)

Consultez `docs/executable_guide.md` pour les instructions de création d'un exécutable Windows (.exe) avec PyInstaller.

## Documentation

La documentation complète se trouve dans le dossier `DataShare/docs/` :
*   `code_explanation.md`: Structure du code.
*   `pin_auth_guide.md`: Guide de l'authentification PIN.
*   `remote_update_guide.md`: Système de mise à jour.
